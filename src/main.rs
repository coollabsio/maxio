#![allow(
    clippy::collapsible_if,
    clippy::redundant_closure,
    clippy::redundant_pattern_matching,
    clippy::needless_borrows_for_generic_args,
    clippy::io_other_error,
    clippy::if_same_then_else,
    clippy::manual_pattern_char_comparison,
    clippy::derivable_impls,
    clippy::items_after_test_module,
    clippy::overly_complex_bool_expr,
    clippy::too_many_arguments,
    clippy::new_without_default,
    clippy::needless_bool,
    clippy::collapsible_else_if
)]

mod api;
mod auth;
mod config;
mod embedded;
mod error;
mod openapi;
mod server;
mod storage;
mod xml;

use clap::Parser;
use clap::Subcommand;
use config::Config;
use http::Uri;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "maxio",
    about = "S3-compatible object storage server",
    version = env!("CARGO_PKG_VERSION")
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[command(flatten)]
    config: Config,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the HTTP/S3 server (default when no subcommand is provided)
    Serve,

    /// Check server health by sending an HTTP GET request
    Healthcheck {
        /// Healthcheck endpoint URL
        #[arg(long, env = "MAXIO_HEALTHCHECK_URL", default_value_t = default_healthcheck_url())]
        url: String,

        /// Timeout in milliseconds for connect/read operations
        #[arg(long, env = "MAXIO_HEALTHCHECK_TIMEOUT_MS", default_value = "2000")]
        timeout_ms: u64,
    },

    /// Manage the SSE-S3 master-key keyring
    #[command(subcommand)]
    Keyring(KeyringCmd),

    /// Write the web console OpenAPI document (used to generate the UI API client)
    Openapi {
        /// Output file; prints to stdout when omitted
        #[arg(long)]
        output: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum KeyringCmd {
    /// Generate a new master key, mark it active, and demote the previous
    /// active key (retained so existing objects keep decrypting).
    /// Restart the server after rotating to pick up the new active key.
    Rotate {
        /// Data directory containing .maxio-keys.json
        #[arg(long, env = "MAXIO_DATA_DIR", default_value = "./data")]
        data_dir: String,
    },

    /// Print the keyring file contents (key ids + metadata, never the key
    /// material itself).
    List {
        #[arg(long, env = "MAXIO_DATA_DIR", default_value = "./data")]
        data_dir: String,
    },
}

fn default_healthcheck_url() -> String {
    let port = std::env::var("MAXIO_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(9000);
    format!("http://127.0.0.1:{}/healthz", port)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Commands::Serve) | None => {}
        Some(Commands::Healthcheck { url, timeout_ms }) => {
            return run_healthcheck(&url, timeout_ms).await;
        }
        Some(Commands::Keyring(KeyringCmd::Rotate { ref data_dir })) => {
            return run_keyring_rotate(data_dir).await;
        }
        Some(Commands::Keyring(KeyringCmd::List { ref data_dir })) => {
            return run_keyring_list(data_dir).await;
        }
        Some(Commands::Openapi { ref output }) => {
            let json = openapi::openapi_json();
            match output {
                Some(path) => {
                    if let Some(parent) = path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(path, json)?;
                }
                None => print!("{json}"),
            }
            return Ok(());
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = cli.config;

    if config.access_key == "maxioadmin"
        && config.secret_key == "maxioadmin"
        && !config.allow_insecure_dev
    {
        anyhow::bail!(
            "refusing to start with default credentials in production; set MAXIO_ACCESS_KEY/MAXIO_SECRET_KEY or use --allow-insecure-dev for local development"
        );
    }

    tokio::fs::create_dir_all(&config.data_dir).await?;

    // Build the SSE-S3 keyring (bootstrap a random master key on first run).
    let keyring = Arc::new(
        storage::keys::Keyring::load(&config.data_dir, config.master_key.as_deref()).await?,
    );
    if config.master_key.is_none() {
        tracing::info!(
            "SSE-S3 keyring: active key id {} (file {}/.maxio-keys.json — BACK THIS UP)",
            keyring.active_id(),
            config.data_dir
        );
    } else {
        tracing::info!(
            "SSE-S3 keyring: active key id {} (from MAXIO_MASTER_KEY)",
            keyring.active_id()
        );
    }

    let storage = storage::filesystem::FilesystemStorage::new(
        &config.data_dir,
        config.erasure_coding,
        config.chunk_size,
        config.parity_shards,
        keyring.clone(),
    )
    .await?;

    storage::provision_default_buckets(&storage, &config.default_buckets, &config.region).await;

    let state = server::AppState {
        storage: Arc::new(storage),
        config: Arc::new(config.clone()),
        login_rate_limiter: Arc::new(api::console::LoginRateLimiter::new()),
    };

    // Background housekeeping: abort stale multipart uploads (>7 days) and
    // remove leftover temp files from crashed writes. Runs once at startup,
    // then hourly.
    {
        let storage = state.storage.clone();
        tokio::spawn(async move {
            let stale_after = chrono::Duration::days(7);
            let mut ticker = tokio::time::interval(Duration::from_secs(3600));
            loop {
                ticker.tick().await;
                let (uploads, temps) = storage.housekeeping_sweep(stale_after).await;
                if uploads > 0 || temps > 0 {
                    tracing::info!(
                        "housekeeping: removed {} stale upload(s), {} temp file(s)",
                        uploads,
                        temps
                    );
                }
            }
        });
    }

    let app = server::build_router(state);

    let addr = format!("{}:{}", config.address, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    if config.access_key == "maxioadmin" && config.secret_key == "maxioadmin" {
        tracing::warn!(
            "WARNING: Using default credentials because insecure development mode is enabled."
        );
    }

    tracing::info!("MaxIO v{} listening on {}", env!("CARGO_PKG_VERSION"), addr);
    tracing::info!("Access Key: {}", config.access_key);
    tracing::info!("Secret Key: [REDACTED]");
    tracing::info!("Data dir:   {}", config.data_dir);
    tracing::info!("Region:     {}", config.region);
    if config.erasure_coding {
        tracing::info!(
            "Erasure coding: enabled (chunk size: {}MB)",
            config.chunk_size / (1024 * 1024)
        );
        if config.parity_shards > 0 {
            tracing::info!(
                "Parity shards: {} (can tolerate {} lost/corrupt chunks per object)",
                config.parity_shards,
                config.parity_shards
            );
        }
    } else if config.parity_shards > 0 {
        tracing::warn!("--parity-shards ignored: requires --erasure-coding to be enabled");
    }
    let display_host = if config.address == "0.0.0.0" {
        "localhost"
    } else {
        &config.address
    };
    tracing::info!("Web UI:     http://{}:{}/ui/", display_host, config.port);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(())
}

async fn run_healthcheck(url: &str, timeout_ms: u64) -> anyhow::Result<()> {
    let uri: Uri = url.parse()?;
    if uri.scheme_str() != Some("http") {
        anyhow::bail!("unsupported scheme in healthcheck URL: only http is supported");
    }

    let host = uri
        .host()
        .ok_or_else(|| anyhow::anyhow!("healthcheck URL is missing host"))?;
    let port = uri.port_u16().unwrap_or(80);
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let timeout_duration = Duration::from_millis(timeout_ms);

    let mut stream: TcpStream = timeout(timeout_duration, TcpStream::connect((host, port)))
        .await
        .map_err(|_| anyhow::anyhow!("healthcheck connect timeout after {}ms", timeout_ms))??;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: maxio-healthcheck/{}\r\n\r\n",
        path_and_query,
        host,
        env!("CARGO_PKG_VERSION")
    );
    timeout(timeout_duration, stream.write_all(request.as_bytes()))
        .await
        .map_err(|_| anyhow::anyhow!("healthcheck write timeout after {}ms", timeout_ms))??;

    let mut response = Vec::new();
    timeout(timeout_duration, stream.read_to_end(&mut response))
        .await
        .map_err(|_| anyhow::anyhow!("healthcheck read timeout after {}ms", timeout_ms))??;

    let status_line = String::from_utf8_lossy(&response)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string();
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse::<u16>().ok())
        .ok_or_else(|| anyhow::anyhow!("invalid HTTP response from {}", url))?;

    if (200..300).contains(&status_code) {
        println!("ok");
        return Ok(());
    }

    anyhow::bail!("healthcheck failed with HTTP status {}", status_code);
}

async fn run_keyring_rotate(data_dir: &str) -> anyhow::Result<()> {
    let result = storage::keys::rotate(data_dir).await?;
    println!("✓ keyring rotated at {}/.maxio-keys.json", data_dir);
    println!("  new active key id: {}", result.new_active_id);
    match result.previous_active_id {
        Some(prev) => println!(
            "  previous active:   {} (retained for old-object decryption)",
            prev
        ),
        None => println!("  previous active:   <none> (first key in ring)"),
    }
    println!("  total keys in ring: {}", result.total_keys);
    println!();
    println!("Restart the server to begin encrypting new objects with the new key.");
    Ok(())
}

async fn run_keyring_list(data_dir: &str) -> anyhow::Result<()> {
    let path = format!("{}/.maxio-keys.json", data_dir);
    let data = match tokio::fs::read_to_string(&path).await {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("No keyring file yet at {}", path);
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    // Minimal pretty-print: parse, strip key_b64 fields, show id/created/active.
    let v: serde_json::Value = serde_json::from_str(&data)?;
    let empty = Vec::new();
    let entries = v.get("keys").and_then(|k| k.as_array()).unwrap_or(&empty);
    println!("{:<20}  {:<26}  ACTIVE", "KEY_ID", "CREATED_AT");
    for e in entries {
        let id = e.get("id").and_then(|x| x.as_str()).unwrap_or("?");
        let created = e.get("created_at").and_then(|x| x.as_str()).unwrap_or("?");
        let active = e.get("active").and_then(|x| x.as_bool()).unwrap_or(false);
        println!(
            "{:<20}  {:<26}  {}",
            id,
            created,
            if active { "yes" } else { "no" }
        );
    }
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install CTRL+C signal handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("SIGINT (Ctrl+C) received, draining connections...");
        }
        _ = terminate => {
            tracing::info!("SIGTERM received, draining connections...");
        }
    }
}
