mod api;
mod auth;
mod config;
mod embedded;
mod error;
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
    version = env!("MAXIO_VERSION")
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[command(flatten)]
    config: Config,
}

#[derive(Subcommand, Debug)]
enum Commands {
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
        Some(Commands::Healthcheck { url, timeout_ms }) => {
            return run_healthcheck(&url, timeout_ms).await;
        }
        Some(Commands::Keyring(KeyringCmd::Rotate { ref data_dir })) => {
            return run_keyring_rotate(data_dir).await;
        }
        Some(Commands::Keyring(KeyringCmd::List { ref data_dir })) => {
            return run_keyring_list(data_dir).await;
        }
        None => {}
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = cli.config;

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
    ).await?;

    let state = server::AppState {
        storage: Arc::new(storage),
        config: Arc::new(config.clone()),
        login_rate_limiter: Arc::new(api::console::LoginRateLimiter::new()),
    };

    let app = server::build_router(state);

    let addr = format!("{}:{}", config.address, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    if config.access_key == "maxioadmin" && config.secret_key == "maxioadmin" {
        tracing::warn!(
            "WARNING: Using default credentials. Set MAXIO_ACCESS_KEY/MAXIO_SECRET_KEY (or MINIO_ROOT_USER/MINIO_ROOT_PASSWORD) for production use."
        );
    }

    tracing::info!("MaxIO v{} listening on {}", env!("MAXIO_VERSION"), addr);
    tracing::info!("Access Key: {}", config.access_key);
    tracing::info!("Secret Key: [REDACTED]");
    tracing::info!("Data dir:   {}", config.data_dir);
    tracing::info!("Region:     {}", config.region);
    if config.erasure_coding {
        tracing::info!("Erasure coding: enabled (chunk size: {}MB)", config.chunk_size / (1024 * 1024));
        if config.parity_shards > 0 {
            tracing::info!("Parity shards: {} (can tolerate {} lost/corrupt chunks per object)", config.parity_shards, config.parity_shards);
        }
    } else if config.parity_shards > 0 {
        tracing::warn!("--parity-shards ignored: requires --erasure-coding to be enabled");
    }
    let display_host = if config.address == "0.0.0.0" { "localhost" } else { &config.address };
    tracing::info!("Web UI:     http://{}:{}/ui/", display_host, config.port);

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
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
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let timeout_duration = Duration::from_millis(timeout_ms);

    let mut stream: TcpStream = timeout(timeout_duration, TcpStream::connect((host, port)))
        .await
        .map_err(|_| anyhow::anyhow!("healthcheck connect timeout after {}ms", timeout_ms))??;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: maxio-healthcheck/{}\r\n\r\n",
        path_and_query,
        host,
        env!("MAXIO_VERSION")
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
        Some(prev) => println!("  previous active:   {} (retained for old-object decryption)", prev),
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
    let entries = v
        .get("keys")
        .and_then(|k| k.as_array())
        .unwrap_or(&empty);
    println!("{:<20}  {:<26}  {}", "KEY_ID", "CREATED_AT", "ACTIVE");
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
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");
    tracing::info!("Shutdown signal received, draining connections...");
}
