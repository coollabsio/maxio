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
mod iam;
mod limits;
mod openapi;
mod serve;
mod server;
mod storage;
mod vhost;
mod xml;

use clap::Parser;
use clap::Subcommand;
use config::Config;
use http::Uri;
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

    /// Scan the data directory for crash leftovers and inconsistent objects.
    ///
    /// Reports orphaned data, sidecar mismatches, stale temp files, promote
    /// directories, and multipart debris. `--repair` fixes the cases that can
    /// be made consistent from the bytes already on disk. Bytes with no
    /// sidecar are moved to `.maxio-quarantine/` instead of being adopted.
    /// Stop the server first.
    Check {
        /// Data directory to scan
        #[arg(long, env = "MAXIO_DATA_DIR", default_value = "./data")]
        data_dir: String,

        /// Rewrite or remove inconsistencies that can be fixed safely.
        /// Refuses to run while a maxio server holds the data directory lock.
        #[arg(long)]
        repair: bool,

        /// SSE-S3 master key (base64-encoded 32 bytes). Same as the server flag.
        /// When omitted, MAXIO_MASTER_KEY from the environment is used.
        #[arg(long)]
        master_key: Option<String>,

        /// File containing the SSE-S3 master key. Same as the server flag.
        /// When omitted, MAXIO_MASTER_KEY_FILE from the environment is used.
        #[arg(long)]
        master_key_file: Option<std::path::PathBuf>,

        /// With `--repair`, record a mismatched checksum or single-part etag
        /// from the payload instead of quarantining the object.
        #[arg(long)]
        accept_current_checksums: bool,

        /// With `--repair`, when two copies differ and neither can be verified,
        /// record a content hash of the current bytes and rebuild the archive
        /// from them. Without this flag those copies are left unchanged.
        #[arg(long)]
        accept_unverifiable_current: bool,

        /// With `--repair`, when two copies differ and neither can be verified,
        /// quarantine the current object and restore it from the archived copy
        /// of the same version id. Off unless this flag is set. When both this
        /// flag and `--accept-unverifiable-current` are set, the archive is
        /// restored and the current bytes are quarantined.
        #[arg(long)]
        restore_unverifiable_from_archive: bool,
    },

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

    /// Add every key from another keyring file into this data directory.
    ///
    /// Keeps the keys already stored here. The active key does not change when
    /// this data directory already has one. Use this after
    /// `--allow-missing-master-key` created a new key and you still have the
    /// original `.maxio-keys.json`: pass that backup as `--from`. Do not copy
    /// the backup over the current file; that drops the new key.
    Merge {
        #[arg(long, env = "MAXIO_DATA_DIR", default_value = "./data")]
        data_dir: String,
        /// Keyring file to merge in. Key material is not printed.
        #[arg(long)]
        from: std::path::PathBuf,
    },
}

fn default_healthcheck_url() -> String {
    let port = std::env::var("MAXIO_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(9000);
    format!("http://127.0.0.1:{}/maxio/health/live", port)
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
        Some(Commands::Keyring(KeyringCmd::Merge {
            ref data_dir,
            ref from,
        })) => {
            return run_keyring_merge(data_dir, from).await;
        }
        Some(Commands::Check {
            ref data_dir,
            repair,
            ref master_key,
            ref master_key_file,
            accept_current_checksums,
            accept_unverifiable_current,
            restore_unverifiable_from_archive,
        }) => {
            // Read-only check must not stamp a marker. --repair writes it
            // only after the data-directory lock is held (see check_with).
            // A newer format is refused here, before any rewrite.
            storage::format::ensure_readable(data_dir).await?;
            let inline = master_key.as_deref().or(cli.config.master_key.as_deref());
            let file = master_key_file
                .as_deref()
                .or(cli.config.master_key_file.as_deref());
            let resolved = storage::keys::resolve_master_key(inline, file).await?;
            return run_check(
                data_dir,
                repair,
                accept_current_checksums,
                accept_unverifiable_current,
                restore_unverifiable_from_archive,
                resolved.as_deref(),
            )
            .await;
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
    let virtual_domains =
        vhost::parse_domains(&config.domain).map_err(|err| anyhow::anyhow!(err))?;

    if config.access_key == "maxioadmin"
        && config.secret_key == "maxioadmin"
        && !config.allow_insecure_dev
    {
        anyhow::bail!(
            "refusing to start with the default credentials (maxioadmin/maxioadmin). \
             Set MAXIO_ACCESS_KEY and MAXIO_SECRET_KEY, then open http://localhost:9000/ui/. \
             Pass --allow-insecure-dev only for a trusted local machine that should keep the defaults."
        );
    }

    // Lock first, then stamp the format marker, so two processes cannot
    // migrate the same directory. Held until exit, including a graceful
    // shutdown. A crash closes the fd and the OS drops the flock.
    let _data_lock = storage::lock::acquire_exclusive(
        std::path::Path::new(&config.data_dir),
        storage::lock::LockReason::Serve,
    )?;
    let format_version = storage::format::ensure_current(&config.data_dir).await?;
    tracing::info!("on-disk format version {format_version}");

    // Resolve the external key before any keyring file is created. IAM secrets
    // use the same key, so a missing keyring must not be replaced while
    // iam.json still holds sealed secrets.
    let master_key_b64 = storage::keys::resolve_master_key(
        config.master_key.as_deref(),
        config.master_key_file.as_deref(),
    )
    .await?;
    iam::secrets::refuse_missing_keyring(
        &config.data_dir,
        master_key_b64.is_some(),
        config.allow_missing_master_key,
    )
    .await?;
    let keyring = Arc::new(if config.allow_missing_master_key {
        storage::keys::Keyring::load_with(
            &config.data_dir,
            storage::keys::LoadOptions {
                master_key_b64: master_key_b64.as_deref(),
                allow_missing_master_key: true,
            },
        )
        .await?
    } else {
        storage::keys::Keyring::load(&config.data_dir, master_key_b64.as_deref()).await?
    });
    iam::store::ensure_secrets_readable(&config.data_dir, &keyring)
        .await
        .map_err(|err| {
            if config.allow_missing_master_key {
                anyhow::Error::msg(format!(
                    "{err}\n\n{}",
                    iam::secrets::allow_missing_does_not_cover_iam(&config.data_dir)
                ))
            } else {
                anyhow::Error::msg(err)
            }
        })?;
    match (&config.master_key, &config.master_key_file) {
        (_, Some(path)) => {
            tracing::info!(
                "SSE-S3 keyring: active key id {} (from master key file {}; not written into the data directory)",
                keyring.active_id(),
                path.display()
            );
        }
        (Some(_), None) => {
            tracing::info!(
                "SSE-S3 keyring: active key id {} (from MAXIO_MASTER_KEY; not written into the data directory)",
                keyring.active_id()
            );
        }
        (None, None) => {
            tracing::info!(
                "SSE-S3 keyring: active key id {} (file {}/.maxio-keys.json — BACK THIS UP; {}/.maxio-key-check.json stays with the data and has no key material)",
                keyring.active_id(),
                config.data_dir,
                config.data_dir
            );
        }
    }

    let mut storage = storage::filesystem::FilesystemStorage::new(
        &config.data_dir,
        config.erasure_coding,
        config.chunk_size,
        config.parity_shards,
        keyring.clone(),
    )
    .await?;
    storage.set_upload_limits(
        config.max_object_size,
        config.max_part_size,
        config.max_multipart_object_size,
    );

    storage::provision_default_buckets(&storage, &config.default_buckets, &config.region).await;

    let state = server::AppState {
        storage: Arc::new(storage),
        config: Arc::new(config.clone()),
        login_rate_limiter: Arc::new(
            api::console::LoginRateLimiter::from_trusted(&config.trusted_proxy)
                .map_err(|err| anyhow::anyhow!(err))?,
        ),
        revoked_sessions: Arc::new(
            api::console::RevokedSessions::open(std::path::Path::new(&config.data_dir)).await,
        ),
    };

    // Background housekeeping: abort stale multipart uploads (>7 days),
    // remove leftover temp files from crashed writes, and apply bucket
    // lifecycle rules. Runs once at startup, then hourly. Stops when the
    // process begins draining for shutdown.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    {
        let storage = state.storage.clone();
        let mut shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            let stale_after = chrono::Duration::days(7);
            let mut ticker = tokio::time::interval(Duration::from_secs(3600));
            loop {
                tokio::select! {
                    _ = ticker.tick() => {}
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            break;
                        }
                        continue;
                    }
                }
                let (uploads, temps) = storage.housekeeping_sweep(stale_after).await;
                if uploads > 0 || temps > 0 {
                    tracing::info!(
                        "housekeeping: removed {} stale upload(s), {} temp file(s)",
                        uploads,
                        temps
                    );
                }
                let stats = storage::lifecycle::run_lifecycle(&storage, chrono::Utc::now()).await;
                if stats.did_something() {
                    tracing::info!(
                        "lifecycle: expired {} object(s), {} noncurrent version(s), \
                         {} delete marker(s), aborted {} upload(s)",
                        stats.expired_objects,
                        stats.noncurrent_versions_expired,
                        stats.delete_markers_removed,
                        stats.uploads_aborted,
                    );
                }
                if stats.errors > 0 {
                    tracing::warn!("lifecycle: {} error(s) during sweep", stats.errors);
                }
            }
        });
    }

    let app = server::build_router(state);

    let addr = format!("{}:{}", config.address, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    let bound = listener.local_addr()?;
    if config.access_key == "maxioadmin" && config.secret_key == "maxioadmin" {
        tracing::warn!(
            "WARNING: Using default credentials because insecure development mode is enabled."
        );
    }

    tracing::info!(
        "MaxIO v{} listening on {}",
        env!("CARGO_PKG_VERSION"),
        bound
    );
    tracing::info!("Access Key: {}", config.access_key);
    tracing::info!("Secret Key: [REDACTED]");
    tracing::info!("Data dir:   {}", config.data_dir);
    tracing::info!("Region:     {}", config.region);
    if virtual_domains.is_empty() {
        tracing::info!("Addressing: path-style");
    } else {
        tracing::info!(
            "Addressing: path-style and virtual-hosted-style ({})",
            virtual_domains.join(", ")
        );
    }
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
    tracing::info!("Web UI:     http://{}:{}/ui/", display_host, bound.port());

    let serve_opts = serve::ServeOptions {
        max_header_bytes: config.max_header_bytes,
        max_connections: config.max_connections,
        idle_timeout: Duration::from_secs(config.idle_timeout_secs),
        shutdown_timeout: Duration::from_secs(config.shutdown_timeout_secs),
    };
    let shutdown_tx_for_signal = shutdown_tx.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx_for_signal.send(true);
    });
    match serve::serve(listener, app, serve_opts, shutdown_rx).await? {
        serve::ShutdownOutcome::Drained => {
            tracing::info!("in-flight requests drained; shutdown complete");
        }
        serve::ShutdownOutcome::TimedOut => {
            tracing::warn!(
                "shutdown timeout of {}s elapsed; aborted remaining connections",
                config.shutdown_timeout_secs
            );
        }
    }
    let _ = shutdown_tx.send(true);

    Ok(())
}

async fn run_check(
    data_dir: &str,
    repair: bool,
    accept_current_checksums: bool,
    accept_unverifiable_current: bool,
    restore_unverifiable_from_archive: bool,
    master_key_b64: Option<&str>,
) -> anyhow::Result<()> {
    let report = storage::check::check_with_opts(
        std::path::Path::new(data_dir),
        repair,
        master_key_b64,
        accept_current_checksums,
        accept_unverifiable_current,
        restore_unverifiable_from_archive,
    )
    .await?;
    report.print();
    if report.unresolved() > 0 {
        anyhow::bail!(report.failure_message(repair));
    }
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
    // The lock is taken before the format marker or the keyring file is written,
    // and a running server already holds it.
    let _lock = storage::lock::acquire_exclusive(
        std::path::Path::new(data_dir),
        storage::lock::LockReason::RotateKeyring,
    )?;
    storage::format::ensure_current(data_dir).await?;
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

async fn run_keyring_merge(data_dir: &str, from: &std::path::Path) -> anyhow::Result<()> {
    // Lock before the format marker. A held lock must not stamp `.maxio-format`.
    let _lock = storage::lock::acquire_exclusive(
        std::path::Path::new(data_dir),
        storage::lock::LockReason::MergeKeyring,
    )?;
    storage::format::ensure_current(data_dir).await?;
    let result = storage::keys::merge_keyring(data_dir, from).await?;
    println!("✓ keyring merged into {data_dir}/.maxio-keys.json");
    if result.added_ids.is_empty() {
        println!("  added:             <none> (already present)");
    } else {
        println!("  added:             {}", result.added_ids.join(", "));
    }
    println!("  active key id:     {}", result.active_id);
    println!("  total keys in ring: {}", result.total_keys);
    println!();
    println!("Restart the server so it loads the merged keyring.");
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

#[cfg(test)]
mod keyring_lock_tests {
    use super::{run_keyring_merge, run_keyring_rotate};
    use crate::storage::lock::{LockReason, acquire_exclusive};

    #[tokio::test]
    async fn rotate_and_merge_take_the_lock_before_the_format_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let _held = acquire_exclusive(dir, LockReason::Serve).unwrap();

        let rotate = run_keyring_rotate(dir.to_str().unwrap())
            .await
            .unwrap_err()
            .to_string();
        assert!(
            rotate.contains("rotating the keyring"),
            "rotate must refuse while a server holds the lock: {rotate}"
        );
        assert!(
            !dir.join(".maxio-format").exists(),
            "rotate wrote the format marker without the lock"
        );

        let merge = run_keyring_merge(
            dir.to_str().unwrap(),
            std::path::Path::new("/no/such/keyring.json"),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            merge.contains("merging the keyring"),
            "merge must refuse while a server holds the lock: {merge}"
        );
        assert!(
            !dir.join(".maxio-format").exists(),
            "merge wrote the format marker without the lock"
        );
    }
}
