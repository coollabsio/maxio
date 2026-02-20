mod api;
mod auth;
mod config;
mod embedded;
mod error;
mod server;
mod storage;
mod xml;

use clap::Parser;
use config::Config;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::parse();

    let storage = storage::filesystem::FilesystemStorage::new(
        &config.data_dir,
        config.erasure_coding,
        config.chunk_size,
        config.parity_shards,
    ).await?;

    let state = server::AppState {
        storage: Arc::new(storage),
        config: Arc::new(config.clone()),
        login_rate_limiter: Arc::new(api::console::LoginRateLimiter::new()),
    };

    let app = server::build_router(state);

    let addr = format!("{}:{}", config.address, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    if config.access_key == "minioadmin" && config.secret_key == "minioadmin" {
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

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");
    tracing::info!("Shutdown signal received, draining connections...");
}
