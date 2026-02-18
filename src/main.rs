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

    let storage = storage::filesystem::FilesystemStorage::new(&config.data_dir).await?;

    let state = server::AppState {
        storage: Arc::new(storage),
        config: Arc::new(config.clone()),
    };

    let app = server::build_router(state);

    let addr = format!("{}:{}", config.address, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Maxio listening on {}", addr);
    tracing::info!("Access Key: {}", config.access_key);
    tracing::info!("Secret Key: {}", config.secret_key);
    tracing::info!("Data dir:   {}", config.data_dir);
    tracing::info!("Region:     {}", config.region);

    axum::serve(listener, app)
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
