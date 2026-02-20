use clap::Parser;
use std::env;

fn first_env_value(keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| env::var(key).ok().filter(|value| !value.trim().is_empty()))
}

fn default_access_key() -> String {
    first_env_value(&["MINIO_ROOT_USER", "MINIO_ACCESS_KEY"])
        .unwrap_or_else(|| "minioadmin".to_string())
}

fn default_secret_key() -> String {
    first_env_value(&["MINIO_ROOT_PASSWORD", "MINIO_SECRET_KEY"])
        .unwrap_or_else(|| "minioadmin".to_string())
}

fn default_region() -> String {
    first_env_value(&["MINIO_REGION_NAME", "MINIO_REGION"])
        .unwrap_or_else(|| "us-east-1".to_string())
}

#[derive(Parser, Debug, Clone)]
#[command(name = "maxio", about = "S3-compatible object storage server", version = env!("MAXIO_VERSION"))]
pub struct Config {
    /// Port to listen on
    #[arg(long, env = "MAXIO_PORT", default_value = "9000")]
    pub port: u16,

    /// Address to bind to
    #[arg(long, env = "MAXIO_ADDRESS", default_value = "0.0.0.0")]
    pub address: String,

    /// Root data directory
    #[arg(long, env = "MAXIO_DATA_DIR", default_value = "./data")]
    pub data_dir: String,

    /// Access key (MAXIO_ACCESS_KEY, MINIO_ROOT_USER, MINIO_ACCESS_KEY)
    #[arg(long, env = "MAXIO_ACCESS_KEY", default_value_t = default_access_key())]
    pub access_key: String,

    /// Secret key (MAXIO_SECRET_KEY, MINIO_ROOT_PASSWORD, MINIO_SECRET_KEY)
    #[arg(long, env = "MAXIO_SECRET_KEY", default_value_t = default_secret_key())]
    pub secret_key: String,

    /// Default region (MAXIO_REGION, MINIO_REGION_NAME, MINIO_REGION)
    #[arg(long, env = "MAXIO_REGION", default_value_t = default_region())]
    pub region: String,

    /// Enable erasure coding with per-chunk integrity checksums
    #[arg(long, env = "MAXIO_ERASURE_CODING", default_value = "false")]
    pub erasure_coding: bool,

    /// Chunk size in bytes for erasure coding (default 10MB)
    #[arg(long, env = "MAXIO_CHUNK_SIZE", default_value = "10485760")]
    pub chunk_size: u64,

    /// Number of parity shards for erasure coding (0 = no parity, requires --erasure-coding)
    #[arg(long, env = "MAXIO_PARITY_SHARDS", default_value = "0")]
    pub parity_shards: u32,
}
