use clap::Parser;

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

    /// Access key (like AWS_ACCESS_KEY_ID)
    #[arg(long, env = "MAXIO_ACCESS_KEY", default_value = "minioadmin")]
    pub access_key: String,

    /// Secret key (like AWS_SECRET_ACCESS_KEY)
    #[arg(long, env = "MAXIO_SECRET_KEY", default_value = "minioadmin")]
    pub secret_key: String,

    /// Default region
    #[arg(long, env = "MAXIO_REGION", default_value = "us-east-1")]
    pub region: String,
}
