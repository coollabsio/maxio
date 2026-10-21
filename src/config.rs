use clap::Args;
use std::env;

fn first_env_value(keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| env::var(key).ok().filter(|value| !value.trim().is_empty()))
}

fn default_access_key() -> String {
    first_env_value(&["MINIO_ROOT_USER", "MINIO_ACCESS_KEY"])
        .unwrap_or_else(|| "maxioadmin".to_string())
}

fn default_secret_key() -> String {
    first_env_value(&["MINIO_ROOT_PASSWORD", "MINIO_SECRET_KEY"])
        .unwrap_or_else(|| "maxioadmin".to_string())
}

fn default_region() -> String {
    first_env_value(&["MINIO_REGION_NAME", "MINIO_REGION"])
        .unwrap_or_else(|| "us-east-1".to_string())
}

fn default_default_buckets() -> Option<String> {
    first_env_value(&["MINIO_DEFAULT_BUCKETS"])
}

fn default_domain() -> String {
    first_env_value(&["MINIO_DOMAIN"]).unwrap_or_default()
}

#[derive(Args, Debug, Clone)]
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

    /// SSE-S3 master key (base64-encoded 32 bytes).
    /// Active key for new writes. Not copied into the data directory.
    /// Mutually exclusive with `--master-key-file`.
    #[arg(long, env = "MAXIO_MASTER_KEY")]
    pub master_key: Option<String>,

    /// File containing the SSE-S3 master key (base64-encoded 32 bytes, or 32 raw bytes).
    /// Keeps the key outside the data directory. Not copied into the data directory.
    /// Mutually exclusive with `--master-key`.
    #[arg(long, env = "MAXIO_MASTER_KEY_FILE")]
    pub master_key_file: Option<std::path::PathBuf>,

    /// Start even when SSE-S3 objects exist and their master key is missing.
    /// Those objects stay unreadable. Does not overwrite an unreadable or corrupt keyring file.
    /// Required on every start until the original keys are restored.
    #[arg(long, env = "MAXIO_ALLOW_MISSING_MASTER_KEY", default_value = "false")]
    pub allow_missing_master_key: bool,

    /// Allow the built-in maxioadmin credentials and omit Secure on console cookies for every host.
    /// For local development only. A production server should set its own access key and secret key.
    #[arg(long, env = "MAXIO_ALLOW_INSECURE_DEV", default_value = "false")]
    pub allow_insecure_dev: bool,

    /// Mark console session cookies Secure.
    /// On by default. HTTPS requests (`X-Forwarded-Proto: https`) and any non-loopback host
    /// get a Secure cookie. Plain HTTP to localhost omits it so a browser will store the session.
    /// Set to false only to allow a non-Secure cookie on a non-loopback HTTP host.
    #[arg(long, env = "MAXIO_SECURE_COOKIES", default_value = "true")]
    pub secure_cookies: bool,

    /// Enable erasure coding with per-chunk integrity checksums
    #[arg(long, env = "MAXIO_ERASURE_CODING", default_value = "false")]
    pub erasure_coding: bool,

    /// Chunk size in bytes for erasure coding (default 10MB)
    #[arg(long, env = "MAXIO_CHUNK_SIZE", default_value = "10485760")]
    pub chunk_size: u64,

    /// Number of parity shards for erasure coding (0 = no parity, requires --erasure-coding)
    #[arg(long, env = "MAXIO_PARITY_SHARDS", default_value = "0")]
    pub parity_shards: u32,

    /// Comma-separated list of bucket names to create on first boot
    /// (MAXIO_DEFAULT_BUCKETS, MINIO_DEFAULT_BUCKETS)
    #[arg(long, env = "MAXIO_DEFAULT_BUCKETS", default_value_t = default_default_buckets().unwrap_or_default())]
    pub default_buckets: String,

    /// Max request body size for console JSON/form API routes, in bytes. Object uploads are streaming and not covered by this limit.
    #[arg(long, env = "MAXIO_MAX_CONSOLE_BODY_BYTES", default_value = "1048576")]
    pub max_console_body_bytes: usize,

    /// Seconds to drain in-flight requests after SIGTERM or SIGINT before exiting.
    /// Docker's default stop timeout is 10s, so the default here finishes first.
    /// Raise both together when in-flight uploads should be allowed to finish.
    #[arg(long, env = "MAXIO_SHUTDOWN_TIMEOUT_SECS", default_value_t = 8)]
    pub shutdown_timeout_secs: u64,

    /// Max bytes in one PutObject or CopyObject. Larger objects must use multipart.
    /// Default is 5 GiB, the S3 single-PUT limit.
    #[arg(long, env = "MAXIO_MAX_OBJECT_SIZE", default_value_t = 5 * 1024 * 1024 * 1024)]
    pub max_object_size: u64,

    /// Max bytes in one multipart part. Default is 5 GiB.
    #[arg(long, env = "MAXIO_MAX_PART_SIZE", default_value_t = 5 * 1024 * 1024 * 1024)]
    pub max_part_size: u64,

    /// Max assembled size of one multipart object. Default is 5 TiB.
    #[arg(
        long,
        env = "MAXIO_MAX_MULTIPART_OBJECT_SIZE",
        default_value_t = 5 * 1024 * 1024 * 1024 * 1024
    )]
    pub max_multipart_object_size: u64,

    /// Max total request-header bytes. Hyper also rejects a header block larger
    /// than this (minimum 8192, which is hyper's floor).
    #[arg(long, env = "MAXIO_MAX_HEADER_BYTES", default_value_t = 64 * 1024)]
    pub max_header_bytes: usize,

    /// Max accepted TCP connections. Extra connections receive SlowDown (503) and are closed.
    /// 0 disables the cap.
    #[arg(long, env = "MAXIO_MAX_CONNECTIONS", default_value_t = 1024)]
    pub max_connections: usize,

    /// Max requests handled at once. Further requests receive SlowDown (503).
    /// Health checks are exempt. 0 disables the cap.
    #[arg(long, env = "MAXIO_MAX_CONCURRENT_REQUESTS", default_value_t = 256)]
    pub max_concurrent_requests: usize,

    /// Max seconds a request may run, including the body upload. 0 disables the cap.
    #[arg(long, env = "MAXIO_REQUEST_TIMEOUT_SECS", default_value_t = 3600)]
    pub request_timeout_secs: u64,

    /// Seconds a keep-alive connection may sit idle before it is closed.
    /// 0 disables the cap.
    #[arg(long, env = "MAXIO_IDLE_TIMEOUT_SECS", default_value_t = 60)]
    pub idle_timeout_secs: u64,

    /// Comma-separated proxy addresses allowed to set `X-Forwarded-For` for the
    /// console login limit. Each entry is an IP or a CIDR. Empty (the default)
    /// ignores the header and uses the TCP peer address.
    #[arg(long, env = "MAXIO_TRUSTED_PROXY", default_value = "")]
    pub trusted_proxy: String,

    /// Comma-separated base domains for virtual-hosted-style addressing.
    /// A request to `<bucket>.<domain>` is served from that bucket. Unset leaves every host on path-style.
    /// `MINIO_DOMAIN` is accepted when `MAXIO_DOMAIN` is unset.
    #[arg(long = "domain", env = "MAXIO_DOMAIN", default_value_t = default_domain())]
    pub domain: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 9000,
            address: "0.0.0.0".into(),
            data_dir: "./data".into(),
            access_key: default_access_key(),
            secret_key: default_secret_key(),
            region: default_region(),
            master_key: None,
            master_key_file: None,
            allow_missing_master_key: false,
            allow_insecure_dev: false,
            secure_cookies: true,
            erasure_coding: false,
            chunk_size: 10_485_760,
            parity_shards: 0,
            default_buckets: String::new(),
            max_console_body_bytes: 1_048_576,
            shutdown_timeout_secs: 8,
            max_object_size: 5 * 1024 * 1024 * 1024,
            max_part_size: 5 * 1024 * 1024 * 1024,
            max_multipart_object_size: 5 * 1024 * 1024 * 1024 * 1024,
            max_header_bytes: 64 * 1024,
            max_connections: 1024,
            max_concurrent_requests: 256,
            request_timeout_secs: 3600,
            idle_timeout_secs: 60,
            trusted_proxy: String::new(),
            domain: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Config;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct TestCli {
        #[command(flatten)]
        config: Config,
    }

    #[test]
    fn default_address_is_all_interfaces() {
        unsafe {
            std::env::remove_var("MAXIO_ADDRESS");
        }

        let cli = TestCli::parse_from(["maxio"]);

        assert_eq!(cli.config.address, "0.0.0.0");
    }

    #[test]
    fn domain_flag_is_comma_separated_and_defaults_empty() {
        unsafe {
            std::env::remove_var("MAXIO_DOMAIN");
            std::env::remove_var("MINIO_DOMAIN");
        }
        let cli = TestCli::parse_from(["maxio"]);
        assert_eq!(cli.config.domain, "");

        let cli = TestCli::parse_from(["maxio", "--domain", "localhost,s3.example.com"]);
        assert_eq!(cli.config.domain, "localhost,s3.example.com");
    }
}
