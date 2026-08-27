//! YAML configuration types for the server.
//!
//! Example:
//! ```yaml
//! log_level: info
//! servers:
//!   - type: hysteria2
//!     listen: "0.0.0.0:443"
//!     password: "secret"
//!     cert: cert.pem
//!     key: key.pem
//!   - type: anytls
//!     listen: "0.0.0.0:8443"
//!     cert: cert.pem
//!     key: key.pem
//!     users:
//!       - name: user1
//!         password: "secret123"
//! ```

use serde::Deserialize;

use crate::address::NetLocation;

/// Default max concurrent connections per server.
const DEFAULT_MAX_CONNECTIONS: u32 = 4096;

/// Default TCP congestion control algorithm (BBR).
const DEFAULT_TCP_CONGESTION: &str = "bbr";

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub servers: Vec<ServerConfig>,
    /// TCP congestion control algorithm for outbound connections
    /// (default: "bbr"). Set to "" to use the system default.
    #[serde(default = "default_tcp_congestion")]
    pub tcp_congestion: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ServerConfig {
    Hysteria2(Hysteria2Config),
    Anytls(AnyTlsConfig),
}

#[derive(Debug, Clone, Deserialize)]
pub struct Hysteria2Config {
    pub listen: String,
    pub password: String,
    #[serde(default = "default_true")]
    pub udp_enabled: bool,
    #[serde(default)]
    pub cert: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    /// ALPN protocols (default: ["h3"])
    #[serde(default)]
    pub alpn: Vec<String>,
    /// Maximum concurrent connections (default: 4096).
    /// Set to 0 for unlimited (not recommended — may exhaust file descriptors).
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AnyTlsConfig {
    pub listen: String,
    #[serde(default)]
    pub cert: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default = "default_true")]
    pub udp_enabled: bool,
    #[serde(default)]
    pub users: Vec<AnyTlsUser>,
    /// Optional custom padding scheme (default is the AnyTLS spec default)
    #[serde(default)]
    pub padding_scheme: Option<String>,
    /// Optional fallback destination for failed authentication
    #[serde(default)]
    pub fallback: Option<NetLocation>,
    /// Maximum concurrent connections (default: 4096).
    /// Set to 0 for unlimited (not recommended — may exhaust file descriptors).
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AnyTlsUser {
    pub name: String,
    pub password: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_true() -> bool {
    true
}

fn default_max_connections() -> u32 {
    DEFAULT_MAX_CONNECTIONS
}

fn default_tcp_congestion() -> String {
    DEFAULT_TCP_CONGESTION.to_string()
}

impl Config {
    pub fn load(path: &str) -> std::io::Result<Self> {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            std::io::Error::new(e.kind(), format!("failed to read config {path}: {e}"))
        })?;
        serde_yaml::from_str(&contents)
            .map_err(|e| std::io::Error::other(format!("failed to parse config {path}: {e}")))
    }
}
