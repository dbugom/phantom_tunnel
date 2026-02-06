//! Configuration management

use crate::obfuscation::BrowserProfile;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Main configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server configuration
    pub server: Option<ServerConfig>,
    /// Client configuration
    pub client: Option<ClientConfig>,
    /// Logging configuration
    pub logging: LoggingConfig,
}

impl Config {
    /// Load configuration from file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, crate::Error> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| crate::Error::Config(format!("Failed to read config: {}", e)))?;

        toml::from_str(&content)
            .map_err(|e| crate::Error::Config(format!("Failed to parse config: {}", e)))
    }

    /// Save configuration to file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), crate::Error> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| crate::Error::Config(format!("Failed to serialize config: {}", e)))?;

        std::fs::write(path, content)
            .map_err(|e| crate::Error::Config(format!("Failed to write config: {}", e)))
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: None,
            client: None,
            logging: LoggingConfig::default(),
        }
    }
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Listen address
    pub listen: String,
    /// Server private key (base64)
    #[serde(default)]
    pub private_key: String,
    /// Server public key (base64) - derived from private key, stored for convenience
    #[serde(default)]
    pub public_key: String,
    /// Allowed client public keys (base64)
    pub allowed_clients: Vec<String>,
    /// TLS certificate path (for obfuscation)
    pub tls_cert: Option<String>,
    /// TLS key path
    pub tls_key: Option<String>,
    /// Decoy website to serve for invalid requests
    pub decoy_site: Option<String>,
    /// Maximum concurrent connections
    pub max_connections: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:443".to_string(),
            private_key: String::new(),
            public_key: String::new(),
            allowed_clients: Vec::new(),
            tls_cert: None,
            tls_key: None,
            decoy_site: None,
            max_connections: 1000,
        }
    }
}

/// Client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Server address
    pub server: String,
    /// Server public key (base64)
    pub server_public_key: String,
    /// Client private key (base64)
    #[serde(default)]
    pub private_key: String,
    /// Client public key (base64) - share this with server admin
    #[serde(default)]
    pub public_key: String,
    /// Local SOCKS5 proxy address
    pub socks5_listen: Option<String>,
    /// Local HTTP proxy address
    pub http_listen: Option<String>,
    /// TLS SNI to use (for camouflage)
    pub tls_sni: Option<String>,
    /// TLS fingerprint profile
    pub tls_profile: String,
    /// Enable padding
    pub enable_padding: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server: "127.0.0.1:443".to_string(),
            server_public_key: String::new(),
            private_key: String::new(),
            public_key: String::new(),
            socks5_listen: Some("127.0.0.1:1080".to_string()),
            http_listen: Some("127.0.0.1:8080".to_string()),
            tls_sni: None,
            tls_profile: "chrome".to_string(),
            enable_padding: true,
        }
    }
}

impl ClientConfig {
    /// Get the browser profile from the tls_profile string
    pub fn browser_profile(&self) -> BrowserProfile {
        match self.tls_profile.to_lowercase().as_str() {
            "chrome" => BrowserProfile::Chrome,
            "firefox" => BrowserProfile::Firefox,
            "safari" => BrowserProfile::Safari,
            "edge" => BrowserProfile::Edge,
            "random" => BrowserProfile::Random,
            "ios" | "ios_safari" => BrowserProfile::IosSafari,
            "android" | "android_chrome" => BrowserProfile::AndroidChrome,
            _ => BrowserProfile::Chrome, // Default to Chrome
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    pub level: String,
    /// Log format (pretty, json, compact)
    pub format: String,
    /// Log file path (optional)
    pub file: Option<String>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "pretty".to_string(),
            file: None,
        }
    }
}

/// Generate example configuration
pub fn generate_example_config() -> Config {
    Config {
        server: Some(ServerConfig::default()),
        client: Some(ClientConfig::default()),
        logging: LoggingConfig::default(),
    }
}
