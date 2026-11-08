//! Configuration management

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Main configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// Server configuration
    pub server: Option<ServerConfig>,
    /// Client configuration
    pub client: Option<ClientConfig>,
    /// Logging configuration (optional; defaults to info/pretty)
    #[serde(default)]
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

    /// Save configuration to file. The file holds the private key, so on Unix
    /// it is written with 0600 permissions (owner read/write only).
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), crate::Error> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| crate::Error::Config(format!("Failed to serialize config: {}", e)))?;

        let path = path.as_ref();
        std::fs::write(path, &content)
            .map_err(|e| crate::Error::Config(format!("Failed to write config: {}", e)))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Best-effort: don't fail the save if chmod isn't supported.
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }

        Ok(())
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
    /// Maximum concurrent connections
    pub max_connections: usize,
    /// Allow clients to reach private/loopback/link-local destinations through
    /// the tunnel. Default false to prevent SSRF against the server's own
    /// localhost, LAN, and cloud metadata endpoint (169.254.169.254).
    #[serde(default)]
    pub allow_private_destinations: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:443".to_string(),
            private_key: String::new(),
            public_key: String::new(),
            allowed_clients: Vec::new(),
            max_connections: 1000,
            allow_private_destinations: false,
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
    /// Servers to fall back to, in order, when `server` cannot be reached or
    /// refuses this client. Each entry is either `"host:port"` (same server key
    /// as `server_public_key`) or `{ address = "host:port", public_key = "..." }`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backup_servers: Vec<BackupServer>,
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
            backup_servers: Vec::new(),
        }
    }
}

/// A fallback server for the client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "BackupServerRepr")]
pub struct BackupServer {
    /// `host:port`
    pub address: String,
    /// Server public key (base64). Empty means the same key as the primary
    /// server, i.e. the same server reachable at another address, or a second
    /// box sharing the primary's key.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub public_key: String,
}

/// Accepted spellings of a [`BackupServer`] in TOML.
#[derive(Deserialize)]
#[serde(untagged)]
enum BackupServerRepr {
    Address(String),
    Full {
        address: String,
        #[serde(default)]
        public_key: String,
    },
}

impl From<BackupServerRepr> for BackupServer {
    fn from(r: BackupServerRepr) -> Self {
        match r {
            BackupServerRepr::Address(address) => Self {
                address,
                public_key: String::new(),
            },
            BackupServerRepr::Full {
                address,
                public_key,
            } => Self {
                address,
                public_key,
            },
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
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

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    /// The server config as deployed (v1 layout, comments, json logging) and
    /// the v2 copy with labelled allow-list entries must keep loading.
    #[test]
    fn deployed_server_config_still_parses() {
        let text = format!(
            r#"[server]
# NOT 443: this box's Caddy owns 443/tcp and LiveKit owns 443/udp (TURN).
listen = "0.0.0.0:8444"
public_key = "{k}"
# Clients are allow-listed by public key. Empty list = nobody gets in.
allowed_clients = [
    "{k}",  # device1
    "{k}",
]
max_connections = 100

[logging]
level = "info"
format = "json"
"#,
            k = KEY
        );
        let cfg: Config = toml::from_str(&text).expect("server config must parse");
        let s = cfg.server.unwrap();
        assert_eq!(s.listen, "0.0.0.0:8444");
        assert_eq!(s.allowed_clients.len(), 2);
        assert!(!s.allow_private_destinations, "SSRF guard must default on");
        assert_eq!(cfg.logging.format, "json");
    }

    /// Client configs written by earlier builds contain settings that no
    /// longer exist (tls_profile, enable_padding, tls_sni). They must still
    /// load, with those settings ignored.
    #[test]
    fn older_client_config_with_removed_settings_still_parses() {
        let text = format!(
            r#"[client]
server = "46.225.110.152:8444"
server_public_key = "{k}"
private_key = "{k}"
public_key = "{k}"
socks5_listen = "127.0.0.1:1080"
http_listen = "127.0.0.1:18080"
tls_sni = "www.example.com"
tls_profile = "chrome"
enable_padding = true

[logging]
level = "info"
format = "pretty"
"#,
            k = KEY
        );
        let cfg: Config = toml::from_str(&text).expect("old client config must parse");
        let c = cfg.client.unwrap();
        assert_eq!(c.server, "46.225.110.152:8444");
        assert_eq!(c.http_listen.as_deref(), Some("127.0.0.1:18080"));
    }

    /// The blank template: empty keys, and no [logging] section at all.
    #[test]
    fn minimal_client_config_without_logging_parses() {
        let text = format!(
            r#"[client]
server = "46.225.110.152:8444"
server_public_key = "{k}"
public_key = ""
socks5_listen = "127.0.0.1:1080"
"#,
            k = KEY
        );
        let cfg: Config = toml::from_str(&text).expect("minimal config must parse");
        let c = cfg.client.unwrap();
        assert!(c.private_key.is_empty() && c.public_key.is_empty());
        assert_eq!(c.http_listen, None);
        assert_eq!(cfg.logging.level, "info");
    }

    /// The example configs shipped in the repository must load.
    #[test]
    fn shipped_example_configs_parse() {
        for (name, text) in [
            ("config.example.toml", include_str!("../../config.example.toml")),
            ("examples/server.config.toml", include_str!("../../examples/server.config.toml")),
            ("examples/client.config.toml", include_str!("../../examples/client.config.toml")),
        ] {
            let cfg: Config = toml::from_str(text).unwrap_or_else(|e| panic!("{}: {}", name, e));
            assert!(cfg.server.is_some() || cfg.client.is_some(), "{} is empty", name);
        }
    }

    /// Backup servers: bare strings, inline tables and `[[client.backup_servers]]`
    /// array-of-tables all load; a config without the key has no backups.
    #[test]
    fn backup_servers_parse_in_every_spelling() {
        let text = format!(
            r#"[client]
server = "examroom.dbug.om:8444"
server_public_key = "{k}"
socks5_listen = "127.0.0.1:1080"
backup_servers = [
    "46.225.110.152:8444",                                  # same box, by IP
    {{ address = "backup.example.net:443", public_key = "{k}" }},
]
"#,
            k = KEY
        );
        let c = toml::from_str::<Config>(&text).unwrap().client.unwrap();
        assert_eq!(
            c.backup_servers,
            vec![
                BackupServer { address: "46.225.110.152:8444".into(), public_key: String::new() },
                BackupServer { address: "backup.example.net:443".into(), public_key: KEY.into() },
            ]
        );

        let text = format!(
            r#"[client]
server = "a:1"
server_public_key = "{k}"
socks5_listen = "127.0.0.1:1080"

[[client.backup_servers]]
address = "b:2"

[[client.backup_servers]]
address = "c:3"
public_key = "{k}"
"#,
            k = KEY
        );
        let c = toml::from_str::<Config>(&text).unwrap().client.unwrap();
        assert_eq!(c.backup_servers.len(), 2);
        assert_eq!(c.backup_servers[0].address, "b:2");
        assert!(c.backup_servers[0].public_key.is_empty());
        assert_eq!(c.backup_servers[1].public_key, KEY);
    }

    /// A config with backups survives save + load (the client rewrites its
    /// config when it generates a key, and `--import` writes one).
    #[test]
    fn backup_servers_survive_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = Config {
            client: Some(ClientConfig {
                server: "a:1".into(),
                server_public_key: KEY.into(),
                backup_servers: vec![
                    BackupServer { address: "b:2".into(), public_key: String::new() },
                    BackupServer { address: "[2001:db8::1]:3".into(), public_key: KEY.into() },
                ],
                ..ClientConfig::default()
            }),
            ..Config::default()
        };
        cfg.save(&path).unwrap();
        let back = Config::load(&path).unwrap().client.unwrap();
        assert_eq!(back.backup_servers, cfg.client.unwrap().backup_servers);
        assert_eq!(back.socks5_listen.as_deref(), Some("127.0.0.1:1080"));
    }

    /// Saving and re-loading keeps every setting.
    #[test]
    fn save_then_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("pt-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        let cfg = Config {
            client: Some(ClientConfig {
                server: "1.2.3.4:8444".into(),
                server_public_key: KEY.into(),
                private_key: KEY.into(),
                public_key: KEY.into(),
                ..ClientConfig::default()
            }),
            ..Config::default()
        };
        cfg.save(&path).unwrap();
        let back = Config::load(&path).unwrap().client.unwrap();
        assert_eq!(back.server, "1.2.3.4:8444");
        assert_eq!(back.private_key, KEY);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "config holds a private key; must be owner-only");
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
