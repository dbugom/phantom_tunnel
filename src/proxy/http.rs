//! HTTP CONNECT proxy implementation

use super::{Address, ProxyError};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

/// HTTP CONNECT proxy server
pub struct HttpProxyServer {
    listener: TcpListener,
    /// Optional basic authentication (username:password)
    auth: Option<(String, String)>,
}

impl HttpProxyServer {
    /// Create a new HTTP proxy server
    pub async fn bind(addr: &str) -> Result<Self, ProxyError> {
        let listener = TcpListener::bind(addr).await?;
        info!("HTTP proxy server listening on {}", addr);

        Ok(Self {
            listener,
            auth: None,
        })
    }

    /// Enable basic authentication
    pub fn with_auth(mut self, username: String, password: String) -> Self {
        self.auth = Some((username, password));
        self
    }

    /// Accept and handle incoming connections
    pub async fn run<F, Fut>(&self, handler: F) -> Result<(), ProxyError>
    where
        F: Fn(TcpStream, Address) -> Fut + Clone + Send + 'static,
        Fut: std::future::Future<Output = Result<(), ProxyError>> + Send,
    {
        loop {
            let (stream, peer_addr) = self.listener.accept().await?;
            debug!("New HTTP proxy connection from {}", peer_addr);

            let handler = handler.clone();
            let auth = self.auth.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(stream, auth, handler).await {
                    error!("HTTP proxy connection error: {}", e);
                }
            });
        }
    }

    async fn handle_connection<F, Fut>(
        stream: TcpStream,
        auth: Option<(String, String)>,
        handler: F,
    ) -> Result<(), ProxyError>
    where
        F: Fn(TcpStream, Address) -> Fut,
        Fut: std::future::Future<Output = Result<(), ProxyError>>,
    {
        let mut reader = BufReader::new(stream);

        // Read the request line
        let mut request_line = String::new();
        reader.read_line(&mut request_line).await?;

        let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
        if parts.len() < 3 {
            return Err(ProxyError::GeneralFailure("Invalid request line".to_string()));
        }

        let method = parts[0];
        let target = parts[1];
        let _version = parts[2];

        // Read headers
        let mut headers = std::collections::HashMap::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            let line = line.trim();

            if line.is_empty() {
                break;
            }

            if let Some((key, value)) = line.split_once(':') {
                headers.insert(key.trim().to_lowercase(), value.trim().to_string());
            }
        }

        // Check authentication if required
        if let Some((expected_user, expected_pass)) = &auth {
            let auth_header = headers.get("proxy-authorization");

            let authenticated = if let Some(auth_value) = auth_header {
                if let Some(encoded) = auth_value.strip_prefix("Basic ") {
                    if let Ok(decoded) = base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        encoded,
                    ) {
                        if let Ok(credentials) = String::from_utf8(decoded) {
                            if let Some((user, pass)) = credentials.split_once(':') {
                                user == expected_user && pass == expected_pass
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            };

            if !authenticated {
                let mut stream = reader.into_inner();
                stream.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n").await?;
                stream.write_all(b"Proxy-Authenticate: Basic realm=\"Phantom Tunnel\"\r\n").await?;
                stream.write_all(b"\r\n").await?;
                return Err(ProxyError::AuthenticationFailed);
            }
        }

        // Only support CONNECT method
        if method != "CONNECT" {
            let mut stream = reader.into_inner();
            stream.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n").await?;
            return Err(ProxyError::GeneralFailure(format!(
                "Unsupported method: {}",
                method
            )));
        }

        // Parse target address
        let address = Self::parse_target(target)?;

        debug!("HTTP CONNECT to {}", address);

        // Send success response
        let mut stream = reader.into_inner();
        stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

        // Hand off to handler
        handler(stream, address).await
    }

    fn parse_target(target: &str) -> Result<Address, ProxyError> {
        // Target format: host:port
        let (host, port_str) = target
            .rsplit_once(':')
            .ok_or_else(|| ProxyError::InvalidAddress(target.to_string()))?;

        let port: u16 = port_str
            .parse()
            .map_err(|_| ProxyError::InvalidAddress(target.to_string()))?;

        // Check if it's an IP address or domain
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            Ok(Address::Ipv4(ip.octets(), port))
        } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
            Ok(Address::Ipv6(ip.octets(), port))
        } else {
            Ok(Address::Domain(host.to_string(), port))
        }
    }
}
