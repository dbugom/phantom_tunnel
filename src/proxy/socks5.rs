//! SOCKS5 proxy implementation (RFC 1928)

use super::{Address, ProxyError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

/// SOCKS5 version
const SOCKS_VERSION: u8 = 0x05;

/// Authentication methods
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthMethod {
    NoAuth = 0x00,
    Gssapi = 0x01,
    UsernamePassword = 0x02,
    NoAcceptable = 0xFF,
}

/// SOCKS5 commands
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

impl TryFrom<u8> for Command {
    type Error = ProxyError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Command::Connect),
            0x02 => Ok(Command::Bind),
            0x03 => Ok(Command::UdpAssociate),
            _ => Err(ProxyError::UnsupportedCommand(value)),
        }
    }
}

/// Address types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressType {
    Ipv4 = 0x01,
    Domain = 0x03,
    Ipv6 = 0x04,
}

impl TryFrom<u8> for AddressType {
    type Error = ProxyError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(AddressType::Ipv4),
            0x03 => Ok(AddressType::Domain),
            0x04 => Ok(AddressType::Ipv6),
            _ => Err(ProxyError::UnsupportedAddressType(value)),
        }
    }
}

/// Reply codes
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum Reply {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

/// SOCKS5 proxy server
pub struct Socks5Server {
    listener: TcpListener,
    /// Optional username/password authentication
    auth: Option<(String, String)>,
}

impl Socks5Server {
    /// Create a new SOCKS5 server
    pub async fn bind(addr: &str) -> Result<Self, ProxyError> {
        let listener = TcpListener::bind(addr).await?;
        info!("SOCKS5 server listening on {}", addr);

        Ok(Self {
            listener,
            auth: None,
        })
    }

    /// Enable username/password authentication
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
            debug!("New SOCKS5 connection from {}", peer_addr);

            let handler = handler.clone();
            let auth = self.auth.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(stream, auth, handler).await {
                    error!("SOCKS5 connection error: {}", e);
                }
            });
        }
    }

    async fn handle_connection<F, Fut>(
        mut stream: TcpStream,
        auth: Option<(String, String)>,
        handler: F,
    ) -> Result<(), ProxyError>
    where
        F: Fn(TcpStream, Address) -> Fut,
        Fut: std::future::Future<Output = Result<(), ProxyError>>,
    {
        // Read greeting
        let mut buf = [0u8; 258];
        stream.read_exact(&mut buf[..2]).await?;

        if buf[0] != SOCKS_VERSION {
            return Err(ProxyError::InvalidSocksVersion(buf[0]));
        }

        let nmethods = buf[1] as usize;
        stream.read_exact(&mut buf[..nmethods]).await?;

        // Select authentication method
        let method = if auth.is_some() {
            if buf[..nmethods].contains(&(AuthMethod::UsernamePassword as u8)) {
                AuthMethod::UsernamePassword
            } else {
                AuthMethod::NoAcceptable
            }
        } else if buf[..nmethods].contains(&(AuthMethod::NoAuth as u8)) {
            AuthMethod::NoAuth
        } else {
            AuthMethod::NoAcceptable
        };

        // Send method selection
        stream.write_all(&[SOCKS_VERSION, method as u8]).await?;

        if method == AuthMethod::NoAcceptable {
            return Err(ProxyError::AuthenticationFailed);
        }

        // Handle authentication if required
        if method == AuthMethod::UsernamePassword {
            if let Some((expected_user, expected_pass)) = &auth {
                // Read username/password
                stream.read_exact(&mut buf[..1]).await?; // Version
                stream.read_exact(&mut buf[..1]).await?;
                let ulen = buf[0] as usize;
                stream.read_exact(&mut buf[..ulen]).await?;
                let username = String::from_utf8_lossy(&buf[..ulen]).to_string();

                stream.read_exact(&mut buf[..1]).await?;
                let plen = buf[0] as usize;
                stream.read_exact(&mut buf[..plen]).await?;
                let password = String::from_utf8_lossy(&buf[..plen]).to_string();

                let success = username == *expected_user && password == *expected_pass;
                stream.write_all(&[0x01, if success { 0x00 } else { 0x01 }]).await?;

                if !success {
                    return Err(ProxyError::AuthenticationFailed);
                }
            }
        }

        // Read request
        stream.read_exact(&mut buf[..4]).await?;

        if buf[0] != SOCKS_VERSION {
            return Err(ProxyError::InvalidSocksVersion(buf[0]));
        }

        let command = Command::try_from(buf[1])?;
        // buf[2] is reserved
        let addr_type = AddressType::try_from(buf[3])?;

        // Read address
        let address = match addr_type {
            AddressType::Ipv4 => {
                let mut ip = [0u8; 4];
                stream.read_exact(&mut ip).await?;
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);
                Address::Ipv4(ip, port)
            }
            AddressType::Domain => {
                stream.read_exact(&mut buf[..1]).await?;
                let len = buf[0] as usize;
                stream.read_exact(&mut buf[..len]).await?;
                let domain = String::from_utf8_lossy(&buf[..len]).to_string();
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);
                Address::Domain(domain, port)
            }
            AddressType::Ipv6 => {
                let mut ip = [0u8; 16];
                stream.read_exact(&mut ip).await?;
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);
                Address::Ipv6(ip, port)
            }
        };

        debug!("SOCKS5 {} to {}", format!("{:?}", command), address);

        match command {
            Command::Connect => {
                // Send success reply (we'll establish connection via tunnel)
                let reply = Self::make_reply(Reply::Succeeded, &address);
                stream.write_all(&reply).await?;

                // Hand off to handler
                handler(stream, address).await
            }
            Command::Bind | Command::UdpAssociate => {
                let reply = Self::make_reply(Reply::CommandNotSupported, &address);
                stream.write_all(&reply).await?;
                Err(ProxyError::UnsupportedCommand(command as u8))
            }
        }
    }

    fn make_reply(reply: Reply, addr: &Address) -> Vec<u8> {
        let mut buf = vec![SOCKS_VERSION, reply as u8, 0x00];

        match addr {
            Address::Ipv4(ip, port) => {
                buf.push(AddressType::Ipv4 as u8);
                buf.extend_from_slice(ip);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Address::Ipv6(ip, port) => {
                buf.push(AddressType::Ipv6 as u8);
                buf.extend_from_slice(ip);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Address::Domain(domain, port) => {
                buf.push(AddressType::Domain as u8);
                buf.push(domain.len() as u8);
                buf.extend_from_slice(domain.as_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }

        buf
    }
}
