//! Proxy implementations
//!
//! Provides:
//! - SOCKS5 proxy server
//! - HTTP CONNECT proxy server

#[cfg(feature = "socks5")]
mod socks5;

#[cfg(feature = "http-proxy")]
mod http;

#[cfg(feature = "socks5")]
pub use socks5::Socks5Server;

use thiserror::Error;

/// Proxy errors
#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid SOCKS version: {0}")]
    InvalidSocksVersion(u8),

    #[error("Unsupported command: {0}")]
    UnsupportedCommand(u8),

    #[error("Address type not supported: {0}")]
    UnsupportedAddressType(u8),

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Connection refused")]
    ConnectionRefused,

    #[error("Host unreachable")]
    HostUnreachable,

    #[error("Network unreachable")]
    NetworkUnreachable,

    #[error("TTL expired")]
    TtlExpired,

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("General failure: {0}")]
    GeneralFailure(String),
}

/// Proxy target address
#[derive(Debug, Clone)]
pub enum Address {
    /// IPv4 address and port
    Ipv4([u8; 4], u16),
    /// IPv6 address and port
    Ipv6([u8; 16], u16),
    /// Domain name and port
    Domain(String, u16),
}

impl Address {
    /// Get the port
    pub fn port(&self) -> u16 {
        match self {
            Address::Ipv4(_, port) => *port,
            Address::Ipv6(_, port) => *port,
            Address::Domain(_, port) => *port,
        }
    }

    /// Convert to string representation
    pub fn to_string(&self) -> String {
        match self {
            Address::Ipv4(ip, port) => {
                format!("{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], port)
            }
            Address::Ipv6(ip, port) => {
                let addr = std::net::Ipv6Addr::from(*ip);
                format!("[{}]:{}", addr, port)
            }
            Address::Domain(domain, port) => {
                format!("{}:{}", domain, port)
            }
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}
