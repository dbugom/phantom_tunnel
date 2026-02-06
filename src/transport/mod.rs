//! Transport layer implementations
//!
//! Provides pluggable transport backends:
//! - TCP (raw, for testing)
//! - TLS 1.3 with fingerprint mimicry
//! - QUIC (optional)
//! - DNS tunneling (fallback for heavily censored networks)

mod connection;
mod tcp;

#[cfg(feature = "tls")]
mod tls;

#[cfg(feature = "dns-tunnel")]
mod dns;

pub use connection::{ConnectionState, TunnelConnection};
pub use tcp::TcpTransport;

#[cfg(feature = "tls")]
pub use tls::TlsTransport;

#[cfg(feature = "dns-tunnel")]
pub use dns::{DnsTransport, DnsTunnelConfig, DnsTunnelServer, DnsQueryType};

use async_trait::async_trait;
use std::io;
use thiserror::Error;

/// Transport layer errors
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("Connection closed")]
    Closed,

    #[error("Timeout")]
    Timeout,
}

/// Trait for transport implementations
#[async_trait]
pub trait Transport: Send + Sync {
    /// Connect to a remote endpoint
    async fn connect(&mut self, addr: &str) -> Result<(), TransportError>;

    /// Send data
    async fn send(&mut self, data: &[u8]) -> Result<(), TransportError>;

    /// Receive data
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TransportError>;

    /// Close the connection
    async fn close(&mut self) -> Result<(), TransportError>;

    /// Check if connected
    fn is_connected(&self) -> bool;
}

/// Transport configuration
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Connection timeout in seconds
    pub connect_timeout: u64,
    /// Read timeout in seconds
    pub read_timeout: u64,
    /// Write timeout in seconds
    pub write_timeout: u64,
    /// Enable TCP keepalive
    pub keepalive: bool,
    /// TCP keepalive interval in seconds
    pub keepalive_interval: u64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            connect_timeout: 30,
            read_timeout: 60,
            write_timeout: 60,
            keepalive: true,
            keepalive_interval: 30,
        }
    }
}
