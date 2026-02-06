//! # Phantom Tunnel
//!
//! A secure, censorship-resistant tunneling protocol designed for privacy
//! in highly restricted network environments.
//!
//! ## Features
//!
//! - **End-to-end encryption** using Noise Protocol (IK pattern)
//! - **TLS fingerprint mimicry** to evade deep packet inspection
//! - **Traffic obfuscation** with padding and timing randomization
//! - **Multiple transports**: TLS, QUIC, DNS tunneling
//! - **SOCKS5 and HTTP CONNECT** proxy support
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │                  Application Layer                   │
//! │         (File Transfer, HTTP Proxy, SOCKS5)         │
//! ├─────────────────────────────────────────────────────┤
//! │                  Multiplexing Layer                  │
//! │            (Multiple streams, flow control)          │
//! ├─────────────────────────────────────────────────────┤
//! │                   Tunnel Layer                       │
//! │        (Encryption, authentication, framing)         │
//! ├─────────────────────────────────────────────────────┤
//! │                 Obfuscation Layer                    │
//! │    (TLS mimicry, DNS tunneling, traffic shaping)    │
//! ├─────────────────────────────────────────────────────┤
//! │                  Transport Layer                     │
//! │              (TCP, UDP, QUIC, WebSocket)             │
//! └─────────────────────────────────────────────────────┘
//! ```

pub mod config;
pub mod crypto;
pub mod obfuscation;
pub mod protocol;
pub mod proxy;
pub mod transport;
pub mod tunnel;

pub use config::Config;

/// Protocol version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Protocol magic bytes for identification (internal use only)
pub(crate) const MAGIC: [u8; 4] = [0x50, 0x48, 0x54, 0x4E]; // "PHTN"

/// Maximum frame size (64 KB)
pub const MAX_FRAME_SIZE: usize = 65535;

/// Default port for phantom tunnel
pub const DEFAULT_PORT: u16 = 443;

/// Result type alias
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Crypto error: {0}")]
    Crypto(#[from] crypto::CryptoError),

    #[error("Protocol error: {0}")]
    Protocol(#[from] protocol::ProtocolError),

    #[error("Transport error: {0}")]
    Transport(#[from] transport::TransportError),

    #[error("Tunnel error: {0}")]
    Tunnel(#[from] tunnel::TunnelError),

    #[error("Proxy error: {0}")]
    Proxy(#[from] proxy::ProxyError),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Timeout")]
    Timeout,

    #[error("Authentication failed")]
    AuthenticationFailed,
}
