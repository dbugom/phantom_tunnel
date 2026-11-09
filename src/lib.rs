//! # Phantom Tunnel
//!
//! An encrypted, multiplexed TCP/UDP tunnel with a local SOCKS5 / HTTP CONNECT
//! proxy on the client side.
//!
//! ## What is in the library
//!
//! - [`crypto`]: Noise IK handshake (`Noise_IK_25519_ChaChaPoly_SHA256`) and the
//!   X25519 key types. Clients are authenticated by their static public key.
//! - [`tunnel`]: the frame format carried inside Noise transport messages,
//!   per-stream credit-based flow control ([`tunnel::StreamFlow`]), and the
//!   address header used by UDP datagrams.
//! - [`config`]: the TOML configuration shared by `phantom-server` and
//!   `phantom-client`, including the client's `backup_servers`.
//! - [`link`]: `phantom://` connect links (`phantom-server link`,
//!   `phantom-client --import`).
//!
//! The event loops themselves live in `src/bin/server.rs` and
//! `src/bin/client.rs`.
//!
//! ## Wire format
//!
//! ```text
//! TCP  ──  u16 length ║ Noise ciphertext ( Frame ║ 16-byte tag )
//! ```
//!
//! There is no TLS layer: the stream is length-prefixed Noise ciphertext over
//! plain TCP. See `docs/PROTOCOL_SPEC.md`.

pub mod config;
pub mod crypto;
pub mod link;
pub mod transport;
pub mod tunnel;

pub use config::Config;

/// Crate version, as printed by `--version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Result type alias
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Crypto error: {0}")]
    Crypto(#[from] crypto::CryptoError),

    #[error("Tunnel error: {0}")]
    Tunnel(#[from] tunnel::TunnelError),

    #[error("Configuration error: {0}")]
    Config(String),
}
