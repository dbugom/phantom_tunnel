//! Protocol definitions and constants

use thiserror::Error;

/// Protocol errors
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("Invalid magic bytes")]
    InvalidMagic,

    #[error("Version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: u8, actual: u8 },

    #[error("Invalid message type: {0}")]
    InvalidMessageType(u8),

    #[error("Message too large: {0} bytes")]
    MessageTooLarge(usize),

    #[error("Unexpected message: {0}")]
    UnexpectedMessage(String),

    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),
}

/// Protocol version
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum message size (64 KB)
pub const MAX_MESSAGE_SIZE: usize = 65535;

/// Handshake timeout in seconds
pub const HANDSHAKE_TIMEOUT: u64 = 30;

/// Idle timeout in seconds
pub const IDLE_TIMEOUT: u64 = 300;

/// Keepalive interval in seconds
pub const KEEPALIVE_INTERVAL: u64 = 30;
