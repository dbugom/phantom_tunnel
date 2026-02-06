//! Tunnel layer - encrypted communication channel
//!
//! Provides:
//! - Frame encoding/decoding
//! - Stream multiplexing
//! - Flow control
//! - Padding injection

mod frame;
mod multiplexer;
mod stream;

pub use frame::{Frame, FrameType, FRAME_HEADER_SIZE};
pub use multiplexer::{Multiplexer, StreamCommand, StreamEvent, StreamHandle};
pub use stream::{StreamState, TunnelStream};

use thiserror::Error;

/// Tunnel layer errors
#[derive(Debug, Error)]
pub enum TunnelError {
    #[error("Frame too large: {0} > {1}")]
    FrameTooLarge(usize, usize),

    #[error("Invalid frame: {0}")]
    InvalidFrame(String),

    #[error("Stream not found: {0}")]
    StreamNotFound(u32),

    #[error("Stream closed")]
    StreamClosed,

    #[error("Flow control violation")]
    FlowControl,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Crypto error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
}

/// Maximum number of concurrent streams
pub const MAX_STREAMS: u32 = 1024;

/// Default window size for flow control (256 KB)
pub const DEFAULT_WINDOW_SIZE: u32 = 262144;
