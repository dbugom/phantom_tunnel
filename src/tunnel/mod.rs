//! Tunnel layer: what travels inside the Noise-encrypted connection.
//!
//! - [`Frame`] / [`FrameType`]: the frame format (one frame per Noise message)
//! - [`StreamFlow`]: per-stream credit-based send window (flow control)
//! - [`udp`]: the address header carried by `UdpData` frames
//!
//! The constants below are the protocol parameters both `phantom-server` and
//! `phantom-client` must agree on.

mod flow;
mod frame;
pub mod udp;

pub use flow::StreamFlow;
pub use frame::{Frame, FrameType, FRAME_HEADER_SIZE};

use thiserror::Error;

/// Tunnel layer errors
#[derive(Debug, Error)]
pub enum TunnelError {
    #[error("Invalid frame: {0}")]
    InvalidFrame(String),
}

/// Protocol version exchanged in the Noise handshake payload. v2 adds flow
/// control and UDP; a peer that sends no version byte is treated as v1.
pub const PROTOCOL_VERSION: u8 = 2;

/// Maximum number of concurrently open streams per tunnel connection.
pub const MAX_STREAMS: usize = 1024;

/// Initial per-stream send window, in bytes (256 KB). Both ends assume the
/// peer starts with this much credit.
pub const DEFAULT_WINDOW_SIZE: u32 = 262_144;

/// A receiver sends a `WindowUpdate` once this many bytes have been drained
/// since the last one (half the window).
pub const WINDOW_UPDATE_THRESHOLD: u32 = DEFAULT_WINDOW_SIZE / 2;
