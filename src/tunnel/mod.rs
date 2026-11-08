//! Tunnel layer: what travels inside the Noise-encrypted connection.
//!
//! - [`Frame`] / [`FrameType`]: the frame format (one frame per Noise message)
//! - [`StreamFlow`] / [`RecvWindow`]: per-stream credit-based flow control,
//!   with receive windows that grow when the reader keeps up
//! - [`InboundTx`] / [`InboundRx`]: event loop → local socket channel
//! - [`udp`]: the address header carried by `UdpData` frames
//!
//! The constants below are the protocol parameters both `phantom-server` and
//! `phantom-client` must agree on.

mod flow;
mod frame;
mod inbound;
pub mod udp;

pub use flow::{RecvWindow, StreamFlow, WindowViolation};
pub use inbound::{InboundClosed, InboundRx, InboundTx};
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

/// Largest per-stream receive window the client grants (16 MiB). At a 120 ms
/// round trip that allows roughly 1 Gbit/s on a single connection.
pub const MAX_WINDOW_SIZE: u32 = 16 * 1024 * 1024;
