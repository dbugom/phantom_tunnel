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
// BdpEstimator is used directly via phantom_tunnel::tunnel::BdpEstimator

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

/// Default window size for flow control (4 MB)
/// Larger window allows higher throughput over high-RTT links:
/// 4MB / 100ms RTT = 40 MB/s ≈ 320 Mbps theoretical max
pub const DEFAULT_WINDOW_SIZE: u32 = 4_194_304;

/// Keepalive interval — send Ping every 20 seconds to detect dead connections
pub const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(20);

/// Maximum missed Pong responses before declaring the tunnel dead
pub const MAX_MISSED_PONGS: u32 = 2;

/// Relay read buffer size — 128KB for amortizing syscall overhead
pub const RELAY_BUFFER_SIZE: usize = 128 * 1024;

/// Maximum frame payload that fits within a single Noise Protocol message.
/// Noise spec limits messages to 65535 bytes (ciphertext). After subtracting
/// 16 bytes AEAD tag and 6 bytes frame header, the max payload is 65513.
/// Data larger than this MUST be split into multiple frames before encryption.
pub const MAX_FRAME_PAYLOAD: usize = 65535 - 16 - FRAME_HEADER_SIZE;

/// TLS BufWriter capacity — 64KB for write coalescing
pub const TLS_BUFWRITER_CAPACITY: usize = 64 * 1024;

/// Maximum window size for BDP auto-tuning (16MB)
pub const MAX_WINDOW_SIZE: u32 = 16 * 1024 * 1024;

/// Initial window size for new streams with BDP auto-tuning (1MB — grows via measurement)
pub const INITIAL_WINDOW_SIZE: u32 = 1 * 1024 * 1024;

/// BDP estimator for dynamic flow control window sizing.
///
/// Measures bytes-in-flight during one RTT (between Ping and Pong) to estimate
/// the bandwidth-delay product. If the observed BDP exceeds 2/3 of the current
/// window, the window is doubled (up to MAX_WINDOW_SIZE).
pub struct BdpEstimator {
    /// Bytes received since the measurement PING was sent
    bytes_since_ping: u64,
    /// Whether a BDP measurement is in-flight
    ping_in_flight: bool,
    /// Timestamp when measurement PING was sent
    ping_sent_at: Option<std::time::Instant>,
    /// Current auto-tuned window size
    pub current_window: u32,
}

impl BdpEstimator {
    /// Create a new BDP estimator with the default initial window
    pub fn new() -> Self {
        Self {
            bytes_since_ping: 0,
            ping_in_flight: false,
            ping_sent_at: None,
            current_window: DEFAULT_WINDOW_SIZE,
        }
    }

    /// Called when DATA is received. If no measurement is in progress, signals
    /// that a PING should be sent to start one.
    ///
    /// Returns `true` if the caller should send a PING frame to start a measurement.
    pub fn on_data_received(&mut self, bytes: u32) -> bool {
        if self.ping_in_flight {
            self.bytes_since_ping += bytes as u64;
            false
        } else {
            // Start a new BDP measurement
            self.bytes_since_ping = bytes as u64;
            self.ping_in_flight = true;
            self.ping_sent_at = Some(std::time::Instant::now());
            true // Caller should send PING
        }
    }

    /// Called when PONG is received. Computes BDP and possibly grows the window.
    pub fn on_pong_received(&mut self) {
        if !self.ping_in_flight {
            return;
        }
        self.ping_in_flight = false;

        let rtt = self
            .ping_sent_at
            .take()
            .map(|t| t.elapsed())
            .unwrap_or_default();

        // BDP = bytes observed during one RTT
        let estimated_bdp = self.bytes_since_ping;

        // If observed BDP > 2/3 of current window, double the window
        let threshold = (self.current_window as f64 * 0.67) as u64;
        if estimated_bdp > threshold && self.current_window < MAX_WINDOW_SIZE {
            let new_window = std::cmp::min(
                self.current_window.saturating_mul(2),
                MAX_WINDOW_SIZE,
            );
            tracing::debug!(
                "BDP auto-tune: observed={} threshold={} window: {}KB -> {}KB",
                estimated_bdp,
                threshold,
                self.current_window / 1024,
                new_window / 1024,
            );
            self.current_window = new_window;
        }

        if rtt.as_secs_f64() > 0.0 {
            tracing::debug!(
                "BDP measurement: {} bytes in {:?} (est. {:.1} Mbps), window={}KB",
                self.bytes_since_ping,
                rtt,
                (self.bytes_since_ping as f64 * 8.0) / rtt.as_secs_f64() / 1_000_000.0,
                self.current_window / 1024,
            );
        }
    }
}
