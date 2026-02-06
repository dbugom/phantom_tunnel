//! Multiplexed stream implementation

use super::{Frame, FrameType, TunnelError, DEFAULT_WINDOW_SIZE};
use bytes::{Bytes, BytesMut};
use std::collections::VecDeque;
use tokio::sync::mpsc;

/// Stream state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Stream is open and active
    Open,
    /// Local side has closed
    HalfClosedLocal,
    /// Remote side has closed
    HalfClosedRemote,
    /// Stream is fully closed
    Closed,
}

/// A multiplexed stream within the tunnel
pub struct TunnelStream {
    /// Stream ID
    id: u32,
    /// Current state
    state: StreamState,
    /// Send window (flow control)
    send_window: u32,
    /// Receive window (flow control)
    recv_window: u32,
    /// Incoming data buffer
    recv_buffer: VecDeque<Bytes>,
    /// Destination address (for stream open)
    destination: Option<String>,
}

impl TunnelStream {
    /// Create a new stream
    pub fn new(id: u32) -> Self {
        Self {
            id,
            state: StreamState::Open,
            send_window: DEFAULT_WINDOW_SIZE,
            recv_window: DEFAULT_WINDOW_SIZE,
            recv_buffer: VecDeque::new(),
            destination: None,
        }
    }

    /// Create a new stream with destination
    pub fn with_destination(id: u32, destination: String) -> Self {
        let mut stream = Self::new(id);
        stream.destination = Some(destination);
        stream
    }

    /// Get stream ID
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Get current state
    pub fn state(&self) -> StreamState {
        self.state
    }

    /// Get destination address
    pub fn destination(&self) -> Option<&str> {
        self.destination.as_deref()
    }

    /// Check if stream can send data
    pub fn can_send(&self) -> bool {
        matches!(self.state, StreamState::Open | StreamState::HalfClosedRemote)
            && self.send_window > 0
    }

    /// Check if stream can receive data
    pub fn can_recv(&self) -> bool {
        matches!(self.state, StreamState::Open | StreamState::HalfClosedLocal)
    }

    /// Update send window
    pub fn update_send_window(&mut self, increment: u32) {
        self.send_window = self.send_window.saturating_add(increment);
    }

    /// Consume send window
    pub fn consume_send_window(&mut self, amount: u32) -> Result<(), TunnelError> {
        if amount > self.send_window {
            return Err(TunnelError::FlowControl);
        }
        self.send_window -= amount;
        Ok(())
    }

    /// Add data to receive buffer
    pub fn push_data(&mut self, data: Bytes) -> Result<(), TunnelError> {
        if !self.can_recv() {
            return Err(TunnelError::StreamClosed);
        }

        let data_len = data.len() as u32;
        if data_len > self.recv_window {
            return Err(TunnelError::FlowControl);
        }

        self.recv_window -= data_len;
        self.recv_buffer.push_back(data);
        Ok(())
    }

    /// Read data from receive buffer
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let mut total = 0;

        while total < buf.len() {
            if let Some(data) = self.recv_buffer.front_mut() {
                let to_copy = std::cmp::min(data.len(), buf.len() - total);
                buf[total..total + to_copy].copy_from_slice(&data[..to_copy]);
                total += to_copy;

                if to_copy == data.len() {
                    self.recv_buffer.pop_front();
                } else {
                    *data = data.slice(to_copy..);
                }
            } else {
                break;
            }
        }

        total
    }

    /// Check if there's data available to read
    pub fn has_data(&self) -> bool {
        !self.recv_buffer.is_empty()
    }

    /// Get window update amount (if needed)
    pub fn window_update_needed(&self) -> Option<u32> {
        let threshold = DEFAULT_WINDOW_SIZE / 2;
        if self.recv_window < threshold {
            Some(DEFAULT_WINDOW_SIZE - self.recv_window)
        } else {
            None
        }
    }

    /// Apply window update
    pub fn apply_window_update(&mut self, increment: u32) {
        self.recv_window = self.recv_window.saturating_add(increment);
    }

    /// Close local side
    pub fn close_local(&mut self) {
        self.state = match self.state {
            StreamState::Open => StreamState::HalfClosedLocal,
            StreamState::HalfClosedRemote => StreamState::Closed,
            _ => self.state,
        };
    }

    /// Close remote side
    pub fn close_remote(&mut self) {
        self.state = match self.state {
            StreamState::Open => StreamState::HalfClosedRemote,
            StreamState::HalfClosedLocal => StreamState::Closed,
            _ => self.state,
        };
    }

    /// Check if stream is fully closed
    pub fn is_closed(&self) -> bool {
        self.state == StreamState::Closed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_flow_control() {
        let mut stream = TunnelStream::new(1);

        // Push some data
        stream.push_data(Bytes::from_static(b"Hello")).unwrap();
        assert!(stream.has_data());

        // Read it back
        let mut buf = [0u8; 10];
        let n = stream.read(&mut buf);
        assert_eq!(n, 5);
        assert_eq!(&buf[..n], b"Hello");
    }

    #[test]
    fn test_stream_states() {
        let mut stream = TunnelStream::new(1);
        assert_eq!(stream.state(), StreamState::Open);

        stream.close_local();
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);
        assert!(!stream.can_send());
        assert!(stream.can_recv());

        stream.close_remote();
        assert_eq!(stream.state(), StreamState::Closed);
        assert!(stream.is_closed());
    }
}
