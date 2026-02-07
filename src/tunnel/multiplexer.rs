//! Stream multiplexer for the tunnel
//!
//! Manages multiple logical streams over a single encrypted connection.
//! Based on the protocol specification in docs/PROTOCOL_SPEC.md

use super::{Frame, FrameType, TunnelError, TunnelStream, DEFAULT_WINDOW_SIZE, MAX_STREAMS};
use crate::crypto::NoiseTransport;
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use tokio::sync::mpsc;

/// Stream event sent from multiplexer to stream handlers
#[derive(Debug)]
pub enum StreamEvent {
    /// Data received for stream
    Data(Bytes),
    /// Stream closed by remote
    Close,
    /// Window update
    WindowUpdate(u32),
    /// Error on stream
    Error(TunnelError),
}

/// Command sent from stream handlers to multiplexer
#[derive(Debug)]
pub enum StreamCommand {
    /// Send data on stream
    Send { stream_id: u32, data: Bytes },
    /// Close stream
    Close { stream_id: u32 },
    /// Open new stream to destination
    Open { stream_id: u32, destination: String },
    /// Send window update
    WindowUpdate { stream_id: u32, increment: u32 },
}

/// Stream handle for application use
pub struct StreamHandle {
    stream_id: u32,
    destination: Option<String>,
    cmd_tx: mpsc::Sender<StreamCommand>,
    event_rx: mpsc::Receiver<StreamEvent>,
}

impl StreamHandle {
    /// Get stream ID
    pub fn id(&self) -> u32 {
        self.stream_id
    }

    /// Get destination address (if this is an incoming stream)
    pub fn destination(&self) -> Option<&str> {
        self.destination.as_deref()
    }

    /// Send data on this stream
    pub async fn send(&self, data: Bytes) -> Result<(), TunnelError> {
        self.cmd_tx
            .send(StreamCommand::Send {
                stream_id: self.stream_id,
                data,
            })
            .await
            .map_err(|_| TunnelError::StreamClosed)
    }

    /// Receive data or event
    pub async fn recv(&mut self) -> Option<StreamEvent> {
        self.event_rx.recv().await
    }

    /// Close this stream
    pub async fn close(&self) -> Result<(), TunnelError> {
        self.cmd_tx
            .send(StreamCommand::Close {
                stream_id: self.stream_id,
            })
            .await
            .map_err(|_| TunnelError::StreamClosed)
    }
}

/// Multiplexer state for a single stream
struct StreamState {
    stream: TunnelStream,
    event_tx: mpsc::Sender<StreamEvent>,
}

/// Stream multiplexer
pub struct Multiplexer {
    /// Active streams
    streams: HashMap<u32, StreamState>,
    /// Next stream ID (odd for client, even for server)
    next_stream_id: u32,
    /// Whether this is the client side (odd stream IDs)
    is_client: bool,
    /// Command receiver from stream handles
    cmd_rx: mpsc::Receiver<StreamCommand>,
    /// Command sender (cloned for new stream handles)
    cmd_tx: mpsc::Sender<StreamCommand>,
    /// Pending frames to send
    send_queue: Vec<Frame>,
}

impl Multiplexer {
    /// Create a new client-side multiplexer
    pub fn new_client() -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        Self {
            streams: HashMap::new(),
            next_stream_id: 1, // Odd for client
            is_client: true,
            cmd_rx,
            cmd_tx,
            send_queue: Vec::new(),
        }
    }

    /// Create a new server-side multiplexer
    pub fn new_server() -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        Self {
            streams: HashMap::new(),
            next_stream_id: 2, // Even for server
            is_client: false,
            cmd_rx,
            cmd_tx,
            send_queue: Vec::new(),
        }
    }

    /// Open a new stream to a destination
    pub fn open_stream(&mut self, destination: String) -> Result<StreamHandle, TunnelError> {
        if self.streams.len() >= MAX_STREAMS as usize {
            return Err(TunnelError::StreamNotFound(0)); // TODO: Better error
        }

        let stream_id = self.next_stream_id;
        self.next_stream_id += 2; // Keep odd/even pattern

        let (event_tx, event_rx) = mpsc::channel(64);
        let stream = TunnelStream::with_destination(stream_id, destination.clone());

        self.streams.insert(
            stream_id,
            StreamState {
                stream,
                event_tx,
            },
        );

        // Queue STREAM_OPEN frame
        let frame = Frame::stream_open(stream_id, destination.as_bytes());
        self.send_queue.push(frame);

        Ok(StreamHandle {
            stream_id,
            destination: Some(destination),
            cmd_tx: self.cmd_tx.clone(),
            event_rx,
        })
    }

    /// Handle an incoming frame
    pub async fn handle_frame(&mut self, frame: Frame) -> Result<Option<StreamHandle>, TunnelError> {
        match frame.frame_type {
            FrameType::Data => {
                self.handle_data(frame.stream_id, frame.payload).await?;
                Ok(None)
            }
            FrameType::StreamOpen => {
                let handle = self.handle_stream_open(frame.stream_id, frame.payload)?;
                Ok(Some(handle))
            }
            FrameType::StreamClose => {
                self.handle_stream_close(frame.stream_id).await?;
                Ok(None)
            }
            FrameType::WindowUpdate => {
                self.handle_window_update(frame.stream_id, &frame.payload)?;
                Ok(None)
            }
            FrameType::Ping => {
                self.handle_ping(&frame.payload);
                Ok(None)
            }
            FrameType::Pong => {
                // Handle keepalive response
                Ok(None)
            }
            FrameType::GoAway => {
                // Connection closing
                Err(TunnelError::StreamClosed)
            }
            FrameType::Padding => {
                // Ignore padding frames
                Ok(None)
            }
        }
    }

    /// Handle incoming data frame
    async fn handle_data(&mut self, stream_id: u32, data: Bytes) -> Result<(), TunnelError> {
        let state = self
            .streams
            .get_mut(&stream_id)
            .ok_or(TunnelError::StreamNotFound(stream_id))?;

        // Track received bytes for flow control (without buffering — data goes directly via channel)
        let data_len = data.len() as u32;
        if !state.stream.can_recv() {
            return Err(TunnelError::StreamClosed);
        }
        if data_len > state.stream.recv_window() {
            return Err(TunnelError::FlowControl);
        }
        state.stream.consume_recv_window(data_len);

        // Send data directly to stream handler via channel (no clone, no buffering)
        let _ = state.event_tx.send(StreamEvent::Data(data)).await;

        // Check if window update needed
        if let Some(increment) = state.stream.window_update_needed() {
            state.stream.apply_window_update(increment);
            self.send_queue
                .push(Frame::window_update(stream_id, increment));
        }

        Ok(())
    }

    /// Handle stream open request (server side)
    fn handle_stream_open(
        &mut self,
        stream_id: u32,
        payload: Bytes,
    ) -> Result<StreamHandle, TunnelError> {
        // Parse destination from payload
        let destination = self.parse_destination(&payload)?;

        let (event_tx, event_rx) = mpsc::channel(64);
        let stream = TunnelStream::with_destination(stream_id, destination.clone());

        self.streams.insert(
            stream_id,
            StreamState {
                stream,
                event_tx,
            },
        );

        Ok(StreamHandle {
            stream_id,
            destination: Some(destination),
            cmd_tx: self.cmd_tx.clone(),
            event_rx,
        })
    }

    /// Parse destination address from STREAM_OPEN payload
    /// Supports both SOCKS5 binary format and plain string format (e.g., "example.com:443")
    fn parse_destination(&self, payload: &[u8]) -> Result<String, TunnelError> {
        if payload.is_empty() {
            return Err(TunnelError::InvalidFrame("Empty destination".to_string()));
        }

        let addr_type = payload[0];
        match addr_type {
            0x01 => {
                // IPv4 binary format
                if payload.len() < 7 {
                    return Err(TunnelError::InvalidFrame("Invalid IPv4".to_string()));
                }
                let ip = format!(
                    "{}.{}.{}.{}",
                    payload[1], payload[2], payload[3], payload[4]
                );
                let port = u16::from_be_bytes([payload[5], payload[6]]);
                Ok(format!("{}:{}", ip, port))
            }
            0x03 => {
                // Domain binary format
                if payload.len() < 2 {
                    return Err(TunnelError::InvalidFrame("Invalid domain".to_string()));
                }
                let len = payload[1] as usize;
                if payload.len() < 2 + len + 2 {
                    return Err(TunnelError::InvalidFrame("Invalid domain".to_string()));
                }
                let domain = String::from_utf8_lossy(&payload[2..2 + len]).to_string();
                let port = u16::from_be_bytes([payload[2 + len], payload[2 + len + 1]]);
                Ok(format!("{}:{}", domain, port))
            }
            0x04 => {
                // IPv6 binary format
                if payload.len() < 19 {
                    return Err(TunnelError::InvalidFrame("Invalid IPv6".to_string()));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&payload[1..17]);
                let ip = std::net::Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([payload[17], payload[18]]);
                Ok(format!("[{}]:{}", ip, port))
            }
            _ => {
                // Plain string format (e.g., "example.com:443")
                // This is the format used by our client
                match std::str::from_utf8(payload) {
                    Ok(s) if s.contains(':') => Ok(s.to_string()),
                    Ok(s) => Err(TunnelError::InvalidFrame(format!(
                        "Invalid destination (no port): {}",
                        s
                    ))),
                    Err(_) => Err(TunnelError::InvalidFrame(format!(
                        "Unknown address type: {}",
                        addr_type
                    ))),
                }
            }
        }
    }

    /// Handle stream close from remote
    async fn handle_stream_close(&mut self, stream_id: u32) -> Result<(), TunnelError> {
        if let Some(state) = self.streams.get_mut(&stream_id) {
            state.stream.close_remote();
            let _ = state.event_tx.send(StreamEvent::Close).await;

            if state.stream.is_closed() {
                self.streams.remove(&stream_id);
            }
        }
        Ok(())
    }

    /// Close a stream locally (client-initiated close)
    /// Marks the local side as closed and queues a STREAM_CLOSE frame.
    /// If both sides are closed, removes the stream from the map.
    pub fn close_stream_local(&mut self, stream_id: u32) {
        if let Some(state) = self.streams.get_mut(&stream_id) {
            state.stream.close_local();
            self.send_queue.push(Frame::stream_close(stream_id));

            if state.stream.is_closed() {
                self.streams.remove(&stream_id);
            }
        }
    }

    /// Force-remove a stream from the multiplexer (for cleanup of zombie streams)
    pub fn remove_stream(&mut self, stream_id: u32) {
        self.streams.remove(&stream_id);
    }

    /// Handle window update
    fn handle_window_update(&mut self, stream_id: u32, payload: &[u8]) -> Result<(), TunnelError> {
        if payload.len() < 4 {
            return Err(TunnelError::InvalidFrame("Invalid window update".to_string()));
        }

        let increment = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);

        if let Some(state) = self.streams.get_mut(&stream_id) {
            state.stream.update_send_window(increment);
        }

        Ok(())
    }

    /// Handle ping
    fn handle_ping(&mut self, payload: &[u8]) {
        if payload.len() >= 8 {
            let data = u64::from_be_bytes([
                payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
                payload[7],
            ]);
            self.send_queue.push(Frame::pong(data));
        }
    }

    /// Process pending commands from stream handles
    pub async fn process_commands(&mut self) -> Result<(), TunnelError> {
        while let Ok(cmd) = self.cmd_rx.try_recv() {
            match cmd {
                StreamCommand::Send { stream_id, data } => {
                    // Check stream exists and has window
                    if let Some(state) = self.streams.get_mut(&stream_id) {
                        if state.stream.can_send() {
                            let len = data.len() as u32;
                            state.stream.consume_send_window(len)?;
                            self.send_queue.push(Frame::data(stream_id, data));
                        }
                    }
                }
                StreamCommand::Close { stream_id } => {
                    if let Some(state) = self.streams.get_mut(&stream_id) {
                        state.stream.close_local();
                        self.send_queue.push(Frame::stream_close(stream_id));

                        if state.stream.is_closed() {
                            self.streams.remove(&stream_id);
                        }
                    }
                }
                StreamCommand::Open {
                    stream_id,
                    destination,
                } => {
                    self.send_queue
                        .push(Frame::stream_open(stream_id, destination.as_bytes()));
                }
                StreamCommand::WindowUpdate {
                    stream_id,
                    increment,
                } => {
                    self.send_queue
                        .push(Frame::window_update(stream_id, increment));
                }
            }
        }
        Ok(())
    }

    /// Get frames ready to send
    pub fn take_send_queue(&mut self) -> Vec<Frame> {
        std::mem::take(&mut self.send_queue)
    }

    /// Check if there are frames to send
    pub fn has_pending_frames(&self) -> bool {
        !self.send_queue.is_empty()
    }

    /// Get number of active streams
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Send a ping frame
    pub fn send_ping(&mut self) {
        let mut buf = [0u8; 8];
        crate::crypto::random_bytes(&mut buf);
        let data = u64::from_le_bytes(buf);
        self.send_queue.push(Frame::ping(data));
    }

    /// Send a padding frame (for traffic shaping)
    pub fn send_padding(&mut self, len: usize) {
        self.send_queue.push(Frame::padding(len));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multiplexer_stream_ids() {
        let client = Multiplexer::new_client();
        assert_eq!(client.next_stream_id, 1); // Odd

        let server = Multiplexer::new_server();
        assert_eq!(server.next_stream_id, 2); // Even
    }

    #[test]
    fn test_open_stream() {
        let mut mux = Multiplexer::new_client();
        let handle = mux.open_stream("example.com:443".to_string()).unwrap();

        assert_eq!(handle.id(), 1);
        assert_eq!(mux.stream_count(), 1);
        assert!(mux.has_pending_frames()); // STREAM_OPEN should be queued
    }

    #[test]
    fn test_parse_domain_destination() {
        let mux = Multiplexer::new_server();

        // Domain format: [0x03][len][domain][port_be]
        let mut payload = vec![0x03, 11];
        payload.extend_from_slice(b"example.com");
        payload.extend_from_slice(&443u16.to_be_bytes());

        let dest = mux.parse_destination(&payload).unwrap();
        assert_eq!(dest, "example.com:443");
    }

    #[test]
    fn test_parse_ipv4_destination() {
        let mux = Multiplexer::new_server();

        // IPv4 format: [0x01][4 bytes IP][port_be]
        let payload = vec![0x01, 192, 168, 1, 1, 0x01, 0xBB]; // 192.168.1.1:443

        let dest = mux.parse_destination(&payload).unwrap();
        assert_eq!(dest, "192.168.1.1:443");
    }
}
