//! Connection management for the tunnel
//!
//! Handles the full lifecycle of a tunnel connection including:
//! - TLS connection with fingerprint mimicry
//! - Noise Protocol handshake
//! - Frame encryption/decryption
//! - Reconnection logic

use super::{Transport, TransportConfig, TransportError};
use crate::crypto::{
    Cipher, HandshakeRole, KeyPair, NoiseHandshake, NoiseTransport, PublicKey,
    derive_length_key, KEY_LEN,
};
use crate::tunnel::{Frame, FrameType};
use bytes::BytesMut;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected
    Disconnected,
    /// TLS handshake in progress
    TlsHandshake,
    /// Noise handshake in progress
    NoiseHandshake,
    /// Fully connected and ready
    Connected,
    /// Connection closing
    Closing,
    /// Connection closed
    Closed,
}

/// A managed tunnel connection
pub struct TunnelConnection<T: Transport> {
    transport: T,
    state: ConnectionState,
    local_keypair: KeyPair,
    remote_public: Option<PublicKey>,
    noise_transport: Option<NoiseTransport>,
    length_cipher: Option<Cipher>,
    role: HandshakeRole,
    read_buffer: BytesMut,
}

impl<T: Transport> TunnelConnection<T> {
    /// Create a new client connection
    pub fn new_client(
        transport: T,
        local_keypair: KeyPair,
        server_public: PublicKey,
    ) -> Self {
        Self {
            transport,
            state: ConnectionState::Disconnected,
            local_keypair,
            remote_public: Some(server_public),
            noise_transport: None,
            length_cipher: None,
            role: HandshakeRole::Initiator,
            read_buffer: BytesMut::with_capacity(65536),
        }
    }

    /// Create a new server connection
    pub fn new_server(transport: T, local_keypair: KeyPair) -> Self {
        Self {
            transport,
            state: ConnectionState::Disconnected,
            local_keypair,
            remote_public: None,
            noise_transport: None,
            length_cipher: None,
            role: HandshakeRole::Responder,
            read_buffer: BytesMut::with_capacity(65536),
        }
    }

    /// Get current connection state
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.state == ConnectionState::Connected
    }

    /// Get remote peer's public key (after handshake)
    pub fn remote_public(&self) -> Option<&PublicKey> {
        self.remote_public.as_ref()
    }

    /// Connect to server (client only)
    pub async fn connect(&mut self, addr: &str) -> Result<(), TransportError> {
        if self.role != HandshakeRole::Initiator {
            return Err(TransportError::ConnectionFailed(
                "connect() only valid for client".to_string(),
            ));
        }

        // Connect transport (TLS)
        self.state = ConnectionState::TlsHandshake;
        self.transport.connect(addr).await?;

        // Perform Noise handshake
        self.state = ConnectionState::NoiseHandshake;
        self.perform_client_handshake().await?;

        self.state = ConnectionState::Connected;
        Ok(())
    }

    /// Accept connection (server only)
    pub async fn accept(&mut self) -> Result<(), TransportError> {
        if self.role != HandshakeRole::Responder {
            return Err(TransportError::ConnectionFailed(
                "accept() only valid for server".to_string(),
            ));
        }

        // Perform Noise handshake
        self.state = ConnectionState::NoiseHandshake;
        self.perform_server_handshake().await?;

        self.state = ConnectionState::Connected;
        Ok(())
    }

    /// Perform client-side Noise handshake
    async fn perform_client_handshake(&mut self) -> Result<(), TransportError> {
        let server_public = self.remote_public.as_ref().ok_or_else(|| {
            TransportError::ConnectionFailed("Server public key not set".to_string())
        })?;

        let mut handshake = NoiseHandshake::new_initiator(&self.local_keypair, server_public)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let mut buf = [0u8; 65535];
        let mut payload_buf = [0u8; 65535];

        // Send first message (-> e, es, s, ss)
        let len = handshake
            .write_message(&[], &mut buf)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        // Send length prefix + message
        let len_bytes = (len as u16).to_be_bytes();
        self.transport.send(&len_bytes).await?;
        self.transport.send(&buf[..len]).await?;

        // Receive response (<- e, ee, se)
        let mut len_buf = [0u8; 2];
        let n = self.transport.recv(&mut len_buf).await?;
        if n != 2 {
            return Err(TransportError::ConnectionFailed("Invalid response".to_string()));
        }
        let msg_len = u16::from_be_bytes(len_buf) as usize;

        let n = self.transport.recv(&mut buf[..msg_len]).await?;
        if n != msg_len {
            return Err(TransportError::ConnectionFailed("Incomplete response".to_string()));
        }

        handshake
            .read_message(&buf[..msg_len], &mut payload_buf)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        // Convert to transport mode
        let noise_transport = handshake
            .into_transport()
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        // Derive length encryption key
        let length_key = derive_length_key(&[0u8; KEY_LEN])
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        let length_cipher = Cipher::new(&length_key)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        self.noise_transport = Some(noise_transport);
        self.length_cipher = Some(length_cipher);

        Ok(())
    }

    /// Perform server-side Noise handshake
    async fn perform_server_handshake(&mut self) -> Result<(), TransportError> {
        let mut handshake = NoiseHandshake::new_responder(&self.local_keypair)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let mut buf = [0u8; 65535];
        let mut payload_buf = [0u8; 65535];

        // Receive first message
        let mut len_buf = [0u8; 2];
        let n = self.transport.recv(&mut len_buf).await?;
        if n != 2 {
            return Err(TransportError::ConnectionFailed("Invalid message".to_string()));
        }
        let msg_len = u16::from_be_bytes(len_buf) as usize;

        let n = self.transport.recv(&mut buf[..msg_len]).await?;
        if n != msg_len {
            return Err(TransportError::ConnectionFailed("Incomplete message".to_string()));
        }

        handshake
            .read_message(&buf[..msg_len], &mut payload_buf)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        // Store remote public key
        self.remote_public = handshake.get_remote_static();

        // Send response
        let len = handshake
            .write_message(&[], &mut buf)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let len_bytes = (len as u16).to_be_bytes();
        self.transport.send(&len_bytes).await?;
        self.transport.send(&buf[..len]).await?;

        // Convert to transport mode
        let noise_transport = handshake
            .into_transport()
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        // Derive length encryption key
        let length_key = derive_length_key(&[0u8; KEY_LEN])
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        let length_cipher = Cipher::new(&length_key)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        self.noise_transport = Some(noise_transport);
        self.length_cipher = Some(length_cipher);

        Ok(())
    }

    /// Send a frame
    pub async fn send_frame(&mut self, frame: &Frame) -> Result<(), TransportError> {
        if !self.is_connected() {
            return Err(TransportError::Closed);
        }

        let noise = self.noise_transport.as_mut().ok_or(TransportError::Closed)?;

        // Encode frame
        let plaintext = frame.encode();

        // Encrypt frame
        let mut ciphertext = vec![0u8; plaintext.len() + 16]; // +16 for auth tag
        let ct_len = noise
            .encrypt(&plaintext, &mut ciphertext)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        // Send length + ciphertext
        let len_bytes = (ct_len as u16).to_be_bytes();
        self.transport.send(&len_bytes).await?;
        self.transport.send(&ciphertext[..ct_len]).await?;

        Ok(())
    }

    /// Receive a frame
    pub async fn recv_frame(&mut self) -> Result<Frame, TransportError> {
        if !self.is_connected() {
            return Err(TransportError::Closed);
        }

        let noise = self.noise_transport.as_mut().ok_or(TransportError::Closed)?;

        // Read length
        let mut len_buf = [0u8; 2];
        let n = self.transport.recv(&mut len_buf).await?;
        if n != 2 {
            return Err(TransportError::ConnectionFailed("Invalid frame length".to_string()));
        }
        let frame_len = u16::from_be_bytes(len_buf) as usize;

        // Read ciphertext
        let mut ciphertext = vec![0u8; frame_len];
        let mut total_read = 0;
        while total_read < frame_len {
            let n = self.transport.recv(&mut ciphertext[total_read..]).await?;
            if n == 0 {
                return Err(TransportError::Closed);
            }
            total_read += n;
        }

        // Decrypt
        let mut plaintext = vec![0u8; frame_len];
        let pt_len = noise
            .decrypt(&ciphertext, &mut plaintext)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        // Decode frame
        let mut buf = BytesMut::from(&plaintext[..pt_len]);
        Frame::decode(&mut buf)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?
            .ok_or_else(|| TransportError::ConnectionFailed("Incomplete frame".to_string()))
    }

    /// Close the connection
    pub async fn close(&mut self) -> Result<(), TransportError> {
        self.state = ConnectionState::Closing;

        // Send GOAWAY frame if connected
        if self.noise_transport.is_some() {
            let goaway = Frame {
                frame_type: FrameType::GoAway,
                stream_id: 0,
                payload: bytes::Bytes::new(),
                padding_len: 0,
            };
            let _ = self.send_frame(&goaway).await;
        }

        self.transport.close().await?;
        self.state = ConnectionState::Closed;
        Ok(())
    }
}
