//! Noise Protocol handshake implementation
//!
//! Uses the IK pattern:
//! - Client knows server's static public key (prevents active probing)
//! - Provides mutual authentication
//! - Forward secrecy via ephemeral keys

use super::{CryptoError, KeyPair, PublicKey, NOISE_PATTERN};
use snow::{Builder, HandshakeState, TransportState};

/// Role in the handshake
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeRole {
    /// Initiator (client)
    Initiator,
    /// Responder (server)
    Responder,
}

/// Noise Protocol handshake state machine
pub struct NoiseHandshake {
    state: HandshakeState,
    role: HandshakeRole,
}

impl NoiseHandshake {
    /// Create a new initiator (client) handshake
    ///
    /// # Arguments
    /// * `local_keypair` - Client's static key pair
    /// * `remote_public` - Server's known public key (critical for anti-probing)
    pub fn new_initiator(
        local_keypair: &KeyPair,
        remote_public: &PublicKey,
    ) -> Result<Self, CryptoError> {
        let builder = Builder::new(NOISE_PATTERN.parse().unwrap());

        let state = builder
            .local_private_key(local_keypair.private.as_bytes())
            .remote_public_key(remote_public.as_bytes())
            .build_initiator()
            .map_err(CryptoError::Noise)?;

        Ok(Self {
            state,
            role: HandshakeRole::Initiator,
        })
    }

    /// Create a new responder (server) handshake
    ///
    /// # Arguments
    /// * `local_keypair` - Server's static key pair
    pub fn new_responder(local_keypair: &KeyPair) -> Result<Self, CryptoError> {
        let builder = Builder::new(NOISE_PATTERN.parse().unwrap());

        let state = builder
            .local_private_key(local_keypair.private.as_bytes())
            .build_responder()
            .map_err(CryptoError::Noise)?;

        Ok(Self {
            state,
            role: HandshakeRole::Responder,
        })
    }

    /// Get the handshake role
    pub fn role(&self) -> HandshakeRole {
        self.role
    }

    /// Check if handshake is complete
    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Write the next handshake message
    ///
    /// # Arguments
    /// * `payload` - Optional payload to include (for application data)
    /// * `output` - Buffer to write message to
    ///
    /// # Returns
    /// Number of bytes written
    pub fn write_message(
        &mut self,
        payload: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        self.state
            .write_message(payload, output)
            .map_err(CryptoError::Noise)
    }

    /// Read and process an incoming handshake message
    ///
    /// # Arguments
    /// * `message` - The received handshake message
    /// * `payload` - Buffer to write decrypted payload to
    ///
    /// # Returns
    /// Number of payload bytes
    pub fn read_message(
        &mut self,
        message: &[u8],
        payload: &mut [u8],
    ) -> Result<usize, CryptoError> {
        self.state
            .read_message(message, payload)
            .map_err(CryptoError::Noise)
    }

    /// Get the remote peer's static public key (after handshake)
    pub fn get_remote_static(&self) -> Option<PublicKey> {
        self.state
            .get_remote_static()
            .and_then(|bytes| PublicKey::from_bytes(bytes).ok())
    }

    /// Convert to transport mode after handshake completion
    ///
    /// Returns a transport state for encrypted communication
    pub fn into_transport(self) -> Result<NoiseTransport, CryptoError> {
        if !self.is_finished() {
            return Err(CryptoError::Handshake(
                "Handshake not complete".to_string(),
            ));
        }

        let transport = self
            .state
            .into_transport_mode()
            .map_err(CryptoError::Noise)?;

        Ok(NoiseTransport { state: transport })
    }
}

/// Transport state for encrypted communication after handshake
pub struct NoiseTransport {
    state: TransportState,
}

impl NoiseTransport {
    /// Encrypt a message
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `output` - Buffer for ciphertext (must be plaintext.len() + 16)
    ///
    /// # Returns
    /// Number of bytes written
    pub fn encrypt(&mut self, plaintext: &[u8], output: &mut [u8]) -> Result<usize, CryptoError> {
        self.state
            .write_message(plaintext, output)
            .map_err(CryptoError::Noise)
    }

    /// Decrypt a message
    ///
    /// # Arguments
    /// * `ciphertext` - Encrypted data
    /// * `output` - Buffer for plaintext
    ///
    /// # Returns
    /// Number of bytes written
    pub fn decrypt(&mut self, ciphertext: &[u8], output: &mut [u8]) -> Result<usize, CryptoError> {
        self.state
            .read_message(ciphertext, output)
            .map_err(CryptoError::Noise)
    }

    /// Rekey the sending cipher (for forward secrecy)
    pub fn rekey_outgoing(&mut self) {
        self.state.rekey_outgoing();
    }

    /// Rekey the receiving cipher (for forward secrecy)
    pub fn rekey_incoming(&mut self) {
        self.state.rekey_incoming();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_ik_pattern() {
        // Generate keys
        let server_keypair = KeyPair::generate().unwrap();
        let client_keypair = KeyPair::generate().unwrap();

        // Client knows server's public key
        let mut client =
            NoiseHandshake::new_initiator(&client_keypair, &server_keypair.public).unwrap();
        let mut server = NoiseHandshake::new_responder(&server_keypair).unwrap();

        let mut buf1 = [0u8; 1024];
        let mut buf2 = [0u8; 1024];

        // IK pattern: -> e, es, s, ss
        let len = client.write_message(&[], &mut buf1).unwrap();
        server.read_message(&buf1[..len], &mut buf2).unwrap();

        // <- e, ee, se
        let len = server.write_message(&[], &mut buf1).unwrap();
        client.read_message(&buf1[..len], &mut buf2).unwrap();

        assert!(client.is_finished());
        assert!(server.is_finished());

        // Verify server knows client's public key
        let remote = server.get_remote_static().unwrap();
        assert_eq!(remote, client_keypair.public);

        // Convert to transport and test encryption
        let mut client_transport = client.into_transport().unwrap();
        let mut server_transport = server.into_transport().unwrap();

        let plaintext = b"Hello, secure world!";
        let mut ciphertext = [0u8; 256];
        let mut decrypted = [0u8; 256];

        let ct_len = client_transport
            .encrypt(plaintext, &mut ciphertext)
            .unwrap();
        let pt_len = server_transport
            .decrypt(&ciphertext[..ct_len], &mut decrypted)
            .unwrap();

        assert_eq!(&decrypted[..pt_len], plaintext);
    }

    #[test]
    fn test_bidirectional_encryption() {
        let server_keypair = KeyPair::generate().unwrap();
        let client_keypair = KeyPair::generate().unwrap();

        let mut client =
            NoiseHandshake::new_initiator(&client_keypair, &server_keypair.public).unwrap();
        let mut server = NoiseHandshake::new_responder(&server_keypair).unwrap();

        let mut write_buf = [0u8; 1024];
        let mut read_buf = [0u8; 1024];

        // Complete handshake
        let len = client.write_message(&[], &mut write_buf).unwrap();
        server.read_message(&write_buf[..len], &mut read_buf).unwrap();
        let len = server.write_message(&[], &mut write_buf).unwrap();
        client.read_message(&write_buf[..len], &mut read_buf).unwrap();

        let mut client_transport = client.into_transport().unwrap();
        let mut server_transport = server.into_transport().unwrap();

        // Client to server
        let msg1 = b"Client to server";
        let mut ct = [0u8; 256];
        let mut pt = [0u8; 256];

        let len = client_transport.encrypt(msg1, &mut ct).unwrap();
        let len = server_transport.decrypt(&ct[..len], &mut pt).unwrap();
        assert_eq!(&pt[..len], msg1);

        // Server to client
        let msg2 = b"Server to client";
        let len = server_transport.encrypt(msg2, &mut ct).unwrap();
        let len = client_transport.decrypt(&ct[..len], &mut pt).unwrap();
        assert_eq!(&pt[..len], msg2);
    }
}
