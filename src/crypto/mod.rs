//! Cryptographic primitives for Phantom Tunnel
//!
//! This module provides:
//! - Noise Protocol handshake (IK pattern) for key exchange
//! - ChaCha20-Poly1305 AEAD encryption
//! - X25519 key generation
//! - HKDF-SHA256 key derivation
//! - Secure random number generation

mod aead;
mod handshake;
mod kdf;
mod keys;

pub use aead::{decrypt_length, encrypt_length, Cipher};
pub use handshake::{HandshakeRole, NoiseHandshake, NoiseTransport};
pub use kdf::{derive_length_key, derive_session_keys, Hkdf};
pub use keys::{KeyPair, PrivateKey, PublicKey};

use thiserror::Error;

/// Noise Protocol pattern used for handshake
/// IK: Client knows server's static public key
/// Provides mutual authentication and forward secrecy
pub const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_SHA256";

/// Length of symmetric key in bytes
pub const KEY_LEN: usize = 32;

/// Length of nonce in bytes
pub const NONCE_LEN: usize = 12;

/// Length of authentication tag in bytes
pub const TAG_LEN: usize = 16;

/// Cryptographic errors
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Handshake failed: {0}")]
    Handshake(String),

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Invalid key length")]
    InvalidKeyLength,

    #[error("Invalid nonce")]
    InvalidNonce,

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Noise protocol error: {0}")]
    Noise(#[from] snow::Error),
}

/// Generate cryptographically secure random bytes
pub fn random_bytes(buf: &mut [u8]) {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    rng.fill(buf).expect("Failed to generate random bytes");
}

/// Generate a random nonce
pub fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    random_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes() {
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        random_bytes(&mut buf1);
        random_bytes(&mut buf2);
        assert_ne!(buf1, buf2);
    }
}
