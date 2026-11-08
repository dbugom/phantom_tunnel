//! Key management for Phantom Tunnel

use super::{CryptoError, KEY_LEN};
use serde::{Deserialize, Serialize};
use std::fmt;

/// X25519 key pair for Noise Protocol
#[derive(Clone)]
pub struct KeyPair {
    pub public: PublicKey,
    pub private: PrivateKey,
}

impl KeyPair {
    /// Generate a new random key pair
    pub fn generate() -> Result<Self, CryptoError> {
        let builder = snow::Builder::new(super::NOISE_PATTERN.parse().unwrap());
        let keypair = builder
            .generate_keypair()
            .map_err(|e| CryptoError::KeyGeneration(e.to_string()))?;

        Ok(Self {
            public: PublicKey(
                keypair
                    .public
                    .try_into()
                    .map_err(|_| CryptoError::InvalidKeyLength)?,
            ),
            private: PrivateKey(
                keypair
                    .private
                    .try_into()
                    .map_err(|_| CryptoError::InvalidKeyLength)?,
            ),
        })
    }

    /// Build a key pair from a private key alone, deriving the public half.
    pub fn from_private(private: PrivateKey) -> Self {
        Self {
            public: private.public_key(),
            private,
        }
    }
}

/// X25519 public key
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey(pub [u8; KEY_LEN]);

impl PublicKey {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != KEY_LEN {
            return Err(CryptoError::InvalidKeyLength);
        }
        let mut arr = [0u8; KEY_LEN];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Encode as base64
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.0)
    }

    /// Decode from base64
    pub fn from_base64(s: &str) -> Result<Self, CryptoError> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|e| CryptoError::KeyGeneration(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({}...)", &self.to_base64()[..8])
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base64())
    }
}

/// X25519 private key (kept secret)
#[derive(Clone)]
pub struct PrivateKey(pub [u8; KEY_LEN]);

impl PrivateKey {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != KEY_LEN {
            return Err(CryptoError::InvalidKeyLength);
        }
        let mut arr = [0u8; KEY_LEN];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Derive the X25519 public key for this private key.
    ///
    /// This is the key the peer actually sees in the Noise handshake, so it is
    /// the authoritative value; a `public_key` stored next to the private key
    /// in a config file is only a convenience copy.
    pub fn public_key(&self) -> PublicKey {
        use snow::params::DHChoice;
        use snow::resolvers::{CryptoResolver, DefaultResolver};
        let mut dh = DefaultResolver
            .resolve_dh(&DHChoice::Curve25519)
            .expect("snow default resolver supports Curve25519");
        dh.set(&self.0);
        let mut out = [0u8; KEY_LEN];
        out.copy_from_slice(dh.pubkey());
        PublicKey(out)
    }

    /// Encode as base64 (be careful with this!)
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.0)
    }

    /// Decode from base64
    pub fn from_base64(s: &str) -> Result<Self, CryptoError> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|e| CryptoError::KeyGeneration(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrivateKey([REDACTED])")
    }
}

// Zeroize private key on drop
impl Drop for PrivateKey {
    fn drop(&mut self) {
        // Zero out the private key bytes
        for byte in &mut self.0 {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = KeyPair::generate().unwrap();
        assert_eq!(kp.public.as_bytes().len(), KEY_LEN);
        assert_eq!(kp.private.as_bytes().len(), KEY_LEN);
    }

    #[test]
    fn test_public_key_base64() {
        let kp = KeyPair::generate().unwrap();
        let b64 = kp.public.to_base64();
        let recovered = PublicKey::from_base64(&b64).unwrap();
        assert_eq!(kp.public, recovered);
    }

    #[test]
    fn derived_public_key_matches_generated_pair() {
        for _ in 0..8 {
            let kp = KeyPair::generate().unwrap();
            assert_eq!(kp.private.public_key(), kp.public);
            let rebuilt = KeyPair::from_private(kp.private.clone());
            assert_eq!(rebuilt.public, kp.public);
        }
    }
}
