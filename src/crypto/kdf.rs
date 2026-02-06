//! Key Derivation Functions
//!
//! Provides HKDF-SHA256 for deriving keys from shared secrets

use super::{CryptoError, KEY_LEN};
use ring::hkdf::{self, Salt, HKDF_SHA256};

/// HKDF-SHA256 key derivation
pub struct Hkdf {
    prk: hkdf::Prk,
}

impl Hkdf {
    /// Create HKDF from input keying material
    ///
    /// # Arguments
    /// * `salt` - Optional salt (if None, uses zeros)
    /// * `ikm` - Input keying material
    pub fn new(salt: Option<&[u8]>, ikm: &[u8]) -> Self {
        let salt = match salt {
            Some(s) => Salt::new(HKDF_SHA256, s),
            None => Salt::new(HKDF_SHA256, &[0u8; 32]),
        };

        let prk = salt.extract(ikm);

        Self { prk }
    }

    /// Derive a key from the PRK
    ///
    /// # Arguments
    /// * `info` - Context and application-specific information
    /// * `output` - Buffer to write derived key to
    pub fn expand(&self, info: &[u8], output: &mut [u8]) -> Result<(), CryptoError> {
        let info_refs = [info];
        let okm = self
            .prk
            .expand(&info_refs, HkdfLen(output.len()))
            .map_err(|_| CryptoError::KeyGeneration("HKDF expand failed".to_string()))?;

        okm.fill(output)
            .map_err(|_| CryptoError::KeyGeneration("HKDF fill failed".to_string()))?;

        Ok(())
    }

    /// Derive a 32-byte key
    pub fn expand_key(&self, info: &[u8]) -> Result<[u8; KEY_LEN], CryptoError> {
        let mut key = [0u8; KEY_LEN];
        self.expand(info, &mut key)?;
        Ok(key)
    }

    /// Derive multiple keys at once
    pub fn expand_keys<const N: usize>(
        &self,
        labels: &[&[u8]; N],
    ) -> Result<[[u8; KEY_LEN]; N], CryptoError> {
        let mut keys = [[0u8; KEY_LEN]; N];
        for (i, label) in labels.iter().enumerate() {
            self.expand(label, &mut keys[i])?;
        }
        Ok(keys)
    }
}

/// Helper struct for HKDF output length
struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// Derive keys for a session from the Noise handshake output
///
/// # Arguments
/// * `handshake_hash` - The handshake hash from Noise
///
/// # Returns
/// Tuple of (client_key, server_key, client_nonce_key, server_nonce_key)
pub fn derive_session_keys(
    handshake_hash: &[u8],
) -> Result<([u8; KEY_LEN], [u8; KEY_LEN]), CryptoError> {
    let hkdf = Hkdf::new(None, handshake_hash);

    let client_key = hkdf.expand_key(b"phantom_tunnel_client_key")?;
    let server_key = hkdf.expand_key(b"phantom_tunnel_server_key")?;

    Ok((client_key, server_key))
}

/// Derive a subkey for length encryption
pub fn derive_length_key(session_key: &[u8; KEY_LEN]) -> Result<[u8; KEY_LEN], CryptoError> {
    let hkdf = Hkdf::new(None, session_key);
    hkdf.expand_key(b"phantom_tunnel_length_key")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_basic() {
        let ikm = b"input keying material";
        let hkdf = Hkdf::new(Some(b"salt"), ikm);

        let key1 = hkdf.expand_key(b"label1").unwrap();
        let key2 = hkdf.expand_key(b"label2").unwrap();

        // Different labels should produce different keys
        assert_ne!(key1, key2);

        // Same label should produce same key
        let key1_again = hkdf.expand_key(b"label1").unwrap();
        assert_eq!(key1, key1_again);
    }

    #[test]
    fn test_hkdf_deterministic() {
        let ikm = b"test input";

        let hkdf1 = Hkdf::new(None, ikm);
        let hkdf2 = Hkdf::new(None, ikm);

        let key1 = hkdf1.expand_key(b"test").unwrap();
        let key2 = hkdf2.expand_key(b"test").unwrap();

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_session_key_derivation() {
        let handshake_hash = [0x42u8; 32];
        let (client_key, server_key) = derive_session_keys(&handshake_hash).unwrap();

        // Keys should be different
        assert_ne!(client_key, server_key);

        // Keys should be 32 bytes
        assert_eq!(client_key.len(), KEY_LEN);
        assert_eq!(server_key.len(), KEY_LEN);
    }

    #[test]
    fn test_length_key_derivation() {
        let session_key = [0x42u8; KEY_LEN];
        let length_key = derive_length_key(&session_key).unwrap();

        // Should be different from session key
        assert_ne!(length_key, session_key);
    }
}
