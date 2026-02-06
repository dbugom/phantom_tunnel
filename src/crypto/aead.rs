//! AEAD encryption/decryption utilities
//!
//! Provides ChaCha20-Poly1305 AEAD encryption for frame-level encryption
//! independent of the Noise transport (for length prefix encryption, etc.)

use super::{CryptoError, KEY_LEN, NONCE_LEN, TAG_LEN};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};

/// AEAD cipher for encrypting/decrypting data
pub struct Cipher {
    key: LessSafeKey,
    nonce_counter: u64,
}

impl Cipher {
    /// Create a new cipher from a 32-byte key
    pub fn new(key: &[u8; KEY_LEN]) -> Result<Self, CryptoError> {
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key)
            .map_err(|_| CryptoError::InvalidKeyLength)?;

        Ok(Self {
            key: LessSafeKey::new(unbound_key),
            nonce_counter: 0,
        })
    }

    /// Encrypt data in place, appending the auth tag
    ///
    /// The buffer must have TAG_LEN (16) bytes of extra capacity
    pub fn encrypt_in_place(
        &mut self,
        associated_data: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        let nonce = self.next_nonce();
        let nonce = Nonce::assume_unique_for_key(nonce);

        self.key
            .seal_in_place_append_tag(nonce, Aad::from(associated_data), buffer)
            .map_err(|_| CryptoError::Encryption("seal failed".to_string()))?;

        Ok(())
    }

    /// Decrypt data in place, verifying and removing the auth tag
    ///
    /// Returns the plaintext length (buffer is modified in place)
    pub fn decrypt_in_place(
        &mut self,
        associated_data: &[u8],
        nonce: &[u8; NONCE_LEN],
        buffer: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let nonce = Nonce::assume_unique_for_key(*nonce);

        let plaintext = self
            .key
            .open_in_place(nonce, Aad::from(associated_data), buffer)
            .map_err(|_| CryptoError::Decryption("open failed".to_string()))?;

        Ok(plaintext.len())
    }

    /// Encrypt data, returning ciphertext with appended tag
    pub fn encrypt(
        &mut self,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; NONCE_LEN]), CryptoError> {
        let nonce = self.next_nonce();
        let mut buffer = plaintext.to_vec();

        let nonce_obj = Nonce::assume_unique_for_key(nonce);
        self.key
            .seal_in_place_append_tag(nonce_obj, Aad::from(associated_data), &mut buffer)
            .map_err(|_| CryptoError::Encryption("seal failed".to_string()))?;

        Ok((buffer, nonce))
    }

    /// Decrypt data, verifying the auth tag
    pub fn decrypt(
        &mut self,
        associated_data: &[u8],
        nonce: &[u8; NONCE_LEN],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut buffer = ciphertext.to_vec();
        let nonce = Nonce::assume_unique_for_key(*nonce);

        let plaintext = self
            .key
            .open_in_place(nonce, Aad::from(associated_data), &mut buffer)
            .map_err(|_| CryptoError::Decryption("open failed".to_string()))?;

        Ok(plaintext.to_vec())
    }

    /// Generate the next nonce (monotonic counter)
    fn next_nonce(&mut self) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        // Use counter in little-endian in the last 8 bytes
        nonce[4..12].copy_from_slice(&self.nonce_counter.to_le_bytes());
        self.nonce_counter += 1;
        nonce
    }

    /// Get current nonce counter value
    pub fn nonce_counter(&self) -> u64 {
        self.nonce_counter
    }

    /// Check if rekey is needed (after 2^32 messages)
    pub fn needs_rekey(&self) -> bool {
        self.nonce_counter >= (1u64 << 32)
    }
}

/// Encrypt a length prefix (2 bytes) with a dedicated cipher
///
/// This prevents length-based fingerprinting
pub fn encrypt_length(
    cipher: &mut Cipher,
    length: u16,
) -> Result<([u8; 2 + TAG_LEN], [u8; NONCE_LEN]), CryptoError> {
    let plaintext = length.to_be_bytes();
    let (ciphertext, nonce) = cipher.encrypt(&[], &plaintext)?;

    let mut result = [0u8; 2 + TAG_LEN];
    result.copy_from_slice(&ciphertext);

    Ok((result, nonce))
}

/// Decrypt a length prefix
pub fn decrypt_length(
    cipher: &mut Cipher,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8; 2 + TAG_LEN],
) -> Result<u16, CryptoError> {
    let plaintext = cipher.decrypt(&[], nonce, ciphertext)?;

    if plaintext.len() != 2 {
        return Err(CryptoError::Decryption("invalid length".to_string()));
    }

    Ok(u16::from_be_bytes([plaintext[0], plaintext[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_encrypt_decrypt() {
        let key = [0x42u8; KEY_LEN];
        let mut encrypt_cipher = Cipher::new(&key).unwrap();
        let mut decrypt_cipher = Cipher::new(&key).unwrap();

        let plaintext = b"Hello, World!";
        let aad = b"associated data";

        let (ciphertext, nonce) = encrypt_cipher.encrypt(aad, plaintext).unwrap();
        let decrypted = decrypt_cipher.decrypt(aad, &nonce, &ciphertext).unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_cipher_in_place() {
        let key = [0x42u8; KEY_LEN];
        let mut cipher = Cipher::new(&key).unwrap();

        let plaintext = b"Hello, World!";
        let mut buffer = plaintext.to_vec();

        cipher.encrypt_in_place(&[], &mut buffer).unwrap();

        // Buffer should now be plaintext + tag
        assert_eq!(buffer.len(), plaintext.len() + TAG_LEN);
    }

    #[test]
    fn test_length_encryption() {
        let key = [0x42u8; KEY_LEN];
        let mut encrypt_cipher = Cipher::new(&key).unwrap();
        let mut decrypt_cipher = Cipher::new(&key).unwrap();

        let length: u16 = 1234;
        let (ciphertext, nonce) = encrypt_length(&mut encrypt_cipher, length).unwrap();
        let decrypted = decrypt_length(&mut decrypt_cipher, &nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, length);
    }

    #[test]
    fn test_tamper_detection() {
        let key = [0x42u8; KEY_LEN];
        let mut encrypt_cipher = Cipher::new(&key).unwrap();
        let mut decrypt_cipher = Cipher::new(&key).unwrap();

        let plaintext = b"Hello, World!";
        let (mut ciphertext, nonce) = encrypt_cipher.encrypt(&[], plaintext).unwrap();

        // Tamper with ciphertext
        ciphertext[0] ^= 0xFF;

        // Should fail to decrypt
        let result = decrypt_cipher.decrypt(&[], &nonce, &ciphertext);
        assert!(result.is_err());
    }
}
