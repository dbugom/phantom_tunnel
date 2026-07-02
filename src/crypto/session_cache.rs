//! Session resumption cache for 0-RTT reconnection.
//!
//! After a successful Noise IK handshake, derive a session token:
//!   session_token = HKDF(handshake_hash, "phantom-session", 32)
//!
//! Cache the cipher state keyed by this token. On reconnect, the client
//! sends the token inside TLS early data. If the server recognizes it
//! and the session hasn't expired, the cached state is restored —
//! no Noise re-handshake needed.
//!
//! Protocol:
//!   CLIENT                              SERVER
//!     |--- [0x01 RESUME | 32-byte token] -->|  Server looks up token
//!     |<-------- [0x01 OK] ----------------|  Restore session
//!     |=== Encrypted tunnel resumes ========|
//!
//!   If server doesn't recognize token:
//!     |<-- [0x02 FULL_HANDSHAKE] ----------|  Client falls back to full handshake

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Session tokens expire after 2 minutes (short to limit replay risk)
const SESSION_TTL: Duration = Duration::from_secs(120);

/// Maximum cached sessions (prevents memory exhaustion)
const MAX_CACHED_SESSIONS: usize = 1024;

/// Resumption message types
pub const MSG_RESUME: u8 = 0x01;
pub const MSG_OK: u8 = 0x01;
pub const MSG_FULL_HANDSHAKE: u8 = 0x02;

/// A cached session containing the serialized cipher state
#[derive(Clone)]
pub struct CachedSession {
    /// Serialized send cipher state (nonce + key material)
    pub send_nonce: u64,
    /// Serialized recv cipher state
    pub recv_nonce: u64,
    /// Handshake hash used to derive the session token
    pub handshake_hash: Vec<u8>,
    /// When this session was cached
    pub created_at: Instant,
}

/// Server-side session cache
pub struct SessionCache {
    sessions: HashMap<[u8; 32], CachedSession>,
}

impl SessionCache {
    /// Create a new empty session cache
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Store a session token -> cached session mapping
    pub fn store(&mut self, token: [u8; 32], session: CachedSession) {
        // Evict expired sessions
        self.sessions
            .retain(|_, s| s.created_at.elapsed() < SESSION_TTL);

        // Enforce max size by removing oldest if at capacity
        if self.sessions.len() >= MAX_CACHED_SESSIONS {
            if let Some(oldest_key) = self
                .sessions
                .iter()
                .min_by_key(|(_, s)| s.created_at)
                .map(|(k, _)| *k)
            {
                self.sessions.remove(&oldest_key);
            }
        }

        self.sessions.insert(token, session);
    }

    /// Retrieve and remove a session by token (one-time use for replay resistance)
    pub fn retrieve_and_remove(&mut self, token: &[u8; 32]) -> Option<CachedSession> {
        let session = self.sessions.remove(token)?;
        if session.created_at.elapsed() > SESSION_TTL {
            return None; // Expired
        }
        Some(session)
    }

    /// Number of cached sessions (for diagnostics)
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

/// Derive a session token from the handshake hash using HKDF
pub fn derive_session_token(handshake_hash: &[u8]) -> [u8; 32] {
    use ring::hkdf;

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"phantom-session-salt");
    let prk = salt.extract(handshake_hash);

    let info = &[b"phantom-session-token".as_slice()];
    let okm = prk
        .expand(info, TokenLength(32))
        .expect("HKDF expand failed");

    let mut token = [0u8; 32];
    okm.fill(&mut token).expect("HKDF fill failed");
    token
}

/// Helper for ring HKDF output length
struct TokenLength(usize);

impl ring::hkdf::KeyType for TokenLength {
    fn len(&self) -> usize {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_cache_store_retrieve() {
        let mut cache = SessionCache::new();
        let token = [42u8; 32];
        let session = CachedSession {
            send_nonce: 1,
            recv_nonce: 2,
            handshake_hash: vec![0u8; 32],
            created_at: Instant::now(),
        };

        cache.store(token, session);
        assert_eq!(cache.len(), 1);

        let retrieved = cache.retrieve_and_remove(&token);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().send_nonce, 1);

        // One-time use — second retrieval should fail
        assert!(cache.retrieve_and_remove(&token).is_none());
    }

    #[test]
    fn test_session_token_derivation() {
        let hash1 = [1u8; 32];
        let hash2 = [2u8; 32];

        let token1 = derive_session_token(&hash1);
        let token2 = derive_session_token(&hash2);

        // Different hashes should produce different tokens
        assert_ne!(token1, token2);

        // Same hash should produce same token (deterministic)
        assert_eq!(token1, derive_session_token(&hash1));
    }

    #[test]
    fn test_session_cache_expiry() {
        let mut cache = SessionCache::new();
        let token = [99u8; 32];
        let session = CachedSession {
            send_nonce: 0,
            recv_nonce: 0,
            handshake_hash: vec![],
            created_at: Instant::now() - Duration::from_secs(300), // Expired
        };

        cache.store(token, session);
        assert!(cache.retrieve_and_remove(&token).is_none());
    }
}
