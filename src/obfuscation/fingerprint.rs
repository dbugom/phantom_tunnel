//! TLS Fingerprint Mimicry
//!
//! Configures TLS connections to mimic real browser fingerprints.
//! This is CRITICAL for evading deep packet inspection (DPI) in censored networks.
//!
//! ## How Fingerprinting Works
//!
//! Censors use JA3/JA4 fingerprinting to identify non-browser TLS clients by analyzing:
//! - Cipher suite order
//! - TLS extension order
//! - Supported groups (curves)
//! - Signature algorithms
//! - ALPN protocols
//!
//! ## Limitations
//!
//! rustls doesn't provide full control over ClientHello construction.
//! For maximum mimicry, consider using a custom TLS implementation or
//! patched rustls. This module provides the best possible mimicry within
//! rustls's constraints.

use rustls::crypto::ring as ring_provider;
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, RootCertStore, SupportedCipherSuite};
use std::sync::Arc;

/// Browser fingerprint profiles
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BrowserProfile {
    /// Chrome 120+ on Windows/Mac/Linux
    #[default]
    Chrome,
    /// Firefox 121+ on Windows/Mac/Linux
    Firefox,
    /// Safari 17+ on macOS/iOS
    Safari,
    /// Microsoft Edge (Chromium-based)
    Edge,
    /// Random selection from profiles
    Random,
    /// iOS Safari
    IosSafari,
    /// Android Chrome
    AndroidChrome,
}

impl BrowserProfile {
    /// Get a random profile
    pub fn random() -> Self {
        use crate::crypto::random_bytes;
        let mut buf = [0u8; 1];
        random_bytes(&mut buf);
        match buf[0] % 4 {
            0 => Self::Chrome,
            1 => Self::Firefox,
            2 => Self::Safari,
            _ => Self::Edge,
        }
    }

    /// Get the User-Agent string for this profile
    pub fn user_agent(&self) -> &'static str {
        match self {
            Self::Chrome | Self::Edge => {
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
            Self::Firefox => {
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
            }
            Self::Safari => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
            }
            Self::IosSafari => {
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
            }
            Self::AndroidChrome => {
                "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
            }
            Self::Random => Self::random().user_agent(),
        }
    }

    /// Get ALPN protocols for this profile
    pub fn alpn_protocols(&self) -> Vec<Vec<u8>> {
        match self {
            Self::Chrome | Self::Edge | Self::AndroidChrome => {
                vec![b"h2".to_vec(), b"http/1.1".to_vec()]
            }
            Self::Firefox => {
                vec![b"h2".to_vec(), b"http/1.1".to_vec()]
            }
            Self::Safari | Self::IosSafari => {
                vec![b"h2".to_vec(), b"http/1.1".to_vec()]
            }
            Self::Random => Self::random().alpn_protocols(),
        }
    }
}

/// TLS fingerprint configuration
#[derive(Debug, Clone)]
pub struct FingerprintConfig {
    /// Browser profile to mimic
    pub profile: BrowserProfile,
    /// Server Name Indication (SNI)
    pub sni: String,
    /// Enable session resumption (browsers do this)
    pub session_resumption: bool,
    /// Enable OCSP stapling
    pub ocsp_stapling: bool,
}

impl FingerprintConfig {
    /// Create a new fingerprint config
    pub fn new(profile: BrowserProfile, sni: impl Into<String>) -> Self {
        Self {
            profile,
            sni: sni.into(),
            session_resumption: true,
            ocsp_stapling: true,
        }
    }

    /// Create with Chrome profile
    pub fn chrome(sni: impl Into<String>) -> Self {
        Self::new(BrowserProfile::Chrome, sni)
    }

    /// Create with Firefox profile
    pub fn firefox(sni: impl Into<String>) -> Self {
        Self::new(BrowserProfile::Firefox, sni)
    }

    /// Create with Safari profile
    pub fn safari(sni: impl Into<String>) -> Self {
        Self::new(BrowserProfile::Safari, sni)
    }

    /// Create with random profile
    pub fn random(sni: impl Into<String>) -> Self {
        Self::new(BrowserProfile::Random, sni)
    }
}

/// Build a rustls ClientConfig that mimics a browser fingerprint
pub fn build_tls_config(config: &FingerprintConfig) -> Result<ClientConfig, FingerprintError> {
    let profile = match config.profile {
        BrowserProfile::Random => BrowserProfile::random(),
        p => p,
    };

    // Get root certificates
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    // Get cipher suites for this profile
    let cipher_suites = get_cipher_suites(profile);

    // Create crypto provider with specific cipher suite order
    let crypto_provider = CryptoProvider {
        cipher_suites,
        ..ring_provider::default_provider()
    };

    // Build the config
    let mut tls_config = ClientConfig::builder_with_provider(Arc::new(crypto_provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| FingerprintError::Config(e.to_string()))?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Set ALPN protocols
    tls_config.alpn_protocols = config.profile.alpn_protocols();

    // Enable session resumption (browsers do this)
    if config.session_resumption {
        tls_config.resumption = rustls::client::Resumption::default();
    }

    Ok(tls_config)
}

/// Get cipher suites ordered to match browser profile
fn get_cipher_suites(profile: BrowserProfile) -> Vec<SupportedCipherSuite> {
    use rustls::crypto::ring::cipher_suite;

    match profile {
        BrowserProfile::Chrome | BrowserProfile::Edge | BrowserProfile::AndroidChrome => {
            // Chrome cipher suite order (TLS 1.3 first, then 1.2)
            vec![
                // TLS 1.3 cipher suites
                cipher_suite::TLS13_AES_128_GCM_SHA256,
                cipher_suite::TLS13_AES_256_GCM_SHA384,
                cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                // TLS 1.2 cipher suites
                cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ]
        }
        BrowserProfile::Firefox => {
            // Firefox cipher suite order
            vec![
                cipher_suite::TLS13_AES_128_GCM_SHA256,
                cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                cipher_suite::TLS13_AES_256_GCM_SHA384,
                cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            ]
        }
        BrowserProfile::Safari | BrowserProfile::IosSafari => {
            // Safari cipher suite order
            vec![
                cipher_suite::TLS13_AES_128_GCM_SHA256,
                cipher_suite::TLS13_AES_256_GCM_SHA384,
                cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ]
        }
        BrowserProfile::Random => get_cipher_suites(BrowserProfile::random()),
    }
}

/// Fingerprint-related errors
#[derive(Debug, thiserror::Error)]
pub enum FingerprintError {
    #[error("TLS configuration error: {0}")]
    Config(String),

    #[error("Invalid SNI: {0}")]
    InvalidSni(String),

    #[error("Unsupported profile: {0:?}")]
    UnsupportedProfile(BrowserProfile),
}

/// JA3 fingerprint components (for reference/debugging)
#[derive(Debug, Clone)]
pub struct Ja3Components {
    /// TLS version
    pub version: u16,
    /// Cipher suites (hex)
    pub cipher_suites: Vec<u16>,
    /// Extensions (hex)
    pub extensions: Vec<u16>,
    /// Elliptic curves
    pub curves: Vec<u16>,
    /// EC point formats
    pub point_formats: Vec<u8>,
}

impl Ja3Components {
    /// Get expected JA3 components for a browser profile
    pub fn for_profile(profile: BrowserProfile) -> Self {
        match profile {
            BrowserProfile::Chrome | BrowserProfile::Edge | BrowserProfile::AndroidChrome => {
                Self {
                    version: 0x0303, // TLS 1.2 (in ClientHello, actual is 1.3)
                    cipher_suites: vec![
                        0x1301, 0x1302, 0x1303, // TLS 1.3
                        0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, // TLS 1.2
                    ],
                    extensions: vec![
                        0x0000, // server_name
                        0x0017, // extended_master_secret
                        0xff01, // renegotiation_info
                        0x000a, // supported_groups
                        0x000b, // ec_point_formats
                        0x0023, // session_ticket
                        0x0010, // ALPN
                        0x0005, // status_request
                        0x000d, // signature_algorithms
                        0x0012, // SCT
                        0x002b, // supported_versions
                        0x002d, // psk_key_exchange_modes
                        0x0033, // key_share
                    ],
                    curves: vec![0x001d, 0x0017, 0x0018], // x25519, secp256r1, secp384r1
                    point_formats: vec![0x00],            // uncompressed
                }
            }
            BrowserProfile::Firefox => Self {
                version: 0x0303,
                cipher_suites: vec![
                    0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030,
                ],
                extensions: vec![
                    0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d,
                    0x002b, 0x002d, 0x0033, 0x001c,
                ],
                curves: vec![0x001d, 0x0017, 0x0018, 0x0019],
                point_formats: vec![0x00],
            },
            BrowserProfile::Safari | BrowserProfile::IosSafari => Self {
                version: 0x0303,
                cipher_suites: vec![
                    0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8,
                ],
                extensions: vec![
                    0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d,
                    0x002b, 0x002d, 0x0033,
                ],
                curves: vec![0x001d, 0x0017, 0x0018],
                point_formats: vec![0x00],
            },
            BrowserProfile::Random => Self::for_profile(BrowserProfile::random()),
        }
    }

    /// Calculate JA3 hash (MD5 of fingerprint string)
    pub fn ja3_hash(&self) -> String {
        let fingerprint = self.ja3_string();
        format!("{:x}", md5::compute(fingerprint.as_bytes()))
    }

    /// Get JA3 fingerprint string
    pub fn ja3_string(&self) -> String {
        let ciphers: Vec<String> = self.cipher_suites.iter().map(|c| c.to_string()).collect();
        let extensions: Vec<String> = self.extensions.iter().map(|e| e.to_string()).collect();
        let curves: Vec<String> = self.curves.iter().map(|c| c.to_string()).collect();
        let points: Vec<String> = self.point_formats.iter().map(|p| p.to_string()).collect();

        format!(
            "{},{},{},{},{}",
            self.version,
            ciphers.join("-"),
            extensions.join("-"),
            curves.join("-"),
            points.join("-")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_chrome_config() {
        let config = FingerprintConfig::chrome("example.com");
        let tls_config = build_tls_config(&config).unwrap();

        assert!(!tls_config.alpn_protocols.is_empty());
        assert!(tls_config.alpn_protocols.contains(&b"h2".to_vec()));
    }

    #[test]
    fn test_build_firefox_config() {
        let config = FingerprintConfig::firefox("example.com");
        let tls_config = build_tls_config(&config).unwrap();

        assert!(!tls_config.alpn_protocols.is_empty());
    }

    #[test]
    fn test_ja3_components() {
        let chrome = Ja3Components::for_profile(BrowserProfile::Chrome);
        let firefox = Ja3Components::for_profile(BrowserProfile::Firefox);

        // Different browsers should have different fingerprints
        assert_ne!(chrome.ja3_string(), firefox.ja3_string());
    }

    #[test]
    fn test_random_profile() {
        // Should not panic
        let _profile = BrowserProfile::random();
        let config = FingerprintConfig::random("example.com");
        let _ = build_tls_config(&config).unwrap();
    }

    #[test]
    fn test_user_agents() {
        assert!(BrowserProfile::Chrome.user_agent().contains("Chrome"));
        assert!(BrowserProfile::Firefox.user_agent().contains("Firefox"));
        assert!(BrowserProfile::Safari.user_agent().contains("Safari"));
    }
}
