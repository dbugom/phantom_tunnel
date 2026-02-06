//! Traffic obfuscation layer
//!
//! Provides:
//! - TLS fingerprint mimicry (Chrome, Firefox, Safari)
//! - Traffic padding
//! - Timing randomization
//!
//! ## Critical for Censorship Evasion
//!
//! This module implements techniques to make tunnel traffic indistinguishable
//! from normal browser HTTPS traffic:
//!
//! 1. **TLS Fingerprint Mimicry**: Configure TLS ClientHello to match real browsers
//! 2. **Traffic Padding**: Normalize packet sizes to defeat length analysis
//! 3. **Timing Jitter**: Randomize packet timing to defeat timing analysis

mod fingerprint;
mod padding;
mod timing;

pub use fingerprint::{
    build_tls_config, BrowserProfile, FingerprintConfig, FingerprintError, Ja3Components,
};
pub use padding::{PaddingConfig, PaddingStrategy};
pub use timing::{TimingConfig, TimingObfuscator};

/// Legacy TLS profile enum (use BrowserProfile instead)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[deprecated(note = "Use BrowserProfile instead")]
pub enum TlsProfile {
    Chrome,
    Firefox,
    Safari,
    Edge,
    Default,
}

/// Configuration for traffic obfuscation
#[derive(Debug, Clone)]
pub struct ObfuscationConfig {
    /// Browser profile to mimic
    pub browser_profile: BrowserProfile,
    /// Server Name Indication for TLS
    pub sni: String,
    /// Padding configuration
    pub padding: PaddingConfig,
    /// Timing configuration
    pub timing: TimingConfig,
}

impl ObfuscationConfig {
    /// Create a new obfuscation config
    pub fn new(sni: impl Into<String>) -> Self {
        Self {
            browser_profile: BrowserProfile::Chrome,
            sni: sni.into(),
            padding: PaddingConfig::default(),
            timing: TimingConfig::default(),
        }
    }

    /// Set browser profile
    pub fn with_profile(mut self, profile: BrowserProfile) -> Self {
        self.browser_profile = profile;
        self
    }

    /// Set padding config
    pub fn with_padding(mut self, padding: PaddingConfig) -> Self {
        self.padding = padding;
        self
    }

    /// Set timing config
    pub fn with_timing(mut self, timing: TimingConfig) -> Self {
        self.timing = timing;
        self
    }

    /// Create fingerprint config from this obfuscation config
    pub fn fingerprint_config(&self) -> FingerprintConfig {
        FingerprintConfig::new(self.browser_profile, &self.sni)
    }
}

impl Default for ObfuscationConfig {
    fn default() -> Self {
        Self {
            browser_profile: BrowserProfile::Chrome,
            sni: "www.google.com".to_string(),
            padding: PaddingConfig::default(),
            timing: TimingConfig::default(),
        }
    }
}
