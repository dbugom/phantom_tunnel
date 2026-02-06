//! TLS transport with fingerprint mimicry
//!
//! This transport wraps connections in TLS 1.3 and mimics
//! browser TLS fingerprints to evade deep packet inspection (DPI).
//!
//! ## Fingerprint Mimicry
//!
//! The transport configures TLS to match real browser fingerprints:
//! - Cipher suite ordering matches Chrome/Firefox/Safari
//! - ALPN protocols match browser behavior
//! - Session resumption enabled (browsers do this)

use super::{Transport, TransportConfig, TransportError};
use crate::obfuscation::{build_tls_config, BrowserProfile, FingerprintConfig};
use async_trait::async_trait;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};

/// TLS transport with browser fingerprint mimicry
pub struct TlsTransport {
    stream: Option<TlsStream<TcpStream>>,
    config: TransportConfig,
    tls_config: Arc<rustls::ClientConfig>,
    sni: String,
    profile: BrowserProfile,
}

impl TlsTransport {
    /// Create a new TLS transport with specified browser profile
    pub fn new(
        config: TransportConfig,
        profile: BrowserProfile,
        sni: impl Into<String>,
    ) -> Result<Self, TransportError> {
        let sni = sni.into();
        let fingerprint_config = FingerprintConfig::new(profile, &sni);
        let tls_config = build_tls_config(&fingerprint_config)
            .map_err(|e| TransportError::Tls(e.to_string()))?;

        Ok(Self {
            stream: None,
            config,
            tls_config: Arc::new(tls_config),
            sni,
            profile,
        })
    }

    /// Create with Chrome fingerprint (recommended - most common)
    pub fn chrome(sni: impl Into<String>) -> Result<Self, TransportError> {
        Self::new(TransportConfig::default(), BrowserProfile::Chrome, sni)
    }

    /// Create with Firefox fingerprint
    pub fn firefox(sni: impl Into<String>) -> Result<Self, TransportError> {
        Self::new(TransportConfig::default(), BrowserProfile::Firefox, sni)
    }

    /// Create with Safari fingerprint
    pub fn safari(sni: impl Into<String>) -> Result<Self, TransportError> {
        Self::new(TransportConfig::default(), BrowserProfile::Safari, sni)
    }

    /// Create with random browser fingerprint
    pub fn random(sni: impl Into<String>) -> Result<Self, TransportError> {
        Self::new(TransportConfig::default(), BrowserProfile::Random, sni)
    }

    /// Get the browser profile being used
    pub fn profile(&self) -> BrowserProfile {
        self.profile
    }

    /// Get the SNI being used
    pub fn sni(&self) -> &str {
        &self.sni
    }

    /// Get the User-Agent string for this profile
    pub fn user_agent(&self) -> &'static str {
        self.profile.user_agent()
    }
}

#[async_trait]
impl Transport for TlsTransport {
    async fn connect(&mut self, addr: &str) -> Result<(), TransportError> {
        let timeout = std::time::Duration::from_secs(self.config.connect_timeout);

        // Connect TCP
        let tcp_stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(TransportError::Io)?;

        // Configure TCP options
        tcp_stream.set_nodelay(true).ok();

        // Create TLS connector
        let connector = TlsConnector::from(self.tls_config.clone());

        // Parse SNI (this is what appears in the ClientHello)
        let server_name = ServerName::try_from(self.sni.clone())
            .map_err(|e| TransportError::Tls(format!("Invalid SNI: {}", e)))?;

        // Perform TLS handshake with browser-mimicked fingerprint
        let tls_stream = tokio::time::timeout(
            timeout,
            connector.connect(server_name, tcp_stream),
        )
        .await
        .map_err(|_| TransportError::Timeout)?
        .map_err(|e| TransportError::Tls(e.to_string()))?;

        self.stream = Some(tls_stream);
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        let stream = self.stream.as_mut().ok_or(TransportError::Closed)?;

        let timeout = std::time::Duration::from_secs(self.config.write_timeout);

        tokio::time::timeout(timeout, stream.write_all(data))
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(TransportError::Io)?;

        Ok(())
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        let stream = self.stream.as_mut().ok_or(TransportError::Closed)?;

        let timeout = std::time::Duration::from_secs(self.config.read_timeout);

        let n = tokio::time::timeout(timeout, stream.read(buf))
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(TransportError::Io)?;

        if n == 0 {
            return Err(TransportError::Closed);
        }

        Ok(n)
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        if let Some(mut stream) = self.stream.take() {
            stream.shutdown().await.ok();
        }
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.stream.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_transports() {
        // Should be able to create transports with different profiles
        let chrome = TlsTransport::chrome("example.com").unwrap();
        assert_eq!(chrome.profile(), BrowserProfile::Chrome);
        assert!(chrome.user_agent().contains("Chrome"));

        let firefox = TlsTransport::firefox("example.com").unwrap();
        assert_eq!(firefox.profile(), BrowserProfile::Firefox);
        assert!(firefox.user_agent().contains("Firefox"));

        let safari = TlsTransport::safari("example.com").unwrap();
        assert_eq!(safari.profile(), BrowserProfile::Safari);
        assert!(safari.user_agent().contains("Safari"));
    }

    #[test]
    fn test_sni() {
        let transport = TlsTransport::chrome("www.google.com").unwrap();
        assert_eq!(transport.sni(), "www.google.com");
    }
}
