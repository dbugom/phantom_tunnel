//! Optional QUIC transport.
//!
//! Tries QUIC (UDP 443) first with a 3-second timeout,
//! then falls back to TCP+TLS+H2 if QUIC is blocked.
//!
//! QUIC advantages:
//! - No head-of-line blocking (each stream is independent)
//! - Connection migration (survives network changes)
//! - Built-in TLS 1.3
//!
//! QUIC disadvantages:
//! - Blocked on many enterprise networks (WatchGuard, Palo Alto, etc.)
//! - GFW (China) actively blocks QUIC
//! - UDP 443 may be firewalled
//!
//! This module is feature-gated behind `quic` and is NOT included in the
//! default feature set because QUIC is targeted by DPI firewalls.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Endpoint, ServerConfig as QuinnServerConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, warn};

/// Default QUIC connection timeout before falling back to TCP
const QUIC_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Build a QUIC client config with TLS 1.3
fn build_client_config() -> ClientConfig {
    let crypto = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        })
        .with_no_client_auth();

    ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .expect("valid QUIC client config"),
    ))
}

/// Connect to a server via QUIC with a timeout.
///
/// Returns the bidirectional QUIC stream if successful, or an error.
/// The caller should fall back to TCP+TLS if this fails.
pub async fn connect_quic(
    server_addr: SocketAddr,
    server_name: &str,
) -> anyhow::Result<(quinn::RecvStream, quinn::SendStream)> {
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(build_client_config());

    let connection = tokio::time::timeout(
        QUIC_CONNECT_TIMEOUT,
        endpoint.connect(server_addr, server_name)?,
    )
    .await
    .map_err(|_| anyhow::anyhow!("QUIC connection timeout ({}s)", QUIC_CONNECT_TIMEOUT.as_secs()))?
    .map_err(|e| anyhow::anyhow!("QUIC connection failed: {}", e))?;

    info!("QUIC connection established to {}", server_addr);

    // Open a bidirectional stream for the tunnel
    let (send, recv) = connection.open_bi().await?;
    debug!("QUIC bidirectional stream opened");

    Ok((recv, send))
}

/// Try QUIC first, fall back to TCP+TLS if QUIC is blocked or times out.
///
/// Returns a pair of (AsyncRead, AsyncWrite) trait objects.
pub async fn connect_quic_or_log(
    server_addr: SocketAddr,
    server_name: &str,
) -> Option<(quinn::RecvStream, quinn::SendStream)> {
    match connect_quic(server_addr, server_name).await {
        Ok(streams) => {
            info!("Connected via QUIC");
            Some(streams)
        }
        Err(e) => {
            debug!("QUIC unavailable ({}), caller should use TCP+TLS fallback", e);
            None
        }
    }
}
