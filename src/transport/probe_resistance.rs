//! Active probing resistance.
//!
//! When authentication fails (H2 handshake fails, non-CONNECT request, or
//! Noise handshake fails), proxy the connection to a decoy website so the
//! server looks like a legitimate HTTPS server to active probers.
//!
//! Critical behaviors:
//! 1. Never close connections on auth failure — always proxy to decoy or hold open
//! 2. Never send distinguishable error messages — use standard HTTP error codes
//! 3. Match server timing — don't respond faster/slower than the decoy
//! 4. Log probe attempts at warn level for monitoring

use tokio::io::{copy_bidirectional, AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tracing::{debug, warn};

/// Default decoy backend address (local Caddy/nginx serving a real website)
const DEFAULT_DECOY_BACKEND: &str = "127.0.0.1:8443";

/// Proxy an unauthorized connection to the decoy backend.
/// This makes the server look like a normal web server to active probers.
///
/// If `decoy_backend` is None, falls back to holding the connection open
/// briefly before closing (still better than immediately closing).
pub async fn proxy_to_decoy<T>(
    mut stream: T,
    decoy_backend: Option<&str>,
) -> anyhow::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    let backend_addr = decoy_backend.unwrap_or(DEFAULT_DECOY_BACKEND);
    debug!("Proxying unauthorized connection to decoy backend {}", backend_addr);

    match TcpStream::connect(backend_addr).await {
        Ok(mut backend) => {
            // Silently proxy all data bidirectionally
            let _ = copy_bidirectional(&mut stream, &mut backend).await;
            Ok(())
        }
        Err(e) => {
            // Decoy backend unavailable — hold connection open briefly
            // to avoid revealing the server's true nature through timing
            warn!("Decoy backend {} unavailable: {}", backend_addr, e);
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            Ok(())
        }
    }
}
