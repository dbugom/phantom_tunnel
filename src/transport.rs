//! Pluggable outer transport: the camouflage layer.
//!
//! The tunnel's own protocol — the length-prefixed Noise ciphertext described
//! in [`crate::tunnel`] — is a byte stream. This module decides what that byte
//! stream *looks like* on the wire, without changing a single byte of it:
//!
//! - [`ClientTransport::Plain`] / [`ServerTransport::Plain`]: the bytes go
//!   straight over TCP. Fast, but recognisable: an observer sees high-entropy
//!   data from the first byte, which modern censors (e.g. the GFW's 2023
//!   "fully encrypted traffic" classifier) flag precisely because it has no
//!   plaintext structure. This is the default, for compatibility.
//!
//! - [`ClientTransport::WebSocket`] / [`ServerTransport::WebSocket`]: the bytes
//!   are carried inside a WebSocket, optionally wrapped in real TLS. Pointed at
//!   a reverse proxy (Caddy, nginx) on a real HTTPS domain, the connection is
//!   genuine TLS to that domain with a real certificate, and the tunnel is one
//!   WebSocket path among the site's normal traffic. There is nothing to
//!   fingerprint because it is not an imitation of HTTPS — it *is* HTTPS to a
//!   real site, and an active probe of any other path gets the real website.
//!
//! The Noise handshake, mutual authentication, flow control and UDP all run
//! unchanged on top of whichever transport is selected. Camouflage is a pure
//! outer wrapper.
//!
//! TLS uses `rustls` with the *ring* crypto backend (the same crypto the rest
//! of the crate already builds), chosen so the clients still cross-compile to
//! every target.

use std::sync::Arc;

use anyhow::{Context, Result};
use async_tungstenite::tokio::{accept_async, client_async};
use async_tungstenite::tungstenite::client::IntoClientRequest;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use ws_stream_tungstenite::WsStream;

/// Boxed read half of an established transport.
pub type BoxedRead = Box<dyn tokio::io::AsyncRead + Unpin + Send>;
/// Boxed write half of an established transport.
pub type BoxedWrite = Box<dyn tokio::io::AsyncWrite + Unpin + Send>;

/// How the client dresses up the tunnel on the wire.
#[derive(Clone, Debug)]
pub enum ClientTransport {
    /// Raw length-prefixed Noise over TCP.
    Plain,
    /// Noise carried inside a WebSocket (optionally over TLS).
    WebSocket(WsClient),
}

/// WebSocket client settings.
#[derive(Clone, Debug)]
pub struct WsClient {
    /// Wrap the connection in TLS (`wss`). False means plain `ws`, for when a
    /// local terminator already provides TLS.
    pub tls: bool,
    /// Request path, e.g. `/relay`. The reverse proxy routes this path to the
    /// tunnel and everything else to the real website.
    pub path: String,
    /// TLS server name (SNI). Normally the real domain.
    pub sni: String,
    /// HTTP `Host` header. Normally the same as `sni`.
    pub host: String,
    /// Skip TLS certificate verification. Only for self-signed test servers or
    /// pinning-free setups; never for real deployments.
    pub insecure: bool,
}

/// How the server expects the tunnel to arrive.
#[derive(Clone, Debug)]
pub enum ServerTransport {
    /// Raw length-prefixed Noise over TCP.
    Plain,
    /// A WebSocket (TLS is terminated upstream by the reverse proxy, so the
    /// server speaks plain `ws`).
    WebSocket,
}

/// Connect to `dial_addr` and return the tunnel byte-stream halves.
///
/// `dial_addr` is the `host:port` actually dialed over TCP (e.g. the reverse
/// proxy on `:443`); the TLS SNI and HTTP Host come from [`WsClient`], so the
/// dialed address and the presented domain can differ (e.g. dialing by IP).
pub async fn connect_client(
    transport: &ClientTransport,
    dial_addr: &str,
) -> Result<(BoxedRead, BoxedWrite)> {
    let tcp = TcpStream::connect(dial_addr)
        .await
        .with_context(|| format!("TCP connect to {dial_addr}"))?;
    // Small request/response frames: Nagle would add ~40ms delayed-ACK stalls.
    tcp.set_nodelay(true).ok();

    match transport {
        ClientTransport::Plain => {
            let (r, w) = tcp.into_split();
            Ok((Box::new(r), Box::new(w)))
        }
        ClientTransport::WebSocket(ws) => {
            let url = format!("ws://{}{}", ws.host, ws.path);
            let request = url
                .as_str()
                .into_client_request()
                .with_context(|| format!("build WebSocket request for {url}"))?;
            if ws.tls {
                let connector = tls_connector(ws.insecure)?;
                let server_name = rustls::pki_types::ServerName::try_from(ws.sni.clone())
                    .with_context(|| format!("invalid TLS server name {:?}", ws.sni))?;
                let tls = connector
                    .connect(server_name, tcp)
                    .await
                    .context("TLS handshake")?;
                let (sock, _resp) = client_async(request, tls)
                    .await
                    .context("WebSocket handshake")?;
                Ok(split_boxed(WsStream::new(sock)))
            } else {
                let (sock, _resp) = client_async(request, tcp)
                    .await
                    .context("WebSocket handshake")?;
                Ok(split_boxed(WsStream::new(sock)))
            }
        }
    }
}

/// Accept an incoming tunnel connection on an already-accepted TCP stream.
pub async fn accept_server(
    transport: &ServerTransport,
    stream: TcpStream,
) -> Result<(BoxedRead, BoxedWrite)> {
    match transport {
        ServerTransport::Plain => {
            let (r, w) = stream.into_split();
            Ok((Box::new(r), Box::new(w)))
        }
        ServerTransport::WebSocket => {
            let sock = accept_async(stream)
                .await
                .context("WebSocket accept handshake")?;
            Ok(split_boxed(WsStream::new(sock)))
        }
    }
}

/// Split any duplex stream into boxed tunnel halves.
fn split_boxed<S>(stream: S) -> (BoxedRead, BoxedWrite)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (r, w) = tokio::io::split(stream);
    (Box::new(r), Box::new(w))
}

/// Build a rustls TLS connector on the ring backend.
///
/// ALPN offers only `http/1.1`: the WebSocket upgrade is an HTTP/1.1 mechanism,
/// so negotiating HTTP/2 (which a browser would also offer) would break the
/// upgrade through a reverse proxy.
fn tls_connector(insecure: bool) -> Result<TlsConnector> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("rustls protocol versions")?;

    let mut config = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(danger::NoVerifier::new()))
            .with_no_client_auth()
    } else {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsConnector::from(Arc::new(config)))
}

/// A certificate verifier that accepts anything. Used only when the operator
/// explicitly sets `insecure = true` (self-signed test servers). It disables
/// server authentication, so it must never be used against a real server.
mod danger {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::{ring, CryptoProvider};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    pub struct NoVerifier(CryptoProvider);

    impl NoVerifier {
        pub fn new() -> Self {
            Self(ring::default_provider())
        }
    }

    impl ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
}
