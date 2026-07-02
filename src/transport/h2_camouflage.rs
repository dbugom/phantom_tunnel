//! HTTP/2 CONNECT camouflage layer.
//!
//! Wraps the Noise Protocol tunnel inside an HTTP/2 CONNECT request,
//! making post-TLS traffic look like a browser proxying through HTTPS.
//!
//! Stack: TCP -> TLS (Chrome fingerprint) -> HTTP/2 CONNECT -> Noise -> Frames
//!
//! The Noise-encrypted frames are carried as HTTP/2 DATA frames within
//! a long-lived CONNECT tunnel, making them indistinguishable from a
//! browser using an HTTPS proxy.

use bytes::{Bytes, BytesMut};
use h2::RecvStream;
use http::{Method, StatusCode};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::probe_resistance;

/// Target authority for the CONNECT request.
/// This should look like a legitimate destination to DPI.
const CONNECT_AUTHORITY: &str = "api.google.com:443";

// ============================================================
// AsyncRead adapter (channel-based, for H2 RecvStream)
// ============================================================

/// AsyncRead adapter backed by an unbounded mpsc channel receiving Bytes from H2 RecvStream.
/// Unbounded so the H2 recv task never blocks — H2 flow control limits data on the wire.
pub struct ChannelReader {
    rx: mpsc::UnboundedReceiver<Bytes>,
    buf: BytesMut,
}

impl ChannelReader {
    pub fn new(rx: mpsc::UnboundedReceiver<Bytes>) -> Self {
        Self {
            rx,
            buf: BytesMut::new(),
        }
    }
}

impl AsyncRead for ChannelReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // Return buffered data first
        if !this.buf.is_empty() {
            let n = std::cmp::min(buf.remaining(), this.buf.len());
            buf.put_slice(&this.buf.split_to(n));
            return Poll::Ready(Ok(()));
        }

        // Poll channel for more data
        match this.rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                if data.len() <= buf.remaining() {
                    buf.put_slice(&data);
                } else {
                    let n = buf.remaining();
                    buf.put_slice(&data[..n]);
                    this.buf.extend_from_slice(&data[n..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                // Channel closed = EOF
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

// ============================================================
// AsyncWrite adapter (direct H2 SendStream, no channel)
// ============================================================

/// AsyncWrite adapter wrapping H2 SendStream directly.
/// Uses poll_capacity() for proper async flow control instead of busy-polling.
/// Eliminates the channel + spawned task overhead of the old ChannelWriter.
pub struct H2Writer {
    h2_send: h2::SendStream<Bytes>,
}

impl H2Writer {
    pub fn new(h2_send: h2::SendStream<Bytes>) -> Self {
        Self { h2_send }
    }
}

impl AsyncWrite for H2Writer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        // Tell H2 how much we want to send
        this.h2_send.reserve_capacity(buf.len());

        // Wait for flow control capacity using proper async polling
        match this.h2_send.poll_capacity(cx) {
            Poll::Ready(Some(Ok(cap))) => {
                // Send up to available capacity (write_all handles partial writes)
                let n = std::cmp::min(cap, buf.len());
                let data = Bytes::copy_from_slice(&buf[..n]);
                match this.h2_send.send_data(data, false) {
                    Ok(()) => Poll::Ready(Ok(n)),
                    Err(e) => Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("H2 send error: {e}"),
                    ))),
                }
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("H2 capacity error: {e}"),
            ))),
            Poll::Ready(None) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "H2 send stream closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let _ = this.h2_send.send_data(Bytes::new(), true);
        Poll::Ready(Ok(()))
    }
}

// ============================================================
// CLIENT SIDE
// ============================================================

/// Wraps a TLS stream in HTTP/2 and opens a CONNECT tunnel.
/// Returns (ChannelReader, H2Writer) that implement AsyncRead/AsyncWrite
/// for the Noise Protocol handshake and subsequent tunnel frames.
pub async fn client_h2_connect<T>(
    tls_stream: T,
) -> anyhow::Result<(ChannelReader, H2Writer)>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Perform HTTP/2 handshake with Chrome-like SETTINGS
    // Window sizes set to 16MB to prevent flow control stalls in long-lived tunnels.
    // The h2 crate only sends WINDOW_UPDATE after release_capacity() is called AND
    // the connection future is polled — small windows exhaust before updates arrive.
    let (send_request, connection) = h2::client::Builder::new()
        .initial_window_size(16 * 1024 * 1024) // 16MB stream window
        .initial_connection_window_size(16 * 1024 * 1024) // 16MB connection window
        .max_frame_size(16_384) // Chrome default
        .max_header_list_size(262_144) // 256KB
        .header_table_size(65_536) // 64KB
        .enable_push(false) // Chrome disables push
        .handshake(tls_stream)
        .await?;

    // Spawn the H2 connection driver
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            // Don't log as error if it's a clean close
            if !e.is_go_away() && !e.is_io() {
                error!("H2 client connection error: {e}");
            } else {
                debug!("H2 client connection closed: {e}");
            }
        }
    });

    // Send CONNECT request (looks like browser proxy request)
    let request = http::Request::builder()
        .method(Method::CONNECT)
        .uri(CONNECT_AUTHORITY)
        .version(http::Version::HTTP_2)
        .body(())
        .expect("valid CONNECT request");

    let mut send_request = send_request.ready().await?;
    let (response_future, send_stream) = send_request.send_request(request, false)?;

    // Wait for 200 OK
    let response = response_future.await?;
    if response.status() != StatusCode::OK {
        anyhow::bail!("H2 CONNECT rejected with status: {}", response.status());
    }

    let recv_stream = response.into_body();

    info!("H2 CONNECT tunnel established to {CONNECT_AUTHORITY}");

    // Bridge H2 streams to AsyncRead/AsyncWrite
    h2_to_async_io(send_stream, recv_stream)
}

// ============================================================
// SERVER SIDE
// ============================================================

/// Accept an HTTP/2 connection and wait for a CONNECT request.
/// Returns the AsyncRead/AsyncWrite pair for the tunnel, or None if
/// no valid CONNECT was received (caller should proxy to decoy).
pub async fn server_h2_accept<T>(
    tls_stream: T,
) -> anyhow::Result<Option<(ChannelReader, H2Writer)>>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut connection = h2::server::Builder::new()
        .initial_window_size(16 * 1024 * 1024) // 16MB stream window
        .initial_connection_window_size(16 * 1024 * 1024) // 16MB connection window
        .max_frame_size(16_384)
        .max_header_list_size(262_144)
        .handshake::<T, Bytes>(tls_stream)
        .await?;

    // Wait for the first valid CONNECT request.
    // Use loop+match so `connection` can be moved into spawn after break.
    let (send_stream, recv_stream) = loop {
        let result = match connection.accept().await {
            Some(r) => r?,
            None => return Ok(None), // Connection closed without CONNECT
        };

        let (request, mut respond) = result;

        if request.method() != Method::CONNECT {
            // Not a CONNECT — serve realistic decoy page (looks like nginx)
            warn!("Non-CONNECT request (possible probe): {} {}", request.method(), request.uri());
            serve_decoy_response(request.method(), request.uri().path(), respond)?;
            continue;
        }

        debug!("H2 CONNECT request to {}", request.uri());

        // Accept CONNECT — auth happens at the Noise layer
        let response = http::Response::builder()
            .status(StatusCode::OK)
            .body(())
            .unwrap();

        let send_stream = respond.send_response(response, false)?;
        let recv_stream = request.into_body();
        break (send_stream, recv_stream);
    };

    // CRITICAL: Spawn the H2 connection driver in the background.
    // The h2::server::Connection drives all I/O for H2 streams.
    // Without this, dropping `connection` kills all streams immediately.
    tokio::spawn(async move {
        while let Some(result) = connection.accept().await {
            match result {
                Ok((req, respond)) => {
                    // Serve decoy page for any additional requests
                    let _ = serve_decoy_response(req.method(), req.uri().path(), respond);
                }
                Err(e) => {
                    debug!("H2 server connection driver error: {e}");
                    break;
                }
            }
        }
    });

    let (reader, writer) = h2_to_async_io(send_stream, recv_stream)?;
    Ok(Some((reader, writer)))
}

// ============================================================
// Decoy response for non-CONNECT requests
// ============================================================

/// Serve a realistic nginx-like response for non-CONNECT requests.
/// Makes the server indistinguishable from a normal web server to probers.
fn serve_decoy_response(
    method: &Method,
    path: &str,
    mut respond: h2::server::SendResponse<Bytes>,
) -> anyhow::Result<()> {
    let server_header = "nginx/1.24.0";

    match *method {
        Method::GET | Method::HEAD => {
            let (status, body_html) = if path == "/" {
                (StatusCode::OK, probe_resistance::decoy_index_html())
            } else {
                (StatusCode::NOT_FOUND, probe_resistance::decoy_404_html())
            };

            let response = http::Response::builder()
                .status(status)
                .header("server", server_header)
                .header("content-type", "text/html")
                .header("content-length", body_html.len().to_string())
                .body(())
                .unwrap();

            let is_head = *method == Method::HEAD;
            let mut send_stream = respond.send_response(response, is_head)?;
            if !is_head {
                send_stream.send_data(Bytes::from(body_html), true)?;
            }
        }
        _ => {
            // POST, PUT, DELETE, etc → 405 Method Not Allowed
            let response = http::Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .header("server", server_header)
                .header("allow", "GET, HEAD")
                .header("content-length", "0")
                .body(())
                .unwrap();
            respond.send_response(response, true)?;
        }
    }

    Ok(())
}

// ============================================================
// H2 <-> AsyncRead/AsyncWrite bridge
// ============================================================

/// Create an AsyncRead/AsyncWrite pair backed by H2 send/recv streams.
///
/// Read side: spawns a background task pumping H2 RecvStream -> mpsc -> ChannelReader
/// (channel needed because RecvStream::data() is async-only, no poll variant).
///
/// Write side: wraps H2 SendStream directly in H2Writer using poll_capacity()
/// (no channel, no spawned task — eliminates the busy-poll bottleneck).
fn h2_to_async_io(
    h2_send: h2::SendStream<Bytes>,
    mut h2_recv: RecvStream,
) -> anyhow::Result<(ChannelReader, H2Writer)> {
    // Read side: H2 recv -> unbounded channel -> AsyncRead
    // Unbounded so this task never blocks on send — H2 flow control on the wire
    // limits how much data can be in-flight, bounding memory naturally.
    let (read_tx, read_rx) = mpsc::unbounded_channel::<Bytes>();
    // Clone the FlowControl handle BEFORE entering the recv loop.
    // In h2 v0.4, flow_control() returns by value — calling it inside the loop
    // after data() has been called can return a stale snapshot. Cloning once
    // ensures release_capacity() always targets the live flow control state,
    // so WINDOW_UPDATE frames are actually queued and sent by the connection driver.
    let mut flow_ctl = h2_recv.flow_control().clone();
    tokio::spawn(async move {
        loop {
            match h2_recv.data().await {
                Some(Ok(data)) => {
                    let len = data.len();
                    // Forward data to channel first, then release capacity.
                    // Even if the channel send fails, we still release capacity
                    // to avoid leaking flow control budget.
                    let send_ok = read_tx.send(data).is_ok();
                    // Release flow control capacity so the h2 connection driver
                    // sends WINDOW_UPDATE to the peer, replenishing their send budget.
                    if let Err(e) = flow_ctl.release_capacity(len) {
                        debug!("H2 release_capacity failed ({len}B): {e}");
                        break;
                    }
                    if !send_ok {
                        break;
                    }
                }
                Some(Err(e)) => {
                    debug!("H2 recv error: {e}");
                    break;
                }
                None => {
                    // Stream ended
                    break;
                }
            }
        }
    });

    // Write side: direct H2 SendStream wrapper (no channel, no spawned task)
    let writer = H2Writer::new(h2_send);
    let reader = ChannelReader::new(read_rx);

    Ok((reader, writer))
}
