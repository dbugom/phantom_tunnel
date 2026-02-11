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
use tracing::{debug, error, info};

/// Target authority for the CONNECT request.
/// This should look like a legitimate destination to DPI.
const CONNECT_AUTHORITY: &str = "api.google.com:443";

// ============================================================
// Channel-based AsyncRead/AsyncWrite adapters for H2 streams
// ============================================================

/// AsyncRead adapter backed by an mpsc channel receiving Bytes from H2 RecvStream.
pub struct ChannelReader {
    rx: mpsc::Receiver<Bytes>,
    buf: BytesMut,
}

impl ChannelReader {
    pub fn new(rx: mpsc::Receiver<Bytes>) -> Self {
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

/// AsyncWrite adapter that sends Bytes over an mpsc channel to H2 SendStream.
pub struct ChannelWriter {
    tx: mpsc::Sender<Bytes>,
}

impl ChannelWriter {
    pub fn new(tx: mpsc::Sender<Bytes>) -> Self {
        Self { tx }
    }
}

impl AsyncWrite for ChannelWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let data = Bytes::copy_from_slice(buf);
        let len = data.len();

        // Try to send via channel
        match this.tx.try_send(data) {
            Ok(()) => Poll::Ready(Ok(len)),
            Err(mpsc::error::TrySendError::Full(_data)) => {
                // Channel full — register waker and retry
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "H2 write channel closed",
                )))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// ============================================================
// CLIENT SIDE
// ============================================================

/// Wraps a TLS stream in HTTP/2 and opens a CONNECT tunnel.
/// Returns (ChannelReader, ChannelWriter) that implement AsyncRead/AsyncWrite
/// for the Noise Protocol handshake and subsequent tunnel frames.
pub async fn client_h2_connect<T>(
    tls_stream: T,
) -> anyhow::Result<(ChannelReader, ChannelWriter)>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Perform HTTP/2 handshake with Chrome-like SETTINGS
    let (send_request, connection) = h2::client::Builder::new()
        .initial_window_size(6_291_456) // Chrome: 6MB
        .initial_connection_window_size(15_728_640) // Chrome: 15MB
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

    // Bridge H2 streams to AsyncRead/AsyncWrite via channels
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
) -> anyhow::Result<Option<(ChannelReader, ChannelWriter)>>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut connection = h2::server::Builder::new()
        .initial_window_size(6_291_456)
        .initial_connection_window_size(15_728_640)
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
            // Not a CONNECT — respond with 404 (looks like a normal web server)
            let response = http::Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(())
                .unwrap();
            respond.send_response(response, true)?;
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
    // Without this, dropping `connection` kills all streams immediately
    // (causing "stream closed because of a broken pipe").
    tokio::spawn(async move {
        while let Some(result) = connection.accept().await {
            match result {
                Ok((_req, mut respond)) => {
                    // Reject any additional streams with 404
                    let response = http::Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(())
                        .unwrap();
                    let _ = respond.send_response(response, true);
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
// H2 <-> AsyncRead/AsyncWrite bridge
// ============================================================

/// Create an AsyncRead/AsyncWrite pair backed by H2 send/recv streams.
/// Spawns background tasks to pump data between H2 and channels.
fn h2_to_async_io(
    mut h2_send: h2::SendStream<Bytes>,
    mut h2_recv: RecvStream,
) -> anyhow::Result<(ChannelReader, ChannelWriter)> {
    // Read side: H2 recv -> channel -> AsyncRead
    let (read_tx, read_rx) = mpsc::channel::<Bytes>(64);
    tokio::spawn(async move {
        loop {
            match h2_recv.data().await {
                Some(Ok(data)) => {
                    // Release flow control capacity
                    let _ = h2_recv.flow_control().release_capacity(data.len());
                    if read_tx.send(data).await.is_err() {
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

    // Write side: AsyncWrite -> channel -> H2 send
    let (write_tx, mut write_rx) = mpsc::channel::<Bytes>(64);
    tokio::spawn(async move {
        while let Some(data) = write_rx.recv().await {
            // Reserve capacity before sending
            h2_send.reserve_capacity(data.len());

            // Wait for flow control capacity
            loop {
                let cap = h2_send.capacity();
                if cap > 0 {
                    break;
                }
                tokio::task::yield_now().await;
                h2_send.reserve_capacity(data.len());
            }

            if let Err(e) = h2_send.send_data(data, false) {
                debug!("H2 send error: {e}");
                break;
            }
        }
        // End of stream
        let _ = h2_send.send_data(Bytes::new(), true);
    });

    let reader = ChannelReader::new(read_rx);
    let writer = ChannelWriter::new(write_tx);

    Ok((reader, writer))
}
