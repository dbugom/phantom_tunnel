//! Phantom Tunnel Server
//!
//! A secure, censorship-resistant tunnel server that:
//! - Accepts client connections over TLS
//! - Performs Noise Protocol handshake
//! - Multiplexes streams to target destinations
//! - Resists active probing attacks

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use phantom_tunnel::{
    config::Config,
    crypto::{KeyPair, NoiseHandshake, NoiseTransport, PrivateKey, PublicKey},
    tunnel::{Frame, FrameType, Multiplexer},
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tracing::{debug, error, info, trace, warn};

/// Grace period for draining streams before full removal
const STREAM_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Phantom Tunnel Server - Secure, censorship-resistant tunnel
#[derive(Parser, Debug)]
#[command(name = "phantom-server")]
#[command(about = "Phantom Tunnel Server - Secure, censorship-resistant tunneling")]
#[command(version)]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// Generate new keypair and exit
    #[arg(long)]
    generate_key: bool,

    /// Listen address (overrides config)
    #[arg(short, long)]
    listen: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short = 'v', long, default_value = "info")]
    log_level: String,
}

/// Server state shared across connections
struct ServerState {
    /// Server's keypair
    keypair: KeyPair,
    /// Allowed client public keys
    allowed_clients: HashSet<String>,
    /// Connection semaphore for limiting concurrent connections
    conn_semaphore: Semaphore,
}

/// Command to send data back through the tunnel
enum StreamToTunnel {
    /// Data to send on a stream
    Data { stream_id: u32, data: bytes::Bytes },
    /// Stream closed
    Close { stream_id: u32 },
}

/// Active stream with channel to send data to it
struct ActiveStream {
    data_tx: mpsc::Sender<bytes::Bytes>,
    /// If Some, the stream is draining (closed by client, waiting for cleanup)
    draining_since: Option<Instant>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(&args.log_level)
        .init();

    // Generate key if requested
    if args.generate_key {
        return generate_keypair();
    }

    // Load configuration
    let mut config = Config::load(&args.config).context("Failed to load configuration")?;

    let server_config = config
        .server
        .clone()
        .ok_or_else(|| anyhow!("No [server] section in config file"))?;

    // Parse or generate server keypair
    let keypair = if server_config.private_key.is_empty() {
        // No keys configured - generate new keypair and save to config
        info!("No keypair configured - generating new keypair...");
        let new_keypair = KeyPair::generate()?;

        // Update config with new keys
        if let Some(ref mut server) = config.server {
            server.private_key = new_keypair.private.to_base64();
            server.public_key = new_keypair.public.to_base64();
        }

        // Save updated config
        config.save(&args.config).context("Failed to save config with new keypair")?;
        info!("Generated and saved new keypair to config file");
        info!("Share this public key with clients: {}", new_keypair.public.to_base64());

        new_keypair
    } else {
        // Load existing keypair from config
        let private_key = PrivateKey::from_base64(&server_config.private_key)
            .context("Invalid private key format")?;

        let public_key = if server_config.public_key.is_empty() {
            // Old config without public key - we can't derive it, so error
            error!("Config has private_key but no public_key");
            error!("Please regenerate keys or add public_key to config");
            return Err(anyhow!("Missing public_key in config"));
        } else {
            PublicKey::from_base64(&server_config.public_key)
                .context("Invalid public key format")?
        };

        KeyPair {
            public: public_key,
            private: private_key,
        }
    };

    // Parse allowed clients
    let allowed_clients: HashSet<String> = server_config.allowed_clients.into_iter().collect();

    if allowed_clients.is_empty() {
        warn!("No allowed_clients configured - server will reject all connections");
    } else {
        info!("Loaded {} allowed client(s)", allowed_clients.len());
    }

    // Create server state
    let state = Arc::new(ServerState {
        keypair,
        allowed_clients,
        conn_semaphore: Semaphore::new(server_config.max_connections),
    });

    // Build TLS acceptor if cert/key are configured
    let tls_acceptor = match (server_config.tls_cert, server_config.tls_key) {
        (Some(cert_path), Some(key_path)) => {
            let certs = load_certs(&cert_path)
                .context("Failed to load TLS certificate")?;
            let key = load_private_key(&key_path)
                .context("Failed to load TLS private key")?;

            let tls_config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .context("Failed to build TLS server config")?;

            info!("TLS enabled with cert: {}", cert_path);
            Some(Arc::new(tokio_rustls::TlsAcceptor::from(Arc::new(tls_config))))
        }
        _ => {
            info!("TLS disabled (no tls_cert/tls_key configured)");
            None
        }
    };

    // Determine listen address
    let listen_addr = args.listen.unwrap_or(server_config.listen);

    // Start server
    info!("Phantom Tunnel Server v{}", phantom_tunnel::VERSION);
    info!("Listening on {}", listen_addr);
    info!("Server public key: {}", state.keypair.public.to_base64());

    let listener = TcpListener::bind(&listen_addr)
        .await
        .context("Failed to bind to address")?;

    // Accept connections
    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, peer_addr)) => {
                        debug!("New connection from {}", peer_addr);

                        let state = Arc::clone(&state);
                        let acceptor = tls_acceptor.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, state, acceptor).await {
                                debug!("Connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Accept error: {}", e);
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Shutting down...");
                break;
            }
        }
    }

    Ok(())
}

/// Load TLS certificate chain from PEM file
fn load_certs(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let mut file = std::io::BufReader::new(
        std::fs::File::open(path)
            .context(format!("Failed to open cert file: {}", path))?
    );
    let certs: Vec<_> = rustls_pemfile::certs(&mut file)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("Failed to parse PEM certificates")?;
    if certs.is_empty() {
        return Err(anyhow!("No certificates found in {}", path));
    }
    info!("Loaded {} certificate(s) from {}", certs.len(), path);
    Ok(certs)
}

/// Load TLS private key from PEM file
fn load_private_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let mut file = std::io::BufReader::new(
        std::fs::File::open(path)
            .context(format!("Failed to open key file: {}", path))?
    );
    rustls_pemfile::private_key(&mut file)
        .context("Failed to parse PEM private key")?
        .ok_or_else(|| anyhow!("No private key found in {}", path))
}

/// Generate and print a new keypair
fn generate_keypair() -> Result<()> {
    let keypair = KeyPair::generate()?;

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║              Phantom Tunnel Keypair Generated                ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║ PUBLIC KEY (share with clients):                             ║");
    println!("║ {}  ║", keypair.public.to_base64());
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║ PRIVATE KEY (keep secret, add to server config):             ║");
    println!("║ {}  ║", keypair.private.to_base64());
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("Add to your server config.toml:");
    println!("  private_key = \"{}\"", keypair.private.to_base64());
    println!();
    println!("Share with clients:");
    println!("  server_public_key = \"{}\"", keypair.public.to_base64());

    Ok(())
}

/// Message from the reader task
enum ReaderMessage {
    /// Encrypted frame data received
    Frame(Vec<u8>),
    /// Reader encountered an error
    Error(String),
    /// Connection closed
    Closed,
}

/// Handle a single client connection
async fn handle_connection(
    stream: TcpStream,
    state: Arc<ServerState>,
    tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>>,
) -> Result<()> {
    // Acquire connection permit (clone Arc first so we can move state into inner fn)
    let inner_state = Arc::clone(&state);
    let _permit = state
        .conn_semaphore
        .acquire()
        .await
        .context("Failed to acquire connection permit")?;

    // Disable Nagle's algorithm to avoid delays on small writes (control frames, length prefixes)
    stream.set_nodelay(true)?;

    if let Some(acceptor) = tls_acceptor {
        // TLS wrapping enabled
        let tls_stream = acceptor.accept(stream)
            .await
            .context("TLS accept failed")?;
        debug!("TLS handshake complete with client");

        let (read_half, write_half) = tokio::io::split(tls_stream);
        handle_connection_inner(read_half, write_half, inner_state).await
    } else {
        // Raw TCP (backward compat)
        let (read_half, write_half) = stream.into_split();
        handle_connection_inner(read_half, write_half, inner_state).await
    }
}

/// Inner connection handler, generic over transport read/write halves
async fn handle_connection_inner<R, W>(
    mut read_half: R,
    mut write_half: W,
    state: Arc<ServerState>,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    // Perform Noise handshake
    let (mut noise_transport, client_public) =
        perform_handshake_split(&mut read_half, &mut write_half, &state.keypair).await?;

    // Verify client is allowed
    let client_key_b64 = client_public.to_base64();
    if !state.allowed_clients.is_empty() && !state.allowed_clients.contains(&client_key_b64) {
        warn!("Rejected unknown client: {}...", &client_key_b64[..16]);
        return Err(anyhow!("Client not in allowed list"));
    }

    info!("Client connected: {}...", &client_key_b64[..16]);

    // Create channel for reader task to send frames to main loop
    let (reader_tx, mut reader_rx) = mpsc::channel::<ReaderMessage>(256);

    // Spawn dedicated reader task - this will NOT be cancelled by select!
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            // Read length prefix
            let mut len_buf = [0u8; 2];
            if let Err(e) = read_half.read_exact(&mut len_buf).await {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    let _ = reader_tx.send(ReaderMessage::Closed).await;
                } else {
                    let _ = reader_tx.send(ReaderMessage::Error(e.to_string())).await;
                }
                break;
            }

            let frame_len = u16::from_be_bytes(len_buf) as usize;
            if frame_len > buf.len() {
                let _ = reader_tx.send(ReaderMessage::Error(format!("Frame too large: {}", frame_len))).await;
                break;
            }

            // Read frame data
            if let Err(e) = read_half.read_exact(&mut buf[..frame_len]).await {
                let _ = reader_tx.send(ReaderMessage::Error(e.to_string())).await;
                break;
            }

            // Send complete frame to main loop
            let frame_data = buf[..frame_len].to_vec();
            if reader_tx.send(ReaderMessage::Frame(frame_data)).await.is_err() {
                break; // Main loop closed
            }
        }
    });

    // Create multiplexer
    let mut mux = Multiplexer::new_server();

    // Track active streams
    let mut active_streams: HashMap<u32, ActiveStream> = HashMap::new();

    // Channel for stream tasks to send data back through tunnel
    let (tunnel_tx, mut tunnel_rx) = mpsc::channel::<StreamToTunnel>(256);

    // Buffer for decryption (reused to avoid allocations)
    let mut frame_buf = vec![0u8; 65536];

    // Reusable encryption buffer
    let mut encrypt_buf = vec![0u8; 65536 + 16];

    // Interval for cleaning up expired draining streams
    let mut cleanup_interval = tokio::time::interval(Duration::from_secs(1));
    cleanup_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            // Periodic cleanup of expired draining streams
            _ = cleanup_interval.tick() => {
                let now = Instant::now();
                let expired: Vec<u32> = active_streams
                    .iter()
                    .filter_map(|(&id, stream)| {
                        if let Some(drain_start) = stream.draining_since {
                            if now.duration_since(drain_start) >= STREAM_DRAIN_TIMEOUT {
                                return Some(id);
                            }
                        }
                        None
                    })
                    .collect();

                for stream_id in expired {
                    trace!("Removing expired draining stream {}", stream_id);
                    active_streams.remove(&stream_id);
                    // Also remove from multiplexer to free the stream slot
                    mux.remove_stream(stream_id);
                }
            }
            // Receive frames from reader task
            Some(msg) = reader_rx.recv() => {
                match msg {
                    ReaderMessage::Frame(encrypted_data) => {
                        // Decrypt frame
                        let plaintext_len = match noise_transport.decrypt(&encrypted_data, &mut frame_buf) {
                            Ok(len) => len,
                            Err(e) => {
                                error!("Decrypt failed for frame of {} bytes: {:?}", encrypted_data.len(), e);
                                return Err(anyhow!("Failed to decrypt frame"));
                            }
                        };

                        // Decode frame
                        let mut frame_bytes = bytes::BytesMut::from(&frame_buf[..plaintext_len]);
                        let frame = match Frame::decode(&mut frame_bytes)? {
                            Some(f) => f,
                            None => continue,
                        };

                        debug!("Received frame: type={:?} stream={} payload={} bytes",
                               frame.frame_type, frame.stream_id, frame.payload.len());

                        // Handle different frame types
                        match frame.frame_type {
                            FrameType::StreamOpen => {
                                // New stream request
                                match mux.handle_frame(frame).await {
                                    Ok(Some(stream_handle)) => {
                                        let stream_id = stream_handle.id();
                                        let destination = stream_handle.destination()
                                            .map(|s| s.to_string())
                                            .unwrap_or_else(|| "unknown".to_string());

                                        info!("Opening stream {} to {}", stream_id, destination);

                                        // Create channel for sending data to this stream
                                        let (data_tx, data_rx) = mpsc::channel::<bytes::Bytes>(256);
                                        active_streams.insert(stream_id, ActiveStream {
                                            data_tx,
                                            draining_since: None,
                                        });

                                        // Spawn task to connect to destination and relay data
                                        let tunnel_tx = tunnel_tx.clone();
                                        tokio::spawn(async move {
                                            if let Err(e) = handle_stream(stream_id, destination, data_rx, tunnel_tx).await {
                                                debug!("Stream {} error: {}", stream_id, e);
                                            }
                                        });
                                    }
                                    Ok(None) => {}
                                    Err(e) => {
                                        debug!("Stream open error: {}", e);
                                    }
                                }
                            }
                            FrameType::Data => {
                                // Forward data to appropriate stream handler
                                let stream_id = frame.stream_id;
                                if let Some(active) = active_streams.get(&stream_id) {
                                    if active.draining_since.is_some() {
                                        // Stream is draining - silently drop
                                        trace!("Dropping data for draining stream {}", stream_id);
                                    } else if active.data_tx.send(frame.payload).await.is_err() {
                                        // Stream handler closed - mark as draining instead of removing
                                        debug!("Stream {} handler closed, marking as draining", stream_id);
                                        if let Some(stream) = active_streams.get_mut(&stream_id) {
                                            stream.draining_since = Some(Instant::now());
                                        }
                                    }
                                } else {
                                    // Unknown stream - likely already cleaned up
                                    trace!("Received data for unknown stream {}", stream_id);
                                }
                            }
                            FrameType::StreamClose => {
                                // Client closed stream - mark as draining if not already
                                let stream_id = frame.stream_id;
                                debug!("Client closed stream {}", stream_id);
                                if let Some(stream) = active_streams.get_mut(&stream_id) {
                                    if stream.draining_since.is_none() {
                                        stream.draining_since = Some(Instant::now());
                                    }
                                }
                                let _ = mux.handle_frame(frame).await;
                            }
                            _ => {
                                // Handle other frames through multiplexer
                                let _ = mux.handle_frame(frame).await;
                            }
                        }
                    }
                    ReaderMessage::Error(e) => {
                        error!("Reader error: {}", e);
                        return Err(anyhow!("Reader error: {}", e));
                    }
                    ReaderMessage::Closed => {
                        debug!("Client disconnected");
                        break;
                    }
                }
            }

            // Handle data from stream handlers to send back through tunnel
            Some(cmd) = tunnel_rx.recv() => {
                match cmd {
                    StreamToTunnel::Data { stream_id, data } => {
                        // Only send if stream is not draining
                        let is_draining = active_streams
                            .get(&stream_id)
                            .map(|s| s.draining_since.is_some())
                            .unwrap_or(true);

                        if !is_draining {
                            let frame = Frame::data(stream_id, data);
                            send_frame_write_buffered(&mut write_half, &mut noise_transport, &frame, &mut encrypt_buf).await?;
                        } else {
                            trace!("Dropping outbound data for draining stream {}", stream_id);
                        }
                    }
                    StreamToTunnel::Close { stream_id } => {
                        // Mark as draining and send close frame
                        if let Some(stream) = active_streams.get_mut(&stream_id) {
                            if stream.draining_since.is_none() {
                                stream.draining_since = Some(Instant::now());
                            }
                        }
                        // Close local side in multiplexer (marks HalfClosedLocal, queues STREAM_CLOSE frame)
                        mux.close_stream_local(stream_id);
                    }
                }
            }

            // Shutdown
            else => {
                break;
            }
        }

        // Send any queued frames from multiplexer
        for frame in mux.take_send_queue() {
            // Don't send frames for draining streams
            let is_draining = active_streams
                .get(&frame.stream_id)
                .map(|s| s.draining_since.is_some())
                .unwrap_or(false);

            if !is_draining {
                send_frame_write_buffered(&mut write_half, &mut noise_transport, &frame, &mut encrypt_buf).await?;
            }
        }
    }

    Ok(())
}

/// Perform Noise IK handshake with split streams
async fn perform_handshake_split<R, W>(
    read_half: &mut R,
    write_half: &mut W,
    keypair: &KeyPair,
) -> Result<(NoiseTransport, PublicKey)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut handshake = NoiseHandshake::new_responder(keypair)
        .context("Failed to create handshake")?;

    let mut buf = [0u8; 65535];
    let mut payload_buf = [0u8; 65535];

    // Read first message (-> e, es, s, ss)
    let mut len_buf = [0u8; 2];
    read_half.read_exact(&mut len_buf).await?;
    let msg_len = u16::from_be_bytes(len_buf) as usize;

    read_half.read_exact(&mut buf[..msg_len]).await?;

    handshake
        .read_message(&buf[..msg_len], &mut payload_buf)
        .context("Failed to read handshake message 1")?;

    // Get client's public key
    let client_public = handshake
        .get_remote_static()
        .ok_or_else(|| anyhow!("Failed to get client public key"))?;

    // Send response (<- e, ee, se)
    let len = handshake
        .write_message(&[], &mut buf)
        .context("Failed to write handshake message 2")?;

    let len_bytes = (len as u16).to_be_bytes();
    write_half.write_all(&len_bytes).await?;
    write_half.write_all(&buf[..len]).await?;

    // Convert to transport mode
    let noise_transport = handshake
        .into_transport()
        .context("Failed to enter transport mode")?;

    Ok((noise_transport, client_public))
}

/// Perform Noise IK handshake (legacy, for non-split streams)
#[allow(dead_code)]
async fn perform_handshake(
    stream: &mut TcpStream,
    keypair: &KeyPair,
) -> Result<(NoiseTransport, PublicKey)> {
    let mut handshake = NoiseHandshake::new_responder(keypair)
        .context("Failed to create handshake")?;

    let mut buf = [0u8; 65535];
    let mut payload_buf = [0u8; 65535];

    // Read first message (-> e, es, s, ss)
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let msg_len = u16::from_be_bytes(len_buf) as usize;

    stream.read_exact(&mut buf[..msg_len]).await?;

    handshake
        .read_message(&buf[..msg_len], &mut payload_buf)
        .context("Failed to read handshake message 1")?;

    // Get client's public key
    let client_public = handshake
        .get_remote_static()
        .ok_or_else(|| anyhow!("Failed to get client public key"))?;

    // Send response (<- e, ee, se)
    let len = handshake
        .write_message(&[], &mut buf)
        .context("Failed to write handshake message 2")?;

    let len_bytes = (len as u16).to_be_bytes();
    stream.write_all(&len_bytes).await?;
    stream.write_all(&buf[..len]).await?;

    // Convert to transport mode
    let noise_transport = handshake
        .into_transport()
        .context("Failed to enter transport mode")?;

    Ok((noise_transport, client_public))
}

/// Send an encrypted frame using split write half
#[allow(dead_code)]
async fn send_frame_write<W: AsyncWrite + Unpin>(
    write_half: &mut W,
    noise: &mut NoiseTransport,
    frame: &Frame,
) -> Result<()> {
    let plaintext = frame.encode();
    let mut ciphertext = vec![0u8; plaintext.len() + 16];

    let ct_len = noise
        .encrypt(&plaintext, &mut ciphertext)
        .context("Failed to encrypt frame")?;

    debug!("Sending frame type {:?} stream {} ({} bytes encrypted, {} bytes plaintext)",
           frame.frame_type, frame.stream_id, ct_len, plaintext.len());

    let len_bytes = (ct_len as u16).to_be_bytes();
    write_half.write_all(&len_bytes).await?;
    write_half.write_all(&ciphertext[..ct_len]).await?;

    Ok(())
}

/// Send an encrypted frame with reusable buffer (reduces allocations)
async fn send_frame_write_buffered<W: AsyncWrite + Unpin>(
    write_half: &mut W,
    noise: &mut NoiseTransport,
    frame: &Frame,
    encrypt_buf: &mut Vec<u8>,
) -> Result<()> {
    let plaintext = frame.encode();

    // Ensure buffer is large enough
    let needed = plaintext.len() + 16;
    if encrypt_buf.len() < needed {
        encrypt_buf.resize(needed, 0);
    }

    let ct_len = noise
        .encrypt(&plaintext, encrypt_buf)
        .context("Failed to encrypt frame")?;

    trace!("Sending frame type {:?} stream {} ({} bytes encrypted)",
           frame.frame_type, frame.stream_id, ct_len);

    // Coalesce length prefix + ciphertext into a single write to halve syscall overhead
    let len_bytes = (ct_len as u16).to_be_bytes();
    let mut wire_buf = Vec::with_capacity(2 + ct_len);
    wire_buf.extend_from_slice(&len_bytes);
    wire_buf.extend_from_slice(&encrypt_buf[..ct_len]);
    write_half.write_all(&wire_buf).await?;

    Ok(())
}

/// Send an encrypted frame (legacy, for non-split streams)
#[allow(dead_code)]
async fn send_frame(
    stream: &mut TcpStream,
    noise: &mut NoiseTransport,
    frame: &Frame,
) -> Result<()> {
    let plaintext = frame.encode();
    let mut ciphertext = vec![0u8; plaintext.len() + 16];

    let ct_len = noise
        .encrypt(&plaintext, &mut ciphertext)
        .context("Failed to encrypt frame")?;

    debug!("Sending frame type {:?} stream {} ({} bytes encrypted, {} bytes plaintext)",
           frame.frame_type, frame.stream_id, ct_len, plaintext.len());

    let len_bytes = (ct_len as u16).to_be_bytes();
    stream.write_all(&len_bytes).await?;
    stream.write_all(&ciphertext[..ct_len]).await?;

    Ok(())
}

/// Handle a single stream (connect to destination, relay data)
async fn handle_stream(
    stream_id: u32,
    destination: String,
    mut data_rx: mpsc::Receiver<bytes::Bytes>,
    tunnel_tx: mpsc::Sender<StreamToTunnel>,
) -> Result<()> {
    // Connect to destination
    let target = match TcpStream::connect(&destination).await {
        Ok(t) => {
            // Disable Nagle's algorithm on destination connection too
            let _ = t.set_nodelay(true);
            info!("Stream {} connected to {}", stream_id, destination);
            t
        }
        Err(e) => {
            error!("Stream {} failed to connect to {}: {}", stream_id, destination, e);
            // Send close to client
            let _ = tunnel_tx.send(StreamToTunnel::Close { stream_id }).await;
            return Err(e.into());
        }
    };

    let (mut target_read, mut target_write) = target.into_split();
    let tunnel_tx_clone = tunnel_tx.clone();

    // Task to read from target and send to tunnel
    let target_to_tunnel = tokio::spawn(async move {
        // Max payload: Noise transport limit (65535) - AEAD tag (16) - frame header (7) = 65512
        let mut buf = vec![0u8; 65512];
        loop {
            match target_read.read(&mut buf).await {
                Ok(0) => {
                    // EOF from target
                    break;
                }
                Ok(n) => {
                    let data = bytes::Bytes::copy_from_slice(&buf[..n]);
                    if tunnel_tx_clone.send(StreamToTunnel::Data { stream_id, data }).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    debug!("Stream {} target read error: {}", stream_id, e);
                    break;
                }
            }
        }
        // Send close when target disconnects
        let _ = tunnel_tx_clone.send(StreamToTunnel::Close { stream_id }).await;
    });

    // Task to read from tunnel and send to target
    let tunnel_to_target = tokio::spawn(async move {
        while let Some(data) = data_rx.recv().await {
            if target_write.write_all(&data).await.is_err() {
                break;
            }
        }
    });

    // Wait for either direction to complete
    tokio::select! {
        _ = target_to_tunnel => {}
        _ = tunnel_to_target => {}
    }

    Ok(())
}
