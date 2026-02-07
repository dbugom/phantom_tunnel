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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, Semaphore};
use tracing::{debug, error, info, warn};

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

/// Active stream with channel to send data to it and abort handle
struct ActiveStream {
    data_tx: mpsc::Sender<bytes::Bytes>,
    abort_handle: tokio::task::AbortHandle,
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
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, state).await {
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
async fn handle_connection(stream: TcpStream, state: Arc<ServerState>) -> Result<()> {
    // Acquire connection permit
    let _permit = state
        .conn_semaphore
        .acquire()
        .await
        .context("Failed to acquire connection permit")?;

    // Split stream for handshake
    let (mut read_half, mut write_half) = stream.into_split();

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

    // Buffer for decryption
    let mut frame_buf = vec![0u8; 65536];

    loop {
        tokio::select! {
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

                                        // Spawn task to connect to destination and relay data
                                        let tunnel_tx = tunnel_tx.clone();
                                        let task_handle = tokio::spawn(async move {
                                            if let Err(e) = handle_stream(stream_id, destination, data_rx, tunnel_tx).await {
                                                debug!("Stream {} error: {}", stream_id, e);
                                            }
                                        });

                                        // Store with abort handle so we can stop it when client closes
                                        active_streams.insert(stream_id, ActiveStream {
                                            data_tx,
                                            abort_handle: task_handle.abort_handle(),
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
                                    if active.data_tx.send(frame.payload).await.is_err() {
                                        // Stream handler closed, remove and abort
                                        if let Some(stream) = active_streams.remove(&stream_id) {
                                            stream.abort_handle.abort();
                                        }
                                    }
                                }
                            }
                            FrameType::StreamClose => {
                                // Remove stream and abort its relay task
                                let stream_id = frame.stream_id;
                                debug!("Client closed stream {}", stream_id);
                                if let Some(stream) = active_streams.remove(&stream_id) {
                                    // Abort the relay task to stop reading from target
                                    stream.abort_handle.abort();
                                    debug!("Aborted relay task for stream {}", stream_id);
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
                        // Send data frame to client
                        let frame = Frame::data(stream_id, data);
                        send_frame_write(&mut write_half, &mut noise_transport, &frame).await?;
                    }
                    StreamToTunnel::Close { stream_id } => {
                        // Send close frame to client
                        active_streams.remove(&stream_id);
                        let frame = Frame::stream_close(stream_id);
                        send_frame_write(&mut write_half, &mut noise_transport, &frame).await?;
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
            send_frame_write(&mut write_half, &mut noise_transport, &frame).await?;
        }
    }

    Ok(())
}

/// Perform Noise IK handshake with split streams
async fn perform_handshake_split(
    read_half: &mut OwnedReadHalf,
    write_half: &mut OwnedWriteHalf,
    keypair: &KeyPair,
) -> Result<(NoiseTransport, PublicKey)> {
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
async fn send_frame_write(
    write_half: &mut OwnedWriteHalf,
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
        let mut buf = vec![0u8; 32768];
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
