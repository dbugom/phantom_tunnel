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
    tunnel::{Frame, FrameType},
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, Semaphore};
use tracing::{debug, error, info, trace, warn};

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
    /// Whether clients may reach private/loopback destinations (SSRF guard)
    allow_private_destinations: bool,
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
        allow_private_destinations: server_config.allow_private_destinations,
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
    // Reject immediately if at capacity instead of queueing. A queued connection
    // would still hold the socket open, so a flood of connections could park
    // unbounded sockets waiting for a permit.
    let _permit = match state.conn_semaphore.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            debug!("At connection capacity, dropping new connection");
            return Ok(());
        }
    };

    // Disable Nagle: our frames are small and request/response, so Nagle's
    // algorithm interacts with delayed-ACK to add up to ~40ms per round trip.
    stream.set_nodelay(true).ok();

    // Split stream for handshake
    let (mut read_half, mut write_half) = stream.into_split();

    // Perform Noise handshake with a timeout so a client that connects but never
    // completes the handshake can't hold a connection permit indefinitely.
    let (mut noise_transport, client_public) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        perform_handshake_split(&mut read_half, &mut write_half, &state.keypair),
    )
    .await
    .map_err(|_| anyhow!("Handshake timed out"))??;

    // Verify client is allowed. Fail CLOSED: an empty allowlist rejects every
    // client (matching the warning printed at startup). Previously an empty
    // list silently accepted ANY client that completed the handshake, turning
    // the server into an open relay.
    let client_key_b64 = client_public.to_base64();
    if !state.allowed_clients.contains(&client_key_b64) {
        debug!("Rejected client not in allowlist");
        return Err(anyhow!("Client not in allowed list"));
    }

    // Only the first 8 chars of the key, and only at debug level: a seized
    // server should not reveal which clients connected.
    debug!("Client authenticated");

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

    // Track active streams. This map owns each stream's lifetime and entries are
    // removed on close, so the connection can run indefinitely without leaking
    // (the old code also fed every frame to a Multiplexer whose internal stream
    // table was never pruned).
    let mut active_streams: HashMap<u32, ActiveStream> = HashMap::new();

    // Channel for stream tasks to send data back through tunnel
    let (tunnel_tx, mut tunnel_rx) = mpsc::channel::<StreamToTunnel>(256);

    // Buffer for decryption
    let mut frame_buf = vec![0u8; 65536];

    // Drop a client that goes silent (crash / network loss) so its slot frees.
    // Longer than the client's keepalive interval so normal pings keep it alive.
    let mut last_recv = tokio::time::Instant::now();
    let mut idle_check = tokio::time::interval(std::time::Duration::from_secs(30));
    idle_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    idle_check.tick().await; // consume immediate first tick
    const CLIENT_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);

    loop {
        tokio::select! {
            // Receive frames from reader task
            Some(msg) = reader_rx.recv() => {
                match msg {
                    ReaderMessage::Frame(encrypted_data) => {
                        last_recv = tokio::time::Instant::now();

                        // Decrypt frame
                        let plaintext_len = match noise_transport.decrypt(&encrypted_data, &mut frame_buf) {
                            Ok(len) => len,
                            Err(_) => {
                                // A valid client never sends an undecryptable frame;
                                // treat it as a fatal protocol error for this conn.
                                return Err(anyhow!("Failed to decrypt frame"));
                            }
                        };

                        // Decode frame
                        let mut frame_bytes = bytes::BytesMut::from(&frame_buf[..plaintext_len]);
                        let frame = match Frame::decode(&mut frame_bytes)? {
                            Some(f) => f,
                            None => continue,
                        };

                        // Handle different frame types
                        match frame.frame_type {
                            FrameType::StreamOpen => {
                                let stream_id = frame.stream_id;
                                let destination = match parse_destination(&frame.payload) {
                                    Some(d) => d,
                                    None => {
                                        debug!("Stream {} invalid destination", stream_id);
                                        let frame = Frame::stream_close(stream_id);
                                        send_frame_write(&mut write_half, &mut noise_transport, &frame).await?;
                                        continue;
                                    }
                                };

                                trace!("Opening stream {}", stream_id);

                                let (data_tx, data_rx) = mpsc::channel::<bytes::Bytes>(256);
                                active_streams.insert(stream_id, ActiveStream { data_tx });

                                let tunnel_tx = tunnel_tx.clone();
                                let allow_private = state.allow_private_destinations;
                                tokio::spawn(async move {
                                    if let Err(e) = handle_stream(stream_id, destination, data_rx, tunnel_tx, allow_private).await {
                                        debug!("Stream {} error: {}", stream_id, e);
                                    }
                                });
                            }
                            FrameType::Data => {
                                let stream_id = frame.stream_id;
                                if let Some(active) = active_streams.get(&stream_id) {
                                    if active.data_tx.send(frame.payload).await.is_err() {
                                        active_streams.remove(&stream_id);
                                    }
                                }
                            }
                            FrameType::StreamClose => {
                                active_streams.remove(&frame.stream_id);
                            }
                            FrameType::Ping => {
                                let data = if frame.payload.len() >= 8 {
                                    u64::from_be_bytes(frame.payload[..8].try_into().unwrap())
                                } else { 0 };
                                send_frame_write(&mut write_half, &mut noise_transport, &Frame::pong(data)).await?;
                            }
                            FrameType::Pong | FrameType::Padding | FrameType::WindowUpdate => {}
                            FrameType::GoAway => {
                                break;
                            }
                        }
                    }
                    ReaderMessage::Error(e) => {
                        debug!("Reader error: {}", e);
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
                        let frame = Frame::data(stream_id, data);
                        send_frame_write(&mut write_half, &mut noise_transport, &frame).await?;
                    }
                    StreamToTunnel::Close { stream_id } => {
                        active_streams.remove(&stream_id);
                        let frame = Frame::stream_close(stream_id);
                        send_frame_write(&mut write_half, &mut noise_transport, &frame).await?;
                    }
                }
            }

            // Idle-client check. If the client has been quiet, ping it; any
            // client (including older versions without their own keepalive)
            // answers with a Pong, which refreshes last_recv. Only a client
            // that stays silent past the timeout is dropped.
            _ = idle_check.tick() => {
                if last_recv.elapsed() > CLIENT_IDLE_TIMEOUT {
                    debug!("Client idle timeout");
                    break;
                }
                if last_recv.elapsed() >= std::time::Duration::from_secs(25) {
                    send_frame_write(&mut write_half, &mut noise_transport, &Frame::ping(0)).await?;
                }
            }
        }
    }

    Ok(())
}

/// Parse a STREAM_OPEN payload into a `host:port` destination string.
/// The client sends the destination as a plain UTF-8 `host:port` string.
fn parse_destination(payload: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(payload).ok()?;
    // Must contain a port separator and be a plausible length.
    if s.is_empty() || s.len() > 255 || !s.contains(':') {
        return None;
    }
    Some(s.to_string())
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

/// Send an encrypted frame using split write half
async fn send_frame_write(
    write_half: &mut OwnedWriteHalf,
    noise: &mut NoiseTransport,
    frame: &Frame,
) -> Result<()> {
    let plaintext = frame.encode();
    // 2-byte length prefix + ciphertext in one buffer → one TCP segment.
    let mut out = vec![0u8; 2 + plaintext.len() + 16];
    let ct_len = noise
        .encrypt(&plaintext, &mut out[2..])
        .context("Failed to encrypt frame")?;
    out[0..2].copy_from_slice(&(ct_len as u16).to_be_bytes());
    out.truncate(2 + ct_len);

    write_half.write_all(&out).await?;

    Ok(())
}

/// Returns true if an IP must not be reachable through the tunnel: loopback,
/// private (RFC1918 / ULA), link-local (incl. the 169.254.169.254 cloud
/// metadata endpoint), unspecified, or multicast/broadcast.
fn is_blocked_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                // Carrier-grade NAT 100.64.0.0/10
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // Unique local addresses fc00::/7
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // Link-local fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // IPv4-mapped: unwrap and re-check against the v4 rules
                || v6.to_ipv4_mapped().map(IpAddr::V4).map(is_blocked_ip).unwrap_or(false)
        }
    }
}

/// Resolve `destination` (host:port) to an allowed socket address, applying the
/// SSRF guard unless `allow_private` is set.
async fn resolve_allowed(
    destination: &str,
    allow_private: bool,
) -> Result<std::net::SocketAddr> {
    let addrs: Vec<std::net::SocketAddr> =
        tokio::net::lookup_host(destination).await?.collect();
    if addrs.is_empty() {
        return Err(anyhow!("No addresses resolved"));
    }
    for addr in &addrs {
        if allow_private || !is_blocked_ip(addr.ip()) {
            return Ok(*addr);
        }
    }
    Err(anyhow!("Destination resolves only to blocked addresses"))
}

/// Handle a single stream (connect to destination, relay data)
async fn handle_stream(
    stream_id: u32,
    destination: String,
    mut data_rx: mpsc::Receiver<bytes::Bytes>,
    tunnel_tx: mpsc::Sender<StreamToTunnel>,
    allow_private: bool,
) -> Result<()> {
    // Resolve + vet the destination before connecting (SSRF guard), then
    // connect to the vetted address rather than the hostname, so DNS can't
    // rebind to a blocked IP between the check and the connect.
    let addr = match resolve_allowed(&destination, allow_private).await {
        Ok(a) => a,
        Err(e) => {
            debug!("Stream {} destination rejected: {}", stream_id, e);
            let _ = tunnel_tx.send(StreamToTunnel::Close { stream_id }).await;
            return Err(e);
        }
    };

    // Connect to the vetted destination address
    let target = match TcpStream::connect(addr).await {
        Ok(t) => {
            t.set_nodelay(true).ok();
            trace!("Stream {} connected", stream_id);
            t
        }
        Err(e) => {
            debug!("Stream {} failed to connect: {}", stream_id, e);
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
