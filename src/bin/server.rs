//! Phantom Tunnel Server
//!
//! - Accepts client connections (length-prefixed Noise over plain TCP)
//! - Performs the Noise IK handshake and checks the client allow-list
//! - Relays multiplexed streams and UDP associations to their destinations
//!
//! `phantom-server link` prints a `phantom://` connect link for clients.

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use phantom_tunnel::{
    config::Config,
    crypto::{KeyPair, NoiseHandshake, NoiseTransport, PrivateKey, PublicKey},
    link::{self, ConnectLink},
    tunnel::{
        udp, Frame, FrameType, InboundRx, InboundTx, RecvWindow, StreamFlow, DEFAULT_WINDOW_SIZE,
        MAX_WINDOW_SIZE, PROTOCOL_VERSION,
    },
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
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
    #[arg(short, long, default_value = "config.toml", global = true)]
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

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Print a phantom:// connect link for this server and exit. Clients set
    /// themselves up with `phantom-client --import LINK`.
    Link {
        /// Address clients dial: host or host:port. Without a port, the port
        /// from `listen` is used.
        #[arg(long)]
        address: String,

        /// Backup server clients try, in order, if this one can't be reached:
        /// host:port (same server key) or KEY@host:port. Repeatable.
        #[arg(long = "backup", value_name = "[KEY@]HOST:PORT")]
        backups: Vec<String>,

        /// Name of the person or device, shown when the link is imported.
        #[arg(long)]
        label: Option<String>,

        /// Generate a key pair for the client and put its private key in the
        /// link, so the recipient doesn't have to send a key back. The link is
        /// then a credential. Prints the public key to add to allowed_clients.
        #[arg(long)]
        new_client_key: bool,
    },
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
    /// Bytes drained to the destination; triggers a WindowUpdate to the client.
    Consumed { stream_id: u32, bytes: u32 },
    /// Stream closed
    Close { stream_id: u32 },
    /// A UDP datagram to send back to the client (ATYP|ADDR|PORT|data).
    Udp { stream_id: u32, payload: bytes::Bytes },
}

/// Active stream with channel to send data to it
struct ActiveStream {
    /// Forwards payloads from the client to the destination task.
    inbound: InboundTx,
    /// Send-side credit window (server -> client direction).
    flow: Arc<StreamFlow>,
    /// Receive window for the client's uploads on this stream.
    recv: RecvWindow,
}

/// Remove a stream and release any sender task blocked on its send window.
fn remove_stream(streams: &mut HashMap<u32, ActiveStream>, id: u32) {
    if let Some(s) = streams.remove(&id) {
        s.flow.close();
    }
}

/// Initial per-stream send window as a signed credit count.
const INITIAL_WINDOW: i64 = DEFAULT_WINDOW_SIZE as i64;

/// Largest receive window the server grants per stream (uploads). Half the
/// client's, because the server runs under a 512 MB memory limit and serves
/// many clients; still about 500 Mbit/s per connection at a 120 ms round trip.
const SERVER_MAX_WINDOW: u32 = MAX_WINDOW_SIZE / 2;

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

    if let Some(Command::Link {
        address,
        backups,
        label,
        new_client_key,
    }) = &args.command
    {
        let listen = args.listen.as_deref().unwrap_or(&server_config.listen);
        return print_link(&server_config, listen, address, backups, label.as_deref(), *new_client_key);
    }

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

        // Derived from the private key: this is the key clients must pin.
        let pair = KeyPair::from_private(private_key);
        if !server_config.public_key.is_empty()
            && server_config.public_key != pair.public.to_base64()
        {
            warn!(
                "public_key in the config does not match private_key; clients must use {}",
                pair.public.to_base64()
            );
        }
        pair
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

/// `phantom-server link`: print a connect link for clients of this server.
fn print_link(
    server_config: &phantom_tunnel::config::ServerConfig,
    listen: &str,
    address: &str,
    backups: &[String],
    label: Option<&str>,
    new_client_key: bool,
) -> Result<()> {
    // Prefer the key derived from private_key: it is what the handshake uses.
    let server_public_key = if !server_config.private_key.is_empty() {
        PrivateKey::from_base64(&server_config.private_key)
            .context("Invalid private_key in config")?
            .public_key()
    } else if !server_config.public_key.is_empty() {
        PublicKey::from_base64(&server_config.public_key).context("Invalid public_key in config")?
    } else {
        return Err(anyhow!(
            "The server has no key yet. Start it once to generate one, then make the link."
        ));
    };

    let server = complete_address(address, listen)?;
    let backups = backups
        .iter()
        .map(|b| link::parse_backup(b.trim()).with_context(|| format!("--backup {}", b)))
        .collect::<Result<Vec<_>>>()?;
    if backups.len() > link::MAX_BACKUPS {
        return Err(anyhow!("At most {} backup servers", link::MAX_BACKUPS));
    }
    let client = if new_client_key {
        Some(KeyPair::generate()?)
    } else {
        None
    };

    let text = ConnectLink {
        server,
        server_public_key,
        backups,
        client_private_key: client.as_ref().map(|c| c.private.clone()),
        label: label.map(str::to_string),
    }
    .to_string();
    // Round-trip through the parser so we never hand out a link the client
    // would reject.
    ConnectLink::parse(&text).context("Generated link failed to parse (bug)")?;

    // The link alone on stdout, so `LINK=$(phantom-server link ...)` works;
    // instructions on stderr.
    println!("{}", text);
    eprintln!();
    eprintln!("On the client:  phantom-client -c config.toml --import -   (then paste the link)");
    match &client {
        Some(c) => {
            eprintln!();
            eprintln!("This link contains a private key: send it privately, to one person.");
            eprintln!("Authorise it by adding this line to allowed_clients, then restart the server:");
            eprintln!(
                "    \"{}\",  # {}",
                c.public.to_base64(),
                label.unwrap_or("new client")
            );
        }
        None => {
            eprintln!();
            eprintln!("The link has no client key. Importing it prints the device's public key;");
            eprintln!("add that key to allowed_clients to let it connect.");
        }
    }
    Ok(())
}

/// Accept `host`, `host:port`, `[v6]` or `[v6]:port`, filling in the port from
/// the listen address when it is missing. Refuses wildcard addresses
/// (0.0.0.0, ::), which clients can't dial.
fn complete_address(address: &str, listen: &str) -> Result<String> {
    let address = address.trim();
    let has_port = if address.starts_with('[') {
        address.contains("]:")
    } else {
        address.contains(':')
    };
    let full = if has_port {
        address.to_string()
    } else {
        let port = listen
            .rsplit_once(':')
            .map(|(_, p)| p)
            .ok_or_else(|| anyhow!("--address has no port and listen ({}) has none either", listen))?;
        format!("{}:{}", address, port)
    };
    link::validate_address(&full, "--address")?;
    let host = full.rsplit_once(':').map(|(h, _)| h).unwrap_or(&full);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        // Loopback stays allowed: it is valid behind an SSH port forward.
        if ip.is_unspecified() {
            return Err(anyhow!(
                "--address {} is not reachable by clients; use this server's public hostname or IP",
                full
            ));
        }
    }
    Ok(full)
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
    let (mut noise_transport, client_public, client_version) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        perform_handshake_split(&mut read_half, &mut write_half, &state.keypair),
    )
    .await
    .map_err(|_| anyhow!("Handshake timed out"))??;

    // Flow control and UDP only engage when the client is also v2.
    let flow_enabled = client_version >= 2;

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

                                let (inbound, data_rx) = if flow_enabled {
                                    InboundTx::credit()
                                } else {
                                    InboundTx::blocking(256)
                                };
                                let flow = Arc::new(StreamFlow::new(INITIAL_WINDOW));
                                active_streams.insert(stream_id, ActiveStream {
                                    inbound,
                                    flow: Arc::clone(&flow),
                                    recv: RecvWindow::new(SERVER_MAX_WINDOW),
                                });

                                let tunnel_tx = tunnel_tx.clone();
                                let allow_private = state.allow_private_destinations;
                                tokio::spawn(async move {
                                    if let Err(e) = handle_stream(stream_id, destination, data_rx, tunnel_tx, allow_private, flow, flow_enabled).await {
                                        debug!("Stream {} error: {}", stream_id, e);
                                    }
                                });
                            }
                            FrameType::UdpAssociate => {
                                let stream_id = frame.stream_id;
                                trace!("Opening UDP association {}", stream_id);
                                let (inbound, data_rx) = InboundTx::datagram(1024);
                                active_streams.insert(stream_id, ActiveStream {
                                    inbound,
                                    flow: Arc::new(StreamFlow::new(INITIAL_WINDOW)),
                                    recv: RecvWindow::new(SERVER_MAX_WINDOW),
                                });
                                let tunnel_tx = tunnel_tx.clone();
                                let allow_private = state.allow_private_destinations;
                                tokio::spawn(async move {
                                    if let Err(e) = handle_udp(stream_id, data_rx, tunnel_tx, allow_private).await {
                                        debug!("UDP {} error: {}", stream_id, e);
                                    }
                                });
                            }
                            FrameType::Data => {
                                let stream_id = frame.stream_id;
                                if let Some(active) = active_streams.get_mut(&stream_id) {
                                    // v2: memory is bounded by our receive window, so a
                                    // client sending past it is cut off. (v1 clients have
                                    // no window; their channel blocks instead.)
                                    if flow_enabled && active.recv.on_received(frame.payload.len()).is_err() {
                                        debug!("Stream {} exceeded window; resetting", stream_id);
                                        remove_stream(&mut active_streams, stream_id);
                                        let f = Frame::stream_close(stream_id);
                                        send_frame_write(&mut write_half, &mut noise_transport, &f).await?;
                                    } else if active.inbound.send(frame.payload).await.is_err() {
                                        remove_stream(&mut active_streams, stream_id);
                                    }
                                }
                            }
                            FrameType::UdpData => {
                                let stream_id = frame.stream_id;
                                if let Some(active) = active_streams.get(&stream_id) {
                                    // Datagram channel: a full channel drops it.
                                    let _ = active.inbound.send(frame.payload).await;
                                }
                            }
                            FrameType::WindowUpdate => {
                                if flow_enabled {
                                    if let Some(active) = active_streams.get(&frame.stream_id) {
                                        if frame.payload.len() >= 4 {
                                            let inc = u32::from_be_bytes(frame.payload[..4].try_into().unwrap());
                                            active.flow.add(inc as i64);
                                        }
                                    }
                                }
                            }
                            FrameType::StreamClose => {
                                remove_stream(&mut active_streams, frame.stream_id);
                            }
                            FrameType::Ping => {
                                let data = if frame.payload.len() >= 8 {
                                    u64::from_be_bytes(frame.payload[..8].try_into().unwrap())
                                } else { 0 };
                                send_frame_write(&mut write_half, &mut noise_transport, &Frame::pong(data)).await?;
                            }
                            FrameType::Pong | FrameType::Padding => {}
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
                    StreamToTunnel::Udp { stream_id, payload } => {
                        let frame = Frame::udp_data(stream_id, payload);
                        send_frame_write(&mut write_half, &mut noise_transport, &frame).await?;
                    }
                    StreamToTunnel::Consumed { stream_id, bytes } => {
                        if flow_enabled {
                            if let Some(active) = active_streams.get_mut(&stream_id) {
                                if let Some(inc) = active.recv.on_drained(bytes) {
                                    let f = Frame::window_update(stream_id, inc);
                                    send_frame_write(&mut write_half, &mut noise_transport, &f).await?;
                                }
                            }
                        }
                    }
                    StreamToTunnel::Close { stream_id } => {
                        remove_stream(&mut active_streams, stream_id);
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

/// Perform Noise IK handshake with split streams.
/// Returns the transport, the client's static public key, and the client's
/// protocol version (0 if the client is a v1 build that sent no version byte).
async fn perform_handshake_split(
    read_half: &mut OwnedReadHalf,
    write_half: &mut OwnedWriteHalf,
    keypair: &KeyPair,
) -> Result<(NoiseTransport, PublicKey, u8)> {
    let mut handshake = NoiseHandshake::new_responder(keypair)
        .context("Failed to create handshake")?;

    let mut buf = [0u8; 65535];
    let mut payload_buf = [0u8; 65535];

    // Read first message (-> e, es, s, ss)
    let mut len_buf = [0u8; 2];
    read_half.read_exact(&mut len_buf).await?;
    let msg_len = u16::from_be_bytes(len_buf) as usize;

    read_half.read_exact(&mut buf[..msg_len]).await?;

    let payload_len = handshake
        .read_message(&buf[..msg_len], &mut payload_buf)
        .context("Failed to read handshake message 1")?;

    // The client's protocol version is the first payload byte, if present.
    let client_version = if payload_len >= 1 { payload_buf[0] } else { 0 };

    // Get client's public key
    let client_public = handshake
        .get_remote_static()
        .ok_or_else(|| anyhow!("Failed to get client public key"))?;

    // Send response (<- e, ee, se) carrying our version as the payload.
    let len = handshake
        .write_message(&[PROTOCOL_VERSION], &mut buf)
        .context("Failed to write handshake message 2")?;

    let len_bytes = (len as u16).to_be_bytes();
    write_half.write_all(&len_bytes).await?;
    write_half.write_all(&buf[..len]).await?;

    // Convert to transport mode
    let noise_transport = handshake
        .into_transport()
        .context("Failed to enter transport mode")?;

    Ok((noise_transport, client_public, client_version))
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
    mut data_rx: InboundRx,
    tunnel_tx: mpsc::Sender<StreamToTunnel>,
    allow_private: bool,
    flow: Arc<StreamFlow>,
    flow_enabled: bool,
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

    // Task to read from target and send to tunnel (download direction). Gated by
    // the client's send window so one slow client can't make us buffer without
    // bound; backpressure here only affects this one destination socket.
    let target_to_tunnel = tokio::spawn(async move {
        let mut buf = vec![0u8; 32768];
        'outer: loop {
            let n = match target_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    debug!("Stream {} target read error: {}", stream_id, e);
                    break;
                }
            };
            if flow_enabled {
                let mut sent = 0;
                while sent < n {
                    let got = flow.acquire(n - sent).await;
                    if got == 0 {
                        break 'outer; // stream closed
                    }
                    let data = bytes::Bytes::copy_from_slice(&buf[sent..sent + got]);
                    if tunnel_tx_clone.send(StreamToTunnel::Data { stream_id, data }).await.is_err() {
                        break 'outer;
                    }
                    sent += got;
                }
            } else {
                let data = bytes::Bytes::copy_from_slice(&buf[..n]);
                if tunnel_tx_clone.send(StreamToTunnel::Data { stream_id, data }).await.is_err() {
                    break;
                }
            }
        }
        // Send close when target disconnects
        let _ = tunnel_tx_clone.send(StreamToTunnel::Close { stream_id }).await;
    });

    // Task to read from tunnel and send to target (upload direction). Report
    // bytes drained so the server can replenish the client's send window.
    let consumed_tx = tunnel_tx.clone();
    let tunnel_to_target = tokio::spawn(async move {
        while let Some(data) = data_rx.recv().await {
            let n = data.len();
            if target_write.write_all(&data).await.is_err() {
                break;
            }
            if flow_enabled && n > 0 {
                let _ = consumed_tx.send(StreamToTunnel::Consumed { stream_id, bytes: n as u32 }).await;
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

/// Relay a UDP association. Outbound datagrams (ATYP|ADDR|PORT|data) arrive on
/// `data_rx`; inbound datagrams are sent back as `StreamToTunnel::Udp` tagged
/// with the source address. Destinations are SSRF-vetted. The session ends when
/// the client closes the association (dropping `data_rx`) or after an idle
/// period with no traffic in either direction.
async fn handle_udp(
    stream_id: u32,
    mut data_rx: InboundRx,
    tunnel_tx: mpsc::Sender<StreamToTunnel>,
    allow_private: bool,
) -> Result<()> {
    use phantom_tunnel::tunnel::udp::UdpTarget;

    let sock = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    const UDP_IDLE: std::time::Duration = std::time::Duration::from_secs(60);

    // Inbound: datagrams from destinations -> back through the tunnel.
    let recv_sock = Arc::clone(&sock);
    let recv_tx = tunnel_tx.clone();
    let recv_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, src) = match tokio::time::timeout(UDP_IDLE, recv_sock.recv_from(&mut buf)).await {
                Ok(Ok(v)) => v,
                _ => break, // idle timeout or socket error
            };
            let mut payload = bytes::BytesMut::new();
            udp::encode_ip(&mut payload, src);
            payload.extend_from_slice(&buf[..n]);
            if recv_tx.send(StreamToTunnel::Udp { stream_id, payload: payload.freeze() }).await.is_err() {
                break;
            }
        }
    });

    // Outbound: datagrams from the client -> the destination.
    while let Ok(Some(payload)) = tokio::time::timeout(UDP_IDLE, data_rx.recv()).await {
        let (target, off) = match udp::parse_target(&payload) {
            Some(v) => v,
            None => continue,
        };
        let data = &payload[off..];
        let dest = match target {
            UdpTarget::Ip(a) => {
                if allow_private || !is_blocked_ip(a.ip()) {
                    Some(a)
                } else {
                    None
                }
            }
            UdpTarget::Domain(h, p) => resolve_allowed(&format!("{}:{}", h, p), allow_private).await.ok(),
        };
        if let Some(dest) = dest {
            let _ = sock.send_to(data, dest).await;
        }
    }

    recv_task.abort();
    let _ = tunnel_tx.send(StreamToTunnel::Close { stream_id }).await;
    Ok(())
}
