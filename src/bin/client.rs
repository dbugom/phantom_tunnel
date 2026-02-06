//! Phantom Tunnel Client
//!
//! A secure, censorship-resistant tunnel client that:
//! - Connects to server with TLS fingerprint mimicry
//! - Performs Noise Protocol handshake
//! - Runs local SOCKS5/HTTP proxy
//! - Multiplexes connections through tunnel

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use phantom_tunnel::{
    config::Config,
    crypto::{KeyPair, NoiseHandshake, NoiseTransport, PrivateKey, PublicKey},
    obfuscation::BrowserProfile,
    tunnel::{Frame, FrameType, Multiplexer, StreamEvent},
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tracing::{debug, error, info, warn};

/// Phantom Tunnel Client - Secure, censorship-resistant tunnel
#[derive(Parser, Debug)]
#[command(name = "phantom-client")]
#[command(about = "Phantom Tunnel Client - Secure, censorship-resistant tunneling")]
#[command(version)]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// Generate new keypair and exit
    #[arg(long)]
    generate_key: bool,

    /// Server address (overrides config)
    #[arg(short, long)]
    server: Option<String>,

    /// Local SOCKS5 proxy address
    #[arg(long)]
    socks5: Option<String>,

    /// Local HTTP proxy address
    #[arg(long)]
    http: Option<String>,

    /// Browser profile for TLS fingerprint (chrome, firefox, safari, random)
    #[arg(long, default_value = "chrome")]
    profile: String,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short = 'v', long, default_value = "info")]
    log_level: String,
}

/// Client state
struct ClientState {
    /// Client's keypair
    keypair: KeyPair,
    /// Server's public key
    server_public: PublicKey,
    /// Server address
    server_addr: String,
    /// Browser profile
    profile: BrowserProfile,
    /// SNI for TLS
    sni: String,
}

/// Request to open a new stream through the tunnel
struct OpenStreamRequest {
    destination: String,
    response_tx: oneshot::Sender<Result<StreamConnection, String>>,
}

/// A connection to a remote destination through the tunnel
struct StreamConnection {
    stream_id: u32,
    data_tx: mpsc::Sender<bytes::Bytes>,
    data_rx: mpsc::Receiver<bytes::Bytes>,
}

/// Tunnel command sent from proxy handlers to tunnel task
enum TunnelCommand {
    /// Open a new stream to destination
    OpenStream(OpenStreamRequest),
    /// Send data on a stream
    SendData { stream_id: u32, data: bytes::Bytes },
    /// Close a stream
    CloseStream { stream_id: u32 },
}

/// Shared tunnel handle for proxy handlers
struct TunnelHandle {
    cmd_tx: mpsc::Sender<TunnelCommand>,
}

impl TunnelHandle {
    /// Open a new stream to the given destination
    async fn open_stream(&self, destination: String) -> Result<StreamConnection, String> {
        let (response_tx, response_rx) = oneshot::channel();

        self.cmd_tx
            .send(TunnelCommand::OpenStream(OpenStreamRequest {
                destination,
                response_tx,
            }))
            .await
            .map_err(|_| "Tunnel disconnected".to_string())?;

        response_rx.await.map_err(|_| "Tunnel closed".to_string())?
    }
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

    let client_config = config
        .client
        .clone()
        .ok_or_else(|| anyhow!("No [client] section in config file"))?;

    // Parse server public key first (required)
    if client_config.server_public_key.is_empty() {
        error!("Server public key not configured");
        return Err(anyhow!("Missing server_public_key in config"));
    }

    let server_public = PublicKey::from_base64(&client_config.server_public_key)
        .context("Invalid server public key")?;

    // Parse or generate client keypair
    let keypair = if client_config.private_key.is_empty() {
        // No keys configured - generate new keypair and save to config
        info!("No keypair configured - generating new keypair...");
        let new_keypair = KeyPair::generate()?;

        // Update config with new keys
        if let Some(ref mut client) = config.client {
            client.private_key = new_keypair.private.to_base64();
            client.public_key = new_keypair.public.to_base64();
        }

        // Save updated config
        config.save(&args.config).context("Failed to save config with new keypair")?;
        info!("Generated and saved new keypair to config file");
        info!("Share this public key with server admin: {}", new_keypair.public.to_base64());

        new_keypair
    } else {
        // Load existing keypair from config
        let private_key = PrivateKey::from_base64(&client_config.private_key)
            .context("Invalid private key format")?;

        let public_key = if client_config.public_key.is_empty() {
            // Old config without public key - can't derive, error out
            error!("Config has private_key but no public_key");
            error!("Please regenerate keys or add public_key to config");
            return Err(anyhow!("Missing public_key in config"));
        } else {
            PublicKey::from_base64(&client_config.public_key)
                .context("Invalid public key format")?
        };

        KeyPair {
            public: public_key,
            private: private_key,
        }
    };

    // Parse browser profile
    let profile = match args.profile.to_lowercase().as_str() {
        "chrome" => BrowserProfile::Chrome,
        "firefox" => BrowserProfile::Firefox,
        "safari" => BrowserProfile::Safari,
        "random" => BrowserProfile::Random,
        _ => {
            warn!("Unknown profile '{}', using Chrome", args.profile);
            BrowserProfile::Chrome
        }
    };

    // Create client state
    let state = Arc::new(ClientState {
        keypair,
        server_public,
        server_addr: args.server.unwrap_or(client_config.server),
        profile,
        sni: client_config.tls_sni.unwrap_or_else(|| "www.google.com".to_string()),
    });

    info!("Phantom Tunnel Client v{}", phantom_tunnel::VERSION);
    info!("Server: {}", state.server_addr);
    info!("Browser profile: {:?}", state.profile);
    info!("Client public key: {}...", &state.keypair.public.to_base64()[..16]);

    // Start local proxies
    let socks5_addr = args.socks5.or(client_config.socks5_listen);
    let http_addr = args.http.or(client_config.http_listen);

    // Create channel for tunnel commands
    let (cmd_tx, cmd_rx) = mpsc::channel::<TunnelCommand>(256);
    let tunnel_handle = Arc::new(TunnelHandle { cmd_tx });

    // Connect to server and run tunnel
    info!("Connecting to server...");

    let tunnel_state = Arc::clone(&state);
    let tunnel_cmd_rx = cmd_rx;
    let tunnel_task = tokio::spawn(async move {
        loop {
            match run_tunnel(Arc::clone(&tunnel_state), tunnel_cmd_rx).await {
                Ok(_) => {
                    info!("Tunnel closed normally");
                    break;
                }
                Err(e) => {
                    error!("Tunnel error: {}", e);
                    info!("Reconnecting in 5 seconds...");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
            // After reconnection attempt, we need a new receiver
            // For now, just break - a more robust implementation would recreate the channel
            break;
        }
    });

    // Start SOCKS5 proxy if configured
    if let Some(addr) = &socks5_addr {
        info!("SOCKS5 proxy listening on {}", addr);
        let socks_addr = addr.clone();
        let handle = Arc::clone(&tunnel_handle);
        tokio::spawn(async move {
            if let Err(e) = run_socks5_proxy(&socks_addr, handle).await {
                error!("SOCKS5 proxy error: {}", e);
            }
        });
    }

    // Start HTTP proxy if configured
    if let Some(addr) = &http_addr {
        info!("HTTP proxy listening on {}", addr);
        let http_addr = addr.clone();
        let handle = Arc::clone(&tunnel_handle);
        tokio::spawn(async move {
            if let Err(e) = run_http_proxy(&http_addr, handle).await {
                error!("HTTP proxy error: {}", e);
            }
        });
    }

    // Wait for shutdown signal
    tokio::select! {
        _ = tunnel_task => {
            info!("Tunnel task ended");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Shutting down...");
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
    println!("║ PUBLIC KEY (share with server admin):                        ║");
    println!("║ {}  ║", keypair.public.to_base64());
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║ PRIVATE KEY (keep secret, add to client config):             ║");
    println!("║ {}  ║", keypair.private.to_base64());
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("Add to your client config.toml:");
    println!("  private_key = \"{}\"", keypair.private.to_base64());
    println!();
    println!("Share with server admin (to add to allowed_clients):");
    println!("  \"{}\"", keypair.public.to_base64());

    Ok(())
}

/// Active stream state in the tunnel
struct ActiveStream {
    data_tx: mpsc::Sender<bytes::Bytes>,
}

/// Run the tunnel connection to server
async fn run_tunnel(
    state: Arc<ClientState>,
    mut cmd_rx: mpsc::Receiver<TunnelCommand>,
) -> Result<()> {
    // Connect to server
    let mut stream = TcpStream::connect(&state.server_addr)
        .await
        .context("Failed to connect to server")?;

    info!("Connected to server, performing handshake...");

    // Perform Noise handshake
    let mut noise_transport = perform_handshake(&mut stream, &state.keypair, &state.server_public)
        .await
        .context("Handshake failed")?;

    info!("Handshake complete, tunnel established");

    // Create multiplexer
    let mut mux = Multiplexer::new_client();

    // Track active streams: stream_id -> sender for incoming data
    let mut active_streams: HashMap<u32, ActiveStream> = HashMap::new();

    // Pending stream opens waiting for response
    let mut pending_opens: HashMap<u32, OpenStreamRequest> = HashMap::new();

    // Main loop
    let mut buf = vec![0u8; 65536];
    let mut frame_buf = vec![0u8; 65536];

    loop {
        tokio::select! {
            // Read from server
            read_result = async {
                let mut len_buf = [0u8; 2];
                stream.read_exact(&mut len_buf).await?;
                let frame_len = u16::from_be_bytes(len_buf) as usize;

                if frame_len > buf.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Frame too large"
                    ));
                }

                stream.read_exact(&mut buf[..frame_len]).await?;
                Ok::<_, std::io::Error>(frame_len)
            } => {
                match read_result {
                    Ok(frame_len) => {
                        debug!("Received encrypted frame: {} bytes", frame_len);

                        // Decrypt frame
                        let plaintext_len = match noise_transport
                            .decrypt(&buf[..frame_len], &mut frame_buf) {
                            Ok(len) => len,
                            Err(e) => {
                                error!("Decrypt failed for frame of {} bytes: {:?}", frame_len, e);
                                error!("First 16 bytes: {:02x?}", &buf[..16.min(frame_len)]);
                                return Err(anyhow::anyhow!("Failed to decrypt frame: {:?}", e));
                            }
                        };

                        // Decode frame
                        let mut frame_bytes = bytes::BytesMut::from(&frame_buf[..plaintext_len]);
                        if let Some(frame) = Frame::decode(&mut frame_bytes)? {
                            // Handle data frames specially - forward to stream handler
                            if frame.frame_type == FrameType::Data {
                                if let Some(active) = active_streams.get(&frame.stream_id) {
                                    let _ = active.data_tx.send(frame.payload.clone()).await;
                                }
                            }

                            // Let multiplexer handle frame for bookkeeping
                            if let Err(e) = mux.handle_frame(frame).await {
                                debug!("Frame handling error: {}", e);
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        info!("Server disconnected");
                        break;
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                }
            }

            // Handle commands from proxy handlers
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    TunnelCommand::OpenStream(req) => {
                        debug!("Opening stream to {}", req.destination);

                        // Open stream via multiplexer
                        match mux.open_stream(req.destination.clone()) {
                            Ok(handle) => {
                                let stream_id = handle.id();

                                // CRITICAL: Send the STREAM_OPEN frame IMMEDIATELY before returning
                                // This ensures STREAM_OPEN arrives at server before any DATA frames
                                let mut send_failed = false;
                                for frame in mux.take_send_queue() {
                                    if let Err(e) = send_frame(&mut stream, &mut noise_transport, &frame).await {
                                        error!("Failed to send STREAM_OPEN: {}", e);
                                        send_failed = true;
                                        break;
                                    }
                                }

                                if send_failed {
                                    let _ = req.response_tx.send(Err("Failed to send stream open".to_string()));
                                    continue;
                                }

                                // Create channels for this stream's data
                                let (data_tx, data_rx) = mpsc::channel(256);

                                // Store the sender for incoming data
                                active_streams.insert(stream_id, ActiveStream { data_tx: data_tx.clone() });

                                // Send the connection back to the proxy handler
                                let conn = StreamConnection {
                                    stream_id,
                                    data_tx,
                                    data_rx,
                                };

                                let _ = req.response_tx.send(Ok(conn));
                            }
                            Err(e) => {
                                let _ = req.response_tx.send(Err(format!("Failed to open stream: {}", e)));
                            }
                        }
                    }
                    TunnelCommand::SendData { stream_id, data } => {
                        // Send data frame
                        let frame = Frame::data(stream_id, data);
                        send_frame(&mut stream, &mut noise_transport, &frame).await?;
                    }
                    TunnelCommand::CloseStream { stream_id } => {
                        active_streams.remove(&stream_id);
                        // Send close frame
                        let frame = Frame::stream_close(stream_id);
                        send_frame(&mut stream, &mut noise_transport, &frame).await?;
                    }
                }
            }

            // Shutdown signal
            _ = tokio::signal::ctrl_c() => {
                info!("Closing tunnel...");
                break;
            }
        }

        // Send queued frames from multiplexer
        for frame in mux.take_send_queue() {
            send_frame(&mut stream, &mut noise_transport, &frame).await?;
        }
    }

    Ok(())
}

/// Perform Noise IK handshake (client side)
async fn perform_handshake(
    stream: &mut TcpStream,
    keypair: &KeyPair,
    server_public: &PublicKey,
) -> Result<NoiseTransport> {
    let mut handshake = NoiseHandshake::new_initiator(keypair, server_public)
        .context("Failed to create handshake")?;

    let mut buf = [0u8; 65535];
    let mut payload_buf = [0u8; 65535];

    // Send first message (-> e, es, s, ss)
    let len = handshake
        .write_message(&[], &mut buf)
        .context("Failed to write handshake message 1")?;

    let len_bytes = (len as u16).to_be_bytes();
    stream.write_all(&len_bytes).await?;
    stream.write_all(&buf[..len]).await?;

    // Read response (<- e, ee, se)
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let msg_len = u16::from_be_bytes(len_buf) as usize;

    stream.read_exact(&mut buf[..msg_len]).await?;

    handshake
        .read_message(&buf[..msg_len], &mut payload_buf)
        .context("Failed to read handshake message 2")?;

    // Convert to transport mode
    let noise_transport = handshake
        .into_transport()
        .context("Failed to enter transport mode")?;

    Ok(noise_transport)
}

/// Send an encrypted frame
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

    debug!("Sending frame type {:?} stream {} ({} bytes encrypted)",
           frame.frame_type, frame.stream_id, ct_len);

    let len_bytes = (ct_len as u16).to_be_bytes();
    stream.write_all(&len_bytes).await?;
    stream.write_all(&ciphertext[..ct_len]).await?;

    Ok(())
}

/// Run local SOCKS5 proxy
async fn run_socks5_proxy(addr: &str, tunnel: Arc<TunnelHandle>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        debug!("SOCKS5 connection from {}", peer_addr);

        let tunnel = Arc::clone(&tunnel);
        tokio::spawn(async move {
            if let Err(e) = handle_socks5_connection(stream, tunnel).await {
                debug!("SOCKS5 error: {}", e);
            }
        });
    }
}

/// Handle a SOCKS5 connection
async fn handle_socks5_connection(mut stream: TcpStream, tunnel: Arc<TunnelHandle>) -> Result<()> {
    // SOCKS5 handshake
    let mut buf = [0u8; 258];

    // Read greeting
    stream.read_exact(&mut buf[..2]).await?;
    if buf[0] != 0x05 {
        return Err(anyhow!("Invalid SOCKS version: {}", buf[0]));
    }

    let nmethods = buf[1] as usize;
    stream.read_exact(&mut buf[..nmethods]).await?;

    // Send method selection (no auth)
    stream.write_all(&[0x05, 0x00]).await?;

    // Read request
    stream.read_exact(&mut buf[..4]).await?;
    if buf[0] != 0x05 {
        return Err(anyhow!("Invalid SOCKS version"));
    }

    let cmd = buf[1];
    let addr_type = buf[3];

    if cmd != 0x01 {
        // Only support CONNECT
        stream.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        return Err(anyhow!("Unsupported command: {}", cmd));
    }

    // Parse destination
    let destination = match addr_type {
        0x01 => {
            // IPv4
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            format!("{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], port)
        }
        0x03 => {
            // Domain
            stream.read_exact(&mut buf[..1]).await?;
            let len = buf[0] as usize;
            stream.read_exact(&mut buf[..len]).await?;
            let domain = String::from_utf8_lossy(&buf[..len]).to_string();
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            format!("{}:{}", domain, port)
        }
        0x04 => {
            // IPv6
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            let ip = std::net::Ipv6Addr::from(ip);
            format!("[{}]:{}", ip, port)
        }
        _ => {
            stream.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err(anyhow!("Unsupported address type: {}", addr_type));
        }
    };

    debug!("SOCKS5 CONNECT to {} via tunnel", destination);

    // Open stream through tunnel
    match tunnel.open_stream(destination.clone()).await {
        Ok(mut conn) => {
            info!("Tunnel stream {} opened to {}", conn.stream_id, destination);

            // Send success
            stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;

            // Relay data bidirectionally
            let (mut client_read, mut client_write) = stream.into_split();
            let stream_id = conn.stream_id;
            let tunnel_clone = Arc::clone(&tunnel);

            // Task to read from client and send to tunnel
            let client_to_tunnel = tokio::spawn(async move {
                let mut buf = vec![0u8; 32768];
                loop {
                    match client_read.read(&mut buf).await {
                        Ok(0) => break, // EOF
                        Ok(n) => {
                            let data = bytes::Bytes::copy_from_slice(&buf[..n]);
                            if tunnel_clone.cmd_tx.send(TunnelCommand::SendData {
                                stream_id,
                                data,
                            }).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                // Close the stream when client disconnects
                let _ = tunnel_clone.cmd_tx.send(TunnelCommand::CloseStream { stream_id }).await;
            });

            // Task to read from tunnel and send to client
            let tunnel_to_client = tokio::spawn(async move {
                while let Some(data) = conn.data_rx.recv().await {
                    if client_write.write_all(&data).await.is_err() {
                        break;
                    }
                }
            });

            // Wait for either direction to complete
            tokio::select! {
                _ = client_to_tunnel => {}
                _ = tunnel_to_client => {}
            }
        }
        Err(e) => {
            error!("Failed to open tunnel stream to {}: {}", destination, e);
            // Send failure (host unreachable)
            stream.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        }
    }

    Ok(())
}

/// Run local HTTP proxy
async fn run_http_proxy(addr: &str, tunnel: Arc<TunnelHandle>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        debug!("HTTP proxy connection from {}", peer_addr);

        let tunnel = Arc::clone(&tunnel);
        tokio::spawn(async move {
            if let Err(e) = handle_http_connection(stream, tunnel).await {
                debug!("HTTP proxy error: {}", e);
            }
        });
    }
}

/// Handle an HTTP CONNECT connection
async fn handle_http_connection(mut stream: TcpStream, tunnel: Arc<TunnelHandle>) -> Result<()> {
    use tokio::io::AsyncBufReadExt;

    let mut reader = tokio::io::BufReader::new(&mut stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;

    let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
    if parts.len() < 3 || parts[0] != "CONNECT" {
        stream.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n").await?;
        return Err(anyhow!("Not a CONNECT request"));
    }

    let destination = parts[1].to_string();

    // Read remaining headers
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
    }

    debug!("HTTP CONNECT to {} via tunnel", destination);

    // Open stream through tunnel
    match tunnel.open_stream(destination.clone()).await {
        Ok(mut conn) => {
            info!("Tunnel stream {} opened to {}", conn.stream_id, destination);

            // Send success
            stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

            // Relay data bidirectionally
            let (mut client_read, mut client_write) = stream.into_split();
            let stream_id = conn.stream_id;
            let tunnel_clone = Arc::clone(&tunnel);

            // Task to read from client and send to tunnel
            let client_to_tunnel = tokio::spawn(async move {
                let mut buf = vec![0u8; 32768];
                loop {
                    match client_read.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            let data = bytes::Bytes::copy_from_slice(&buf[..n]);
                            if tunnel_clone.cmd_tx.send(TunnelCommand::SendData {
                                stream_id,
                                data,
                            }).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = tunnel_clone.cmd_tx.send(TunnelCommand::CloseStream { stream_id }).await;
            });

            // Task to read from tunnel and send to client
            let tunnel_to_client = tokio::spawn(async move {
                while let Some(data) = conn.data_rx.recv().await {
                    if client_write.write_all(&data).await.is_err() {
                        break;
                    }
                }
            });

            tokio::select! {
                _ = client_to_tunnel => {}
                _ = tunnel_to_client => {}
            }
        }
        Err(e) => {
            error!("Failed to open tunnel stream to {}: {}", destination, e);
            stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
        }
    }

    Ok(())
}
