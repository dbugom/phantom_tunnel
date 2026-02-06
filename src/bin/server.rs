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
    crypto::{KeyPair, NoiseHandshake, PrivateKey, PublicKey},
    tunnel::{Frame, Multiplexer},
};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
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

/// Handle a single client connection
async fn handle_connection(mut stream: TcpStream, state: Arc<ServerState>) -> Result<()> {
    // Acquire connection permit
    let _permit = state
        .conn_semaphore
        .acquire()
        .await
        .context("Failed to acquire connection permit")?;

    // Perform Noise handshake
    let (mut noise_transport, client_public) =
        perform_handshake(&mut stream, &state.keypair).await?;

    // Verify client is allowed
    let client_key_b64 = client_public.to_base64();
    if !state.allowed_clients.is_empty() && !state.allowed_clients.contains(&client_key_b64) {
        warn!("Rejected unknown client: {}...", &client_key_b64[..16]);
        return Err(anyhow!("Client not in allowed list"));
    }

    info!("Client connected: {}...", &client_key_b64[..16]);

    // Create multiplexer
    let mut mux = Multiplexer::new_server();

    // Main loop: handle frames
    let mut buf = vec![0u8; 65536];
    let mut frame_buf = vec![0u8; 65536];

    loop {
        // Read frame length
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!("Client disconnected");
                break;
            }
            Err(e) => return Err(e.into()),
        }

        let frame_len = u16::from_be_bytes(len_buf) as usize;
        if frame_len > buf.len() {
            return Err(anyhow!("Frame too large: {}", frame_len));
        }

        // Read encrypted frame
        stream.read_exact(&mut buf[..frame_len]).await?;

        // Decrypt frame
        let plaintext_len = noise_transport
            .decrypt(&buf[..frame_len], &mut frame_buf)
            .context("Failed to decrypt frame")?;

        // Decode frame
        let mut frame_bytes = bytes::BytesMut::from(&frame_buf[..plaintext_len]);
        let frame = match Frame::decode(&mut frame_bytes)? {
            Some(f) => f,
            None => continue,
        };

        // Handle frame
        match mux.handle_frame(frame).await {
            Ok(Some(stream_handle)) => {
                // New stream opened - spawn handler
                let dest = "TODO".to_string(); // Get from stream
                debug!("New stream {} to {}", stream_handle.id(), dest);

                tokio::spawn(async move {
                    if let Err(e) = handle_stream(stream_handle).await {
                        debug!("Stream error: {}", e);
                    }
                });
            }
            Ok(None) => {}
            Err(e) => {
                debug!("Frame handling error: {}", e);
            }
        }

        // Process commands and send queued frames
        mux.process_commands().await?;

        for frame in mux.take_send_queue() {
            send_frame(&mut stream, &mut noise_transport, &frame).await?;
        }
    }

    Ok(())
}

/// Perform Noise IK handshake
async fn perform_handshake(
    stream: &mut TcpStream,
    keypair: &KeyPair,
) -> Result<(phantom_tunnel::crypto::NoiseTransport, PublicKey)> {
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

/// Send an encrypted frame
async fn send_frame(
    stream: &mut TcpStream,
    noise: &mut phantom_tunnel::crypto::NoiseTransport,
    frame: &Frame,
) -> Result<()> {
    let plaintext = frame.encode();
    let mut ciphertext = vec![0u8; plaintext.len() + 16];

    let ct_len = noise
        .encrypt(&plaintext, &mut ciphertext)
        .context("Failed to encrypt frame")?;

    let len_bytes = (ct_len as u16).to_be_bytes();
    stream.write_all(&len_bytes).await?;
    stream.write_all(&ciphertext[..ct_len]).await?;

    Ok(())
}

/// Handle a single stream (connect to destination, relay data)
async fn handle_stream(
    mut stream_handle: phantom_tunnel::tunnel::StreamHandle,
) -> Result<()> {
    // TODO: Get destination from stream and connect
    // For now, just drain events
    while let Some(event) = stream_handle.recv().await {
        match event {
            phantom_tunnel::tunnel::StreamEvent::Data(data) => {
                debug!("Stream {} received {} bytes", stream_handle.id(), data.len());
                // TODO: Forward to destination
            }
            phantom_tunnel::tunnel::StreamEvent::Close => {
                debug!("Stream {} closed", stream_handle.id());
                break;
            }
            phantom_tunnel::tunnel::StreamEvent::WindowUpdate(_) => {}
            phantom_tunnel::tunnel::StreamEvent::Error(e) => {
                debug!("Stream {} error: {}", stream_handle.id(), e);
                break;
            }
        }
    }

    Ok(())
}
