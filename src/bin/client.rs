//! Phantom Tunnel Client
//!
//! - Connects to the server (falling back to `backup_servers` in order)
//! - Performs the Noise IK handshake
//! - Runs the local SOCKS5 / HTTP CONNECT proxies
//! - Multiplexes connections through the tunnel
//!
//! `--import LINK` writes a config from a `phantom://` connect link and
//! `--share-link` prints one for the current config (see `phantom_tunnel::link`).

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use phantom_tunnel::{
    config::{ClientConfig, ClientTransportConfig, Config},
    crypto::{KeyPair, NoiseHandshake, NoiseTransport, PrivateKey, PublicKey},
    link::{self, ConnectLink, KeySource},
    transport::{self, ClientTransport, WsClient},
    tunnel::{
        udp, Frame, FrameType, InboundRx, InboundTx, RecvWindow, StreamFlow, DEFAULT_WINDOW_SIZE,
        MAX_STREAMS, MAX_WINDOW_SIZE, PROTOCOL_VERSION,
    },
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, oneshot};
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

    /// Accepted for compatibility with older launch scripts; has no effect.
    #[arg(long, hide = true)]
    #[allow(dead_code)]
    profile: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short = 'v', long, default_value = "info")]
    log_level: String,

    /// Write the config file from a phantom:// connect link, then exit. Use
    /// `--import -` to read the link from standard input, which keeps a link
    /// that contains a private key out of your shell history.
    #[arg(long, value_name = "LINK")]
    import: Option<String>,

    /// With --import: replace the server settings in an existing config file
    /// (a copy of the old file is kept as CONFIG.bak).
    #[arg(long, requires = "import")]
    force: bool,

    /// Print a connect link for this config's servers and exit. The link does
    /// not contain this device's private key.
    #[arg(long, conflicts_with = "import")]
    share_link: bool,
}

/// One server the client can use.
struct Endpoint {
    /// `host:port`
    addr: String,
    /// The server's static public key.
    public_key: PublicKey,
    /// How the tunnel is dressed up on the wire (plain TCP, or WebSocket/TLS).
    transport: ClientTransport,
}

/// Host part of a `host:port` (strips the port; unwraps `[v6]`).
fn host_of(addr: &str) -> &str {
    if let Some(rest) = addr.strip_prefix('[') {
        rest.split(']').next().unwrap_or(addr)
    } else {
        addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr)
    }
}

/// Build the wire transport for one server from the client's transport config.
/// SNI and Host default to the dialled host, so dialling the real domain needs
/// no extra settings; dialling by IP needs an explicit `sni`.
fn build_client_transport(
    cfg: Option<&ClientTransportConfig>,
    dial_addr: &str,
) -> Result<ClientTransport> {
    let cfg = match cfg {
        Some(c) => c,
        None => return Ok(ClientTransport::Plain),
    };
    match cfg.kind.as_str() {
        "plain" => Ok(ClientTransport::Plain),
        "ws" | "wss" => {
            let host = host_of(dial_addr).to_string();
            let sni = cfg.sni.clone().unwrap_or_else(|| host.clone());
            let host_header = cfg.host.clone().or_else(|| cfg.sni.clone()).unwrap_or(host);
            Ok(ClientTransport::WebSocket(WsClient {
                tls: cfg.kind == "wss",
                path: cfg.path.clone(),
                sni,
                host: host_header,
                insecure: cfg.insecure,
            }))
        }
        other => Err(anyhow!(
            "unknown client transport type {:?} (use \"plain\", \"ws\", or \"wss\")",
            other
        )),
    }
}

/// Client state
struct ClientState {
    /// Client's keypair
    keypair: KeyPair,
    /// Primary server first, then the backups, in the order to try them.
    servers: Vec<Endpoint>,
}

impl ClientState {
    /// "primary server" / "backup server 2", for log messages.
    fn describe(&self, index: usize) -> String {
        if index == 0 {
            format!("primary server {}", self.servers[0].addr)
        } else {
            format!("backup server {} ({})", index, self.servers[index].addr)
        }
    }
}

/// What one connection attempt achieved; decides whether to fail over.
#[derive(Default)]
struct SessionStats {
    /// When the Noise handshake completed.
    established_at: Option<tokio::time::Instant>,
    /// Frames received from the server after the handshake.
    frames_received: u64,
}

impl SessionStats {
    /// A session counts as working once the server has sent us something, or it
    /// stayed up for a while. A server that rejects our key completes the
    /// handshake and then closes at once, which must count as a failure.
    /// Call it right after the session ends.
    fn healthy(&self) -> bool {
        match self.established_at {
            Some(t) => self.frames_received > 0 || t.elapsed() >= HEALTHY_AFTER,
            None => false,
        }
    }
}

/// Request to open a new stream through the tunnel
struct OpenStreamRequest {
    destination: String,
    response_tx: oneshot::Sender<Result<StreamConnection, String>>,
}

/// A connection to a remote destination through the tunnel
/// The tunnel task holds the only sender for `data_rx`. When the server closes
/// the stream the tunnel drops that sender, `data_rx` returns `None`, and the
/// local socket is closed. (Keeping a second sender here, as before, meant
/// server-side closes never reached the local application.)
struct StreamConnection {
    stream_id: u32,
    data_rx: InboundRx,
    /// Send-side credit window for this stream (granted by the server's
    /// WindowUpdate frames). The uploader task acquires credit before sending.
    flow: Arc<StreamFlow>,
    /// Whether flow control is active (both ends are v2).
    flow_enabled: bool,
}

/// Tunnel command sent from proxy handlers to tunnel task
enum TunnelCommand {
    /// Open a new stream to destination
    OpenStream(OpenStreamRequest),
    /// Send data on a stream
    SendData { stream_id: u32, data: bytes::Bytes },
    /// Report bytes drained to the local socket, so the tunnel can send a
    /// WindowUpdate replenishing the peer's send window.
    StreamConsumed { stream_id: u32, bytes: u32 },
    /// Close a stream
    CloseStream { stream_id: u32 },
    /// Open a UDP association; replies with the allocated stream id.
    OpenUdp {
        response_tx: oneshot::Sender<Result<UdpSession, String>>,
    },
    /// Send one datagram (ATYP|ADDR|PORT|data) on a UDP association.
    SendUdp { stream_id: u32, payload: bytes::Bytes },
}

/// Handle to a UDP association through the tunnel.
struct UdpSession {
    stream_id: u32,
    /// Inbound datagrams from the tunnel (each ATYP|ADDR|PORT|data).
    rx: InboundRx,
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

    /// Open a UDP association through the tunnel.
    async fn open_udp(&self) -> Result<UdpSession, String> {
        let (response_tx, response_rx) = oneshot::channel();
        self.cmd_tx
            .send(TunnelCommand::OpenUdp { response_tx })
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
    if let Some(link_arg) = &args.import {
        return import_link(&args.config, link_arg, args.force);
    }

    // Load configuration
    let mut config = Config::load(&args.config).context("Failed to load configuration")?;

    if args.share_link {
        let client = config
            .client
            .as_ref()
            .ok_or_else(|| anyhow!("No [client] section in config file"))?;
        return share_link(client);
    }

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

    // Primary first, then backups in config order.
    let primary_addr = args.server.clone().unwrap_or_else(|| client_config.server.clone());
    let mut servers = vec![Endpoint {
        transport: build_client_transport(client_config.transport.as_ref(), &primary_addr)?,
        addr: primary_addr,
        public_key: server_public.clone(),
    }];
    for (i, b) in client_config.backup_servers.iter().enumerate() {
        link::validate_address(&b.address, "backup")
            .with_context(|| format!("backup_servers entry {}", i + 1))?;
        let public_key = if b.public_key.is_empty() {
            server_public.clone()
        } else {
            PublicKey::from_base64(&b.public_key)
                .with_context(|| format!("Invalid public_key for backup server {}", b.address))?
        };
        servers.push(Endpoint {
            transport: build_client_transport(client_config.transport.as_ref(), &b.address)?,
            addr: b.address.clone(),
            public_key,
        });
    }

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

        // The public key is derived from the private key; that is what the
        // server sees. The copy in the config is only for the user to share.
        let pair = KeyPair::from_private(private_key);
        if !client_config.public_key.is_empty()
            && client_config.public_key != pair.public.to_base64()
        {
            warn!(
                "public_key in the config does not match private_key; the server sees {}",
                pair.public.to_base64()
            );
        }
        pair
    };

    // Create client state
    let state = Arc::new(ClientState { keypair, servers });

    info!("Phantom Tunnel Client v{}", phantom_tunnel::VERSION);
    info!("Server: {}", state.servers[0].addr);
    if state.servers.len() > 1 {
        let backups: Vec<&str> = state.servers[1..].iter().map(|e| e.addr.as_str()).collect();
        info!("Backup servers: {}", backups.join(", "));
    }
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
    // cmd_rx is owned by the tunnel task across reconnects: run_tunnel borrows it
    // so queued/incoming proxy commands survive a dropped connection.
    let mut tunnel_cmd_rx = cmd_rx;
    let tunnel_task = tokio::spawn(async move {
        let n = tunnel_state.servers.len();
        // Server to dial next. The client sticks with whichever server last
        // worked; when one fails it moves straight on to the next in the list,
        // and only backs off once every server has failed in a row.
        let mut current = 0usize;
        let mut failed_in_round = 0usize;
        // Exponential backoff with jitter, reset after a working session.
        let mut backoff_secs: u64 = 1;
        loop {
            let mut stats = SessionStats::default();
            let result =
                run_tunnel(Arc::clone(&tunnel_state), current, &mut tunnel_cmd_rx, &mut stats).await;
            // Judge the session once, now that it has ended: healthy() looks at
            // the time since the handshake, which keeps growing while we sleep.
            let healthy = stats.healthy();
            let what = tunnel_state.describe(current);
            match &result {
                Ok(()) => info!("Tunnel to {} closed", what),
                Err(e) => error!("Tunnel to {}: {:#}", what, e),
            }
            if stats.established_at.is_some() && !healthy {
                warn!(
                    "{} closed the connection right after the handshake. This usually means \
                     this client's public key is not in its allowed_clients: {}",
                    what,
                    tunnel_state.keypair.public.to_base64()
                );
            }

            if healthy {
                failed_in_round = 0;
                backoff_secs = 1;
            } else {
                failed_in_round += 1;
                if n > 1 {
                    current = (current + 1) % n;
                    if failed_in_round < n {
                        info!("Trying {}...", tunnel_state.describe(current));
                        continue;
                    }
                }
                // Every server failed this round; back off before the next one.
                failed_in_round = 0;
            }

            // Small jitter so many clients don't reconnect in lockstep (which
            // would itself be a detectable traffic signature).
            let jitter_ms = (tunnel_state.keypair.public.as_bytes()[0] as u64) * 8;
            let wait = std::time::Duration::from_secs(backoff_secs)
                + std::time::Duration::from_millis(jitter_ms);
            info!("Reconnecting to {} in ~{}s...", tunnel_state.describe(current), backoff_secs);
            tokio::time::sleep(wait).await;
            if !healthy {
                backoff_secs = (backoff_secs * 2).min(30);
            }
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

/// `--import`: write (or update) the client config from a connect link.
fn import_link(config_path: &str, link_arg: &str, force: bool) -> Result<()> {
    use std::io::{BufRead, IsTerminal, Write};

    let from_stdin = link_arg == "-";
    let text = if from_stdin {
        if std::io::stdin().is_terminal() {
            eprint!("Paste the phantom:// link and press Enter: ");
            std::io::stderr().flush().ok();
        }
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line).context("Failed to read link from stdin")?;
        line
    } else {
        link_arg.to_string()
    };
    let link = ConnectLink::parse(&text).context("Invalid connect link")?;

    let path = std::path::Path::new(config_path);
    let existing = if path.exists() {
        if !force {
            return Err(anyhow!(
                "{} already exists. Re-run with --force to replace its server settings \
                 (this device's key and proxy ports are kept unless the link contains a key; \
                 the old file is saved as {}.bak).",
                config_path,
                config_path
            ));
        }
        let cfg = Config::load(path).with_context(|| {
            format!("{} exists but cannot be read; move it aside and import again", config_path)
        })?;
        // Rewriting a server config would drop its comments, including the
        // labels next to allowed_clients entries.
        if cfg.server.is_some() {
            return Err(anyhow!(
                "{} has a [server] section; refusing to rewrite a server config. \
                 Import into a separate client config file.",
                config_path
            ));
        }
        Some(cfg)
    } else {
        None
    };

    let existing_client = existing.as_ref().and_then(|c| c.client.as_ref());
    let (client, source) = link.to_client_config(existing_client)?;

    if existing.is_some() {
        let backup = format!("{}.bak", config_path);
        std::fs::copy(path, &backup).with_context(|| format!("Failed to back up to {}", backup))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&backup, std::fs::Permissions::from_mode(0o600));
        }
    }
    let mut config = existing.unwrap_or_default();
    config.client = Some(client.clone());
    config.save(path).context("Failed to write config")?;

    println!("Wrote {}", config_path);
    if let Some(label) = &link.label {
        println!("  Label:   {}", label);
    }
    println!("  Server:  {}", client.server);
    for b in &client.backup_servers {
        println!("  Backup:  {}", b.address);
    }
    println!();
    match source {
        KeySource::FromLink => {
            println!("The link included a key issued by the server admin for this device.");
            if !from_stdin {
                println!("It is a credential: clear it from your shell history if you pasted it on the command line.");
            }
        }
        KeySource::Kept => {
            println!("Kept this device's existing key. Its public key (already given to the admin, if it worked before):");
            println!("  {}", client.public_key);
        }
        KeySource::Generated => {
            println!("Generated a new key for this device. Send this public key to the server admin");
            println!("so they can add it to allowed_clients:");
            println!("  {}", client.public_key);
        }
    }
    println!();
    println!("Start the tunnel with:");
    println!("  phantom-client -c {}", config_path);
    Ok(())
}

/// `--share-link`: print a link for this config's servers, without the
/// device's private key.
fn share_link(client: &ClientConfig) -> Result<()> {
    let link = ConnectLink::from_client_config(client, false)?;
    println!("{}", link);
    eprintln!();
    eprintln!("This link contains the server address(es) and server key, not this device's");
    eprintln!("private key. Whoever imports it gets a new key of their own, which the server");
    eprintln!("admin must add to allowed_clients before it can connect.");
    Ok(())
}

/// Active stream state in the tunnel
struct ActiveStream {
    /// Forwards inbound payloads to the local consumer task.
    inbound: InboundTx,
    /// Send-side credit window (shared with the uploader task).
    flow: Arc<StreamFlow>,
    /// Receive window: what the server may have in flight to us (grows when
    /// the local reader keeps up).
    recv: RecvWindow,
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

/// Remove a stream and release any uploader task blocked on its send window.
fn remove_stream(streams: &mut HashMap<u32, ActiveStream>, id: u32) {
    if let Some(s) = streams.remove(&id) {
        s.flow.close();
    }
}

/// How often to send a keepalive ping.
const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(20);
/// Drop the tunnel (and reconnect) if nothing is received for this long.
const PEER_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// Initial per-stream send window as a signed credit count.
const INITIAL_WINDOW: i64 = DEFAULT_WINDOW_SIZE as i64;
/// Give up on a server that doesn't accept the TCP connection in this time
/// (DNS lookup included) and try the next one. Without it a black-holed
/// address stalls the client for the OS default of a minute or more.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Give up on a server that accepts the connection but doesn't answer the
/// handshake.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// A session that lasted this long counts as working even if idle.
const HEALTHY_AFTER: std::time::Duration = std::time::Duration::from_secs(5);

/// Run the tunnel connection to `state.servers[server]`, recording progress in
/// `stats` so the caller can tell a refused connection from a dropped one.
async fn run_tunnel(
    state: Arc<ClientState>,
    server: usize,
    cmd_rx: &mut mpsc::Receiver<TunnelCommand>,
    stats: &mut SessionStats,
) -> Result<()> {
    let endpoint = &state.servers[server];

    // Establish the outer transport (plain TCP, or WebSocket/TLS camouflage).
    // The timeout covers the whole outer handshake (TCP + TLS + WebSocket).
    let (mut read_half, mut write_half) = tokio::time::timeout(
        CONNECT_TIMEOUT,
        transport::connect_client(&endpoint.transport, &endpoint.addr),
    )
    .await
    .map_err(|_| anyhow!("timed out connecting after {}s", CONNECT_TIMEOUT.as_secs()))?
    .context("Failed to connect")?;

    info!("Connected to {}, performing handshake...", endpoint.addr);

    // Perform Noise handshake using both halves
    let (mut noise_transport, peer_version) = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        perform_handshake_split(&mut read_half, &mut write_half, &state.keypair, &endpoint.public_key),
    )
    .await
    .map_err(|_| anyhow!("handshake timed out after {}s", HANDSHAKE_TIMEOUT.as_secs()))?
    .context("Handshake failed (wrong server key, or not a Phantom Tunnel server?)")?;
    stats.established_at = Some(tokio::time::Instant::now());

    // Flow control and UDP require a v2 server. Against a v1 server we fall back
    // to the previous behaviour (no flow control, blocking forward).
    let flow_enabled = peer_version >= 2;
    info!(
        "Handshake complete, tunnel established (server protocol v{}, flow control {})",
        peer_version,
        if flow_enabled { "on" } else { "off" }
    );

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

    // Track active streams: stream_id -> sender for incoming data.
    // This map is the single source of truth for a stream's lifetime; entries
    // are removed on close so the tunnel can run indefinitely. (The old code
    // routed every frame through a Multiplexer that never freed its entries,
    // which exhausted stream IDs after ~1024 connections and buffered every
    // received byte in memory forever.)
    let mut active_streams: HashMap<u32, ActiveStream> = HashMap::new();

    // Client uses odd stream IDs; allocate monotonically and skip any id still
    // in use (collisions only possible after a ~2^31 wrap, i.e. never in one
    // session, but cheap to guard against).
    let mut next_stream_id: u32 = 1;

    // Buffer for decryption (reused across frames to avoid per-frame allocs).
    let mut frame_buf = vec![0u8; 65536];

    // Keepalive / liveness.
    let mut ping_counter: u64 = 0;
    let mut last_recv = tokio::time::Instant::now();
    let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // First tick fires immediately; consume it so we don't ping at t=0.
    keepalive.tick().await;

    loop {
        tokio::select! {
            // Receive frames from reader task
            Some(msg) = reader_rx.recv() => {
                match msg {
                    ReaderMessage::Frame(encrypted_data) => {
                        last_recv = tokio::time::Instant::now();
                        stats.frames_received += 1;

                        // Decrypt frame
                        let plaintext_len = match noise_transport.decrypt(&encrypted_data, &mut frame_buf) {
                            Ok(len) => len,
                            Err(e) => {
                                return Err(anyhow::anyhow!("Failed to decrypt frame: {:?}", e));
                            }
                        };

                        // Decode frame
                        let mut frame_bytes = bytes::BytesMut::from(&frame_buf[..plaintext_len]);
                        if let Some(frame) = Frame::decode(&mut frame_bytes)? {
                            match frame.frame_type {
                                FrameType::Data => {
                                    if let Some(active) = active_streams.get_mut(&frame.stream_id) {
                                        // v2: memory is bounded by our receive window, so a
                                        // server sending past it is cut off. (v1 servers have
                                        // no window; their channel blocks instead.)
                                        if flow_enabled && active.recv.on_received(frame.payload.len()).is_err() {
                                            debug!("Stream {} exceeded window; resetting", frame.stream_id);
                                            remove_stream(&mut active_streams, frame.stream_id);
                                            let f = Frame::stream_close(frame.stream_id);
                                            send_frame_write(&mut write_half, &mut noise_transport, &f).await?;
                                        } else if active.inbound.send(frame.payload).await.is_err() {
                                            remove_stream(&mut active_streams, frame.stream_id);
                                        }
                                    }
                                }
                                FrameType::UdpData => {
                                    // Deliver datagram to the UDP session; drop oldest
                                    // under pressure (datagram semantics allow loss).
                                    if let Some(active) = active_streams.get(&frame.stream_id) {
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
                                    // Server closed its side; drop the sender so the
                                    // consumer finishes and the socket closes.
                                    remove_stream(&mut active_streams, frame.stream_id);
                                }
                                FrameType::Ping => {
                                    // Reply so the server can measure our liveness.
                                    let data = if frame.payload.len() >= 8 {
                                        u64::from_be_bytes(frame.payload[..8].try_into().unwrap())
                                    } else { 0 };
                                    send_frame_write(&mut write_half, &mut noise_transport, &Frame::pong(data)).await?;
                                }
                                FrameType::Pong | FrameType::Padding => {}
                                FrameType::GoAway => {
                                    return Err(anyhow::anyhow!("Server sent GoAway"));
                                }
                                FrameType::StreamOpen | FrameType::UdpAssociate => {
                                    // Server never opens streams to the client.
                                }
                            }
                        }
                    }
                    ReaderMessage::Error(e) => {
                        return Err(anyhow::anyhow!("Reader error: {}", e));
                    }
                    ReaderMessage::Closed => {
                        info!("Server disconnected");
                        break;
                    }
                }
            }

            // Handle commands from proxy handlers
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    TunnelCommand::OpenStream(req) => {
                        if active_streams.len() >= MAX_STREAMS {
                            let _ = req.response_tx.send(Err("Too many concurrent streams".to_string()));
                            continue;
                        }

                        // Allocate a free odd stream id.
                        let mut stream_id = next_stream_id;
                        while active_streams.contains_key(&stream_id) {
                            stream_id = stream_id.wrapping_add(2);
                            if stream_id == 0 { stream_id = 1; }
                        }
                        next_stream_id = stream_id.wrapping_add(2);
                        if next_stream_id == 0 { next_stream_id = 1; }

                        // Send STREAM_OPEN immediately so it arrives before any
                        // DATA frames for this stream.
                        let open_frame = Frame::stream_open(stream_id, req.destination.as_bytes());
                        if let Err(e) = send_frame_write(&mut write_half, &mut noise_transport, &open_frame).await {
                            let _ = req.response_tx.send(Err(format!("Failed to send stream open: {}", e)));
                            return Err(e);
                        }

                        let (inbound, data_rx) = if flow_enabled {
                            InboundTx::credit()
                        } else {
                            InboundTx::blocking(256)
                        };
                        let flow = Arc::new(StreamFlow::new(INITIAL_WINDOW));
                        active_streams.insert(stream_id, ActiveStream {
                            inbound,
                            flow: Arc::clone(&flow),
                            recv: RecvWindow::new(MAX_WINDOW_SIZE),
                        });

                        let conn = StreamConnection { stream_id, data_rx, flow, flow_enabled };
                        let _ = req.response_tx.send(Ok(conn));
                    }
                    TunnelCommand::OpenUdp { response_tx } => {
                        if active_streams.len() >= MAX_STREAMS {
                            let _ = response_tx.send(Err("Too many concurrent streams".to_string()));
                            continue;
                        }
                        let mut stream_id = next_stream_id;
                        while active_streams.contains_key(&stream_id) {
                            stream_id = stream_id.wrapping_add(2);
                            if stream_id == 0 { stream_id = 1; }
                        }
                        next_stream_id = stream_id.wrapping_add(2);
                        if next_stream_id == 0 { next_stream_id = 1; }

                        let open = Frame::udp_associate(stream_id);
                        if let Err(e) = send_frame_write(&mut write_half, &mut noise_transport, &open).await {
                            let _ = response_tx.send(Err(format!("Failed to open UDP: {}", e)));
                            return Err(e);
                        }
                        // Larger buffer: datagrams can burst.
                        let (inbound, rx) = InboundTx::datagram(1024);
                        active_streams.insert(stream_id, ActiveStream {
                            inbound,
                            flow: Arc::new(StreamFlow::new(INITIAL_WINDOW)),
                            recv: RecvWindow::new(MAX_WINDOW_SIZE),
                        });
                        let _ = response_tx.send(Ok(UdpSession { stream_id, rx }));
                    }
                    TunnelCommand::SendData { stream_id, data } => {
                        // Drop data for a stream we've already torn down.
                        if active_streams.contains_key(&stream_id) {
                            let frame = Frame::data(stream_id, data);
                            send_frame_write(&mut write_half, &mut noise_transport, &frame).await?;
                        }
                    }
                    TunnelCommand::SendUdp { stream_id, payload } => {
                        if active_streams.contains_key(&stream_id) {
                            let frame = Frame::udp_data(stream_id, payload);
                            send_frame_write(&mut write_half, &mut noise_transport, &frame).await?;
                        }
                    }
                    TunnelCommand::StreamConsumed { stream_id, bytes } => {
                        if flow_enabled {
                            if let Some(active) = active_streams.get_mut(&stream_id) {
                                if let Some(inc) = active.recv.on_drained(bytes) {
                                    let f = Frame::window_update(stream_id, inc);
                                    send_frame_write(&mut write_half, &mut noise_transport, &f).await?;
                                }
                            }
                        }
                    }
                    TunnelCommand::CloseStream { stream_id } => {
                        if active_streams.remove(&stream_id).map(|s| s.flow.close()).is_some() {
                            let frame = Frame::stream_close(stream_id);
                            send_frame_write(&mut write_half, &mut noise_transport, &frame).await?;
                        }
                    }
                }
            }

            // Keepalive tick
            _ = keepalive.tick() => {
                if last_recv.elapsed() > PEER_IDLE_TIMEOUT {
                    return Err(anyhow::anyhow!("Peer idle timeout; reconnecting"));
                }
                ping_counter = ping_counter.wrapping_add(1);
                send_frame_write(&mut write_half, &mut noise_transport, &Frame::ping(ping_counter)).await?;
            }
        }
    }

    Ok(())
}

/// Perform Noise IK handshake with split streams.
/// Returns the transport and the peer's negotiated protocol version (0 if the
/// server is a v1 build that sent no version byte).
async fn perform_handshake_split<R, W>(
    read_half: &mut R,
    write_half: &mut W,
    keypair: &KeyPair,
    server_public: &PublicKey,
) -> Result<(NoiseTransport, u8)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut handshake = NoiseHandshake::new_initiator(keypair, server_public)
        .context("Failed to create handshake")?;

    let mut buf = [0u8; 65535];
    let mut payload_buf = [0u8; 65535];

    // Send first message (-> e, es, s, ss) carrying our protocol version as the
    // Noise payload. A v1 server ignores unknown payload bytes.
    let len = handshake
        .write_message(&[PROTOCOL_VERSION], &mut buf)
        .context("Failed to write handshake message 1")?;

    let len_bytes = (len as u16).to_be_bytes();
    write_half.write_all(&len_bytes).await?;
    write_half.write_all(&buf[..len]).await?;

    // Read response (<- e, ee, se)
    let mut len_buf = [0u8; 2];
    read_half.read_exact(&mut len_buf).await?;
    let msg_len = u16::from_be_bytes(len_buf) as usize;

    read_half.read_exact(&mut buf[..msg_len]).await?;

    let payload_len = handshake
        .read_message(&buf[..msg_len], &mut payload_buf)
        .context("Failed to read handshake message 2")?;

    // The server echoes its own version as the response payload; absent on v1.
    let peer_version = if payload_len >= 1 { payload_buf[0] } else { 0 };

    // Convert to transport mode
    let noise_transport = handshake
        .into_transport()
        .context("Failed to enter transport mode")?;

    Ok((noise_transport, peer_version))
}

/// Send an encrypted frame using write half.
/// The 2-byte length prefix and ciphertext are written in a single buffer so
/// they go out as one TCP segment (with TCP_NODELAY set), rather than two
/// writes that could be split and incur extra round-trip latency.
async fn send_frame_write<W>(
    write_half: &mut W,
    noise: &mut NoiseTransport,
    frame: &Frame,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let plaintext = frame.encode();
    // 2-byte length prefix + ciphertext (plaintext + 16-byte tag).
    let mut out = vec![0u8; 2 + plaintext.len() + 16];
    let ct_len = noise
        .encrypt(&plaintext, &mut out[2..])
        .context("Failed to encrypt frame")?;
    out[0..2].copy_from_slice(&(ct_len as u16).to_be_bytes());
    out.truncate(2 + ct_len);

    write_half.write_all(&out).await?;

    Ok(())
}

/// Relay a local TCP connection over an opened tunnel stream, in both
/// directions, applying send-side flow control when enabled. Shared by the
/// SOCKS5 and HTTP CONNECT handlers.
async fn relay_stream(
    mut conn: StreamConnection,
    mut client_read: OwnedReadHalf,
    mut client_write: OwnedWriteHalf,
    tunnel: Arc<TunnelHandle>,
) {
    let stream_id = conn.stream_id;
    let flow_enabled = conn.flow_enabled;
    let flow = Arc::clone(&conn.flow);
    let up = Arc::clone(&tunnel);

    // Uploader: local app -> tunnel. Read first, then send in credit-sized
    // chunks so one stream's backpressure never blocks the tunnel loop.
    let client_to_tunnel = tokio::spawn(async move {
        let mut buf = vec![0u8; 32768];
        'outer: loop {
            let n = match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            if flow_enabled {
                let mut sent = 0;
                while sent < n {
                    let got = flow.acquire(n - sent).await;
                    if got == 0 {
                        break 'outer; // stream closed
                    }
                    let chunk = bytes::Bytes::copy_from_slice(&buf[sent..sent + got]);
                    if up.cmd_tx.send(TunnelCommand::SendData { stream_id, data: chunk }).await.is_err() {
                        break 'outer;
                    }
                    sent += got;
                }
            } else {
                let data = bytes::Bytes::copy_from_slice(&buf[..n]);
                if up.cmd_tx.send(TunnelCommand::SendData { stream_id, data }).await.is_err() {
                    break;
                }
            }
        }
        let _ = up.cmd_tx.send(TunnelCommand::CloseStream { stream_id }).await;
    });

    // Downloader: tunnel -> local app. Report bytes drained so the tunnel can
    // replenish the peer's send window.
    let down = Arc::clone(&tunnel);
    let tunnel_to_client = tokio::spawn(async move {
        while let Some(data) = conn.data_rx.recv().await {
            let n = data.len();
            if client_write.write_all(&data).await.is_err() {
                break;
            }
            if flow_enabled && n > 0 {
                let _ = down.cmd_tx.send(TunnelCommand::StreamConsumed { stream_id, bytes: n as u32 }).await;
            }
        }
    });

    tokio::select! {
        _ = client_to_tunnel => {}
        _ = tunnel_to_client => {}
    }
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

    // UDP ASSOCIATE (0x03) is handled separately; it still reads the (ignored)
    // address/port that follow in the request.
    if cmd == 0x03 {
        return handle_udp_associate(stream, addr_type, tunnel).await;
    }

    if cmd != 0x01 {
        // Only CONNECT and UDP ASSOCIATE are supported.
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
        Ok(conn) => {
            debug!("Tunnel stream {} opened", conn.stream_id);

            // Send success
            stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;

            let (client_read, client_write) = stream.into_split();
            relay_stream(conn, client_read, client_write, tunnel).await;
        }
        Err(e) => {
            debug!("Failed to open tunnel stream: {}", e);
            // Send failure (host unreachable)
            stream.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        }
    }

    Ok(())
}

/// Handle a SOCKS5 UDP ASSOCIATE request. Binds a local UDP socket, replies with
/// its address, opens a UDP association through the tunnel, and relays datagrams
/// until the TCP control connection closes (per RFC 1928).
async fn handle_udp_associate(
    mut stream: TcpStream,
    addr_type: u8,
    tunnel: Arc<TunnelHandle>,
) -> Result<()> {
    // Consume the client's (ignored) DST.ADDR / DST.PORT from the request.
    let mut scratch = [0u8; 256];
    match addr_type {
        0x01 => { stream.read_exact(&mut scratch[..4 + 2]).await?; }
        0x04 => { stream.read_exact(&mut scratch[..16 + 2]).await?; }
        0x03 => {
            stream.read_exact(&mut scratch[..1]).await?;
            let len = scratch[0] as usize;
            stream.read_exact(&mut scratch[..len + 2]).await?;
        }
        _ => {
            stream.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err(anyhow!("Unsupported address type: {}", addr_type));
        }
    }

    // Bind the local UDP relay socket on the same interface as the control conn.
    let local_ip = stream.local_addr()?.ip();
    let udp = Arc::new(UdpSocket::bind((local_ip, 0)).await?);
    let bound = udp.local_addr()?;

    // Open the UDP association through the tunnel.
    let session = tunnel.open_udp().await.map_err(|e| anyhow!(e))?;
    let stream_id = session.stream_id;
    let mut rx = session.rx;

    // Reply: succeeded, with the UDP bind address for the app to send to.
    let mut reply = vec![0x05, 0x00, 0x00];
    let mut hdr = bytes::BytesMut::new();
    udp_encode_socketaddr(&mut hdr, bound);
    reply.extend_from_slice(&hdr);
    stream.write_all(&reply).await?;

    // The app's source address (learned from its first datagram).
    let peer: Arc<tokio::sync::Mutex<Option<std::net::SocketAddr>>> =
        Arc::new(tokio::sync::Mutex::new(None));

    // App -> tunnel: strip the 3-byte SOCKS UDP header, forward ATYP|ADDR|PORT|data.
    let up_udp = Arc::clone(&udp);
    let up_peer = Arc::clone(&peer);
    let up_tunnel = Arc::clone(&tunnel);
    let app_to_tunnel = tokio::spawn(async move {
        let mut dbuf = vec![0u8; 65535];
        loop {
            let (n, src) = match up_udp.recv_from(&mut dbuf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            *up_peer.lock().await = Some(src);
            // SOCKS5 UDP request header: RSV(2) FRAG(1) then ATYP|ADDR|PORT|data.
            if n < 3 || dbuf[2] != 0x00 {
                continue; // too short or fragmented (FRAG != 0): drop
            }
            let payload = bytes::Bytes::copy_from_slice(&dbuf[3..n]);
            if up_tunnel.cmd_tx.send(TunnelCommand::SendUdp { stream_id, payload }).await.is_err() {
                break;
            }
        }
    });

    // tunnel -> app: wrap each datagram in the SOCKS5 UDP response header.
    let down_udp = Arc::clone(&udp);
    let down_peer = Arc::clone(&peer);
    let tunnel_to_app = tokio::spawn(async move {
        while let Some(payload) = rx.recv().await {
            let dst = { *down_peer.lock().await };
            if let Some(dst) = dst {
                let mut out = Vec::with_capacity(3 + payload.len());
                out.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV, FRAG=0
                out.extend_from_slice(&payload); // already ATYP|ADDR|PORT|data
                let _ = down_udp.send_to(&out, dst).await;
            }
        }
    });

    // The association lives as long as the TCP control connection. When it
    // closes (read returns), tear everything down.
    let mut ctrl = [0u8; 256];
    let _ = stream.read(&mut ctrl).await;
    app_to_tunnel.abort();
    tunnel_to_app.abort();
    let _ = tunnel.cmd_tx.send(TunnelCommand::CloseStream { stream_id }).await;
    Ok(())
}

/// Encode a SocketAddr as SOCKS5 ATYP|ADDR|PORT into `buf`.
fn udp_encode_socketaddr(buf: &mut bytes::BytesMut, addr: std::net::SocketAddr) {
    udp::encode_ip(buf, addr);
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

    let parts: Vec<&str> = request_line.split_whitespace().collect();
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
        Ok(conn) => {
            debug!("Tunnel stream {} opened", conn.stream_id);

            // Send success
            stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

            let (client_read, client_write) = stream.into_split();
            relay_stream(conn, client_read, client_write, tunnel).await;
        }
        Err(e) => {
            debug!("Failed to open tunnel stream: {}", e);
            stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
        }
    }

    Ok(())
}
