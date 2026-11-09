//! End-to-end tests for the camouflage transport, driving the real
//! `phantom-server` and `phantom-client` binaries.
//!
//! Two topologies:
//!   1. plain `ws` — client and server both speak WebSocket, no TLS. Exercises
//!      the WebSocket framing and the byte-stream adapter end to end.
//!   2. `wss` behind a TLS terminator — the real deployment shape: the client
//!      speaks WebSocket-over-TLS to a terminator (standing in for Caddy) with
//!      a self-signed cert, which forwards the plaintext WebSocket to a
//!      `ws`-mode server. Proves the whole camouflage path moves data intact.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::TlsAcceptor;

use phantom_tunnel::crypto::KeyPair;

struct ChildGuard(std::process::Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// TCP echo server; returns its `ip:port`.
async fn spawn_echo() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1 << 16];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 || sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// SOCKS5 CONNECT to an `ip:port` target, send `payload`, return the echo.
async fn socks5_roundtrip(socks: &str, target: &str, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(socks).await?;
    s.set_nodelay(true).ok();
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).await?;
    assert_eq!(sel, [0x05, 0x00]);
    let (host, port) = target.rsplit_once(':').unwrap();
    let ip: std::net::Ipv4Addr = host.parse().unwrap();
    let port: u16 = port.parse().unwrap();
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip.octets());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await?;
    if rep[1] != 0 {
        return Err(std::io::Error::other(format!("SOCKS reply {}", rep[1])));
    }
    s.write_all(payload).await?;
    let mut buf = vec![0u8; payload.len()];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn wait_ready(socks: &str, echo: &str, limit: Duration) {
    let deadline = tokio::time::Instant::now() + limit;
    while tokio::time::Instant::now() < deadline {
        if let Ok(Ok(r)) = tokio::time::timeout(
            Duration::from_secs(3),
            socks5_roundtrip(socks, echo, b"ready?"),
        )
        .await
        {
            if r == b"ready?" {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("tunnel did not become ready within {limit:?}");
}

/// A terminator standing in for Caddy: accepts TLS with a self-signed cert and
/// pumps the plaintext to a plain-`ws` backend. Returns its `ip:port`.
async fn spawn_tls_terminator(backend: String) -> String {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let backend = backend.clone();
            tokio::spawn(async move {
                let tls = match acceptor.accept(tcp).await {
                    Ok(t) => t,
                    Err(_) => return,
                };
                let back = match TcpStream::connect(&backend).await {
                    Ok(b) => b,
                    Err(_) => return,
                };
                let (mut tr, mut tw) = tokio::io::split(tls);
                let (mut br, mut bw) = back.into_split();
                let up = tokio::io::copy(&mut tr, &mut bw);
                let down = tokio::io::copy(&mut br, &mut tw);
                let _ = tokio::try_join!(up, down);
            });
        }
    });
    addr
}

/// Write configs with the given transport sections and launch both binaries.
/// Returns (tempdir, server guard, client guard, socks addr).
fn launch(
    dir: &tempfile::TempDir,
    server_addr: &str,
    client_dial: &str,
    server_transport: &str,
    client_transport_toml: &str,
) -> (ChildGuard, ChildGuard, String) {
    let server_kp = KeyPair::generate().unwrap();
    let client_kp = KeyPair::generate().unwrap();

    let server_cfg = format!(
        "[server]\nlisten = \"{}\"\nprivate_key = \"{}\"\npublic_key = \"{}\"\nallowed_clients = [\"{}\"]\nmax_connections = 100\nallow_private_destinations = true\ntransport = \"{}\"\n\n[logging]\nlevel = \"warn\"\nformat = \"compact\"\n",
        server_addr,
        server_kp.private.to_base64(),
        server_kp.public.to_base64(),
        client_kp.public.to_base64(),
        server_transport,
    );
    let client_cfg = format!(
        "[client]\nserver = \"{}\"\nserver_public_key = \"{}\"\nprivate_key = \"{}\"\npublic_key = \"{}\"\n{}\n\n[logging]\nlevel = \"warn\"\nformat = \"compact\"\n",
        client_dial,
        server_kp.public.to_base64(),
        client_kp.private.to_base64(),
        client_kp.public.to_base64(),
        client_transport_toml,
    );
    let server_path = dir.path().join("server.toml");
    let client_path = dir.path().join("client.toml");
    std::fs::write(&server_path, server_cfg).unwrap();
    std::fs::write(&client_path, client_cfg).unwrap();

    let socks = {
        // Pick a port synchronously for the client's SOCKS listener.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().to_string()
    };

    let server = std::process::Command::new(env!("CARGO_BIN_EXE_phantom-server"))
        .arg("-c")
        .arg(&server_path)
        .spawn()
        .expect("spawn server");
    std::thread::sleep(Duration::from_millis(300));
    let client = std::process::Command::new(env!("CARGO_BIN_EXE_phantom-client"))
        .arg("-c")
        .arg(&client_path)
        .args(["--socks5", &socks, "--http", ""])
        .spawn()
        .expect("spawn client");

    (ChildGuard(server), ChildGuard(client), socks)
}

/// plain `ws` end to end: WebSocket framing with no TLS.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_plaintext_round_trip_and_integrity() {
    let dir = tempfile::tempdir().unwrap();
    let echo = spawn_echo().await;
    let server_addr = format!("127.0.0.1:{}", free_port().await);

    let client_transport = "[client.transport]\ntype = \"ws\"\npath = \"/relay\"";
    let (_srv, _cli, socks) = launch(&dir, &server_addr, &server_addr, "ws", client_transport);

    wait_ready(&socks, &echo, Duration::from_secs(15)).await;

    // 4 MiB through the WebSocket must come back byte-for-byte.
    let payload: Vec<u8> = (0..4 * 1024 * 1024).map(|i| (i * 31 + 7) as u8).collect();
    let got = socks5_roundtrip(&socks, &echo, &payload).await.unwrap();
    assert_eq!(got, payload, "data corrupted through the WebSocket transport");
}

/// `wss` behind a TLS terminator: the real deployment shape.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wss_behind_tls_terminator_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let echo = spawn_echo().await;

    // ws-mode server on a private port; TLS terminator (self-signed) in front.
    let server_addr = format!("127.0.0.1:{}", free_port().await);
    let tls_addr = spawn_tls_terminator(server_addr.clone()).await;

    // Client speaks wss to the terminator; cert is self-signed so insecure=true.
    let client_transport =
        "[client.transport]\ntype = \"wss\"\npath = \"/relay\"\nsni = \"localhost\"\nhost = \"localhost\"\ninsecure = true";
    let (_srv, _cli, socks) = launch(&dir, &server_addr, &tls_addr, "ws", client_transport);

    wait_ready(&socks, &echo, Duration::from_secs(15)).await;

    let payload: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i * 17 + 3) as u8).collect();
    let got = socks5_roundtrip(&socks, &echo, &payload).await.unwrap();
    assert_eq!(got, payload, "data corrupted through the wss transport");

    // A second, independent stream must also work (exercises stream reuse).
    let small = b"second stream over wss".to_vec();
    assert_eq!(socks5_roundtrip(&socks, &echo, &small).await.unwrap(), small);
}

/// A plain-TCP client must still reach a plain server (default transport
/// unchanged), proving the refactor didn't disturb the default path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plain_transport_still_works() {
    let dir = tempfile::tempdir().unwrap();
    let echo = spawn_echo().await;
    let server_addr = format!("127.0.0.1:{}", free_port().await);
    let (_srv, _cli, socks) = launch(&dir, &server_addr, &server_addr, "plain", "");
    wait_ready(&socks, &echo, Duration::from_secs(15)).await;
    let payload = vec![0xABu8; 64 * 1024];
    assert_eq!(socks5_roundtrip(&socks, &echo, &payload).await.unwrap(), payload);
}
