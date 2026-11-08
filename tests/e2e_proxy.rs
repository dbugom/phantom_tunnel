//! End-to-end tests that launch the real `phantom-server` and `phantom-client`
//! binaries and drive traffic through the SOCKS5 proxy to a local echo server.
//!
//! These are regression tests for the stability fixes:
//! - many sequential connections (the old client stopped after ~1024 streams)
//! - data integrity across the tunnel
//! - the SSRF guard (private destinations blocked unless explicitly allowed)

use phantom_tunnel::crypto::KeyPair;
use std::process::Child;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Kills a child process when dropped so a failed assertion doesn't leak servers.
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Bind to port 0, read the assigned port, then release it so a child process
/// can claim it. (Small race window, acceptable for tests.)
async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// Minimal SOCKS5 CONNECT + round-trip: connects to `socks`, asks for `target`,
/// sends `payload`, and returns the bytes echoed back (same length).
async fn socks5_roundtrip(
    socks: &str,
    target: &str,
    payload: &[u8],
) -> std::io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(socks).await?;
    s.set_nodelay(true).ok();

    // Greeting: VER=5, 1 method, no-auth.
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).await?;
    assert_eq!(sel, [0x05, 0x00], "server must select no-auth");

    // CONNECT request with a domain-style target "host:port".
    let (host, port) = target.rsplit_once(':').unwrap();
    let port: u16 = port.parse().unwrap();
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;

    // Reply: VER, REP, RSV, ATYP + bound addr. Read header then the address.
    let mut rep = [0u8; 4];
    s.read_exact(&mut rep).await?;
    if rep[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("SOCKS reply code {}", rep[1]),
        ));
    }
    let addr_len = match rep[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize
        }
        other => panic!("unexpected ATYP {}", other),
    };
    let mut skip = vec![0u8; addr_len + 2];
    s.read_exact(&mut skip).await?;

    // Tunnel round-trip.
    s.write_all(payload).await?;
    let mut buf = vec![0u8; payload.len()];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Spawn a tiny TCP echo server; returns its address.
async fn spawn_echo() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16384];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });
    addr
}

/// Write server + client configs and launch both binaries. Returns guards and
/// the SOCKS listen address.
async fn launch(allow_private: bool) -> (tempfile::TempDir, ChildGuard, ChildGuard, String) {
    let dir = tempfile::tempdir().unwrap();
    let server_kp = KeyPair::generate().unwrap();
    let client_kp = KeyPair::generate().unwrap();

    let server_port = free_port().await;
    let socks_port = free_port().await;
    let server_addr = format!("127.0.0.1:{}", server_port);
    let socks_addr = format!("127.0.0.1:{}", socks_port);

    let server_cfg = format!(
        "[server]\nlisten = \"{}\"\nprivate_key = \"{}\"\npublic_key = \"{}\"\nallowed_clients = [\"{}\"]\nmax_connections = 1000\nallow_private_destinations = {}\n\n[logging]\nlevel = \"warn\"\nformat = \"compact\"\n",
        server_addr,
        server_kp.private.to_base64(),
        server_kp.public.to_base64(),
        client_kp.public.to_base64(),
        allow_private,
    );
    let client_cfg = format!(
        "[client]\nserver = \"{}\"\nserver_public_key = \"{}\"\nprivate_key = \"{}\"\npublic_key = \"{}\"\nsocks5_listen = \"{}\"\ntls_profile = \"chrome\"\nenable_padding = false\n\n[logging]\nlevel = \"warn\"\nformat = \"compact\"\n",
        server_addr,
        server_kp.public.to_base64(),
        client_kp.private.to_base64(),
        client_kp.public.to_base64(),
        socks_addr,
    );

    let server_cfg_path = dir.path().join("server.toml");
    let client_cfg_path = dir.path().join("client.toml");
    std::fs::write(&server_cfg_path, server_cfg).unwrap();
    std::fs::write(&client_cfg_path, client_cfg).unwrap();

    let server = std::process::Command::new(env!("CARGO_BIN_EXE_phantom-server"))
        .arg("-c")
        .arg(&server_cfg_path)
        .spawn()
        .expect("spawn server");
    // Give the server a moment to bind before the client dials.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let client = std::process::Command::new(env!("CARGO_BIN_EXE_phantom-client"))
        .arg("-c")
        .arg(&client_cfg_path)
        .spawn()
        .expect("spawn client");

    (dir, ChildGuard(server), ChildGuard(client), socks_addr)
}

/// Wait until a full round-trip through the tunnel succeeds (both processes up
/// and the tunnel established), up to ~15s.
async fn wait_ready(socks: &str, echo: &str) {
    for _ in 0..150 {
        if let Ok(r) = socks5_roundtrip(socks, echo, b"rdy").await {
            if r == b"rdy" {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("tunnel did not become ready in time");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_sequential_connections() {
    let echo = spawn_echo().await;
    let (_dir, _server, _client, socks) = launch(true).await;
    wait_ready(&socks, &echo).await;

    // The old client exhausted stream IDs after 1024 opens; go well past that.
    let total = 1500;
    let mut ok = 0;
    for i in 0..total {
        let payload = format!("msg-{:05}", i);
        match socks5_roundtrip(&socks, &echo, payload.as_bytes()).await {
            Ok(r) if r == payload.as_bytes() => ok += 1,
            Ok(r) => panic!("mismatch at {}: {:?}", i, r),
            Err(e) => panic!("connection {} failed: {}", i, e),
        }
    }
    assert_eq!(ok, total, "all {} sequential connections should succeed", total);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn larger_payload_integrity() {
    let echo = spawn_echo().await;
    let (_dir, _server, _client, socks) = launch(true).await;
    wait_ready(&socks, &echo).await;

    // ~256 KB exercises multiple frames and flow in both directions.
    let payload: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    let got = socks5_roundtrip(&socks, &echo, &payload).await.unwrap();
    assert_eq!(got, payload, "large payload must echo back byte-for-byte");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ssrf_guard_blocks_private_by_default() {
    let echo = spawn_echo().await; // echo is on 127.0.0.1 (private/loopback)
    let (_dir, _server, _client, socks) = launch(false).await; // allow_private = false
    // Wait for the SOCKS listener.
    for _ in 0..100 {
        if TcpStream::connect(&socks).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Give the tunnel time to establish.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let err = socks5_roundtrip(&socks, &echo, b"should-fail")
        .await
        .expect_err("loopback destination must be blocked when allow_private_destinations=false");
    // UnexpectedEof means the SOCKS handshake succeeded (client + tunnel up) and
    // the server then closed the stream because the destination was refused.
    // ConnectionRefused would instead mean the processes never started.
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::UnexpectedEof,
        "expected server-side refusal after a working tunnel, got: {}",
        err
    );
}

// ---------------------------------------------------------------------------
// Round 2: flow control (no head-of-line blocking) and UDP support.
// ---------------------------------------------------------------------------

use tokio::net::UdpSocket;

/// Spawn a UDP echo server; returns its address.
async fn spawn_udp_echo() -> String {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((n, src)) => {
                    let _ = sock.send_to(&buf[..n], src).await;
                }
                Err(_) => break,
            }
        }
    });
    addr
}

/// Open just the SOCKS5 CONNECT (returns the connected stream, success already
/// read) without doing a round trip — used to hold a stream open/stalled.
async fn socks5_connect(socks: &str, target: &str) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(socks).await?;
    s.set_nodelay(true).ok();
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).await?;
    let (host, port) = target.rsplit_once(':').unwrap();
    let port: u16 = port.parse().unwrap();
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;
    let mut rep = [0u8; 4];
    s.read_exact(&mut rep).await?;
    assert_eq!(rep[1], 0x00, "connect should succeed");
    let addr_len = match rep[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize
        }
        other => panic!("ATYP {}", other),
    };
    let mut skip = vec![0u8; addr_len + 2];
    s.read_exact(&mut skip).await?;
    Ok(s)
}

/// A slow/stalled stream must not block other streams (flow control removes
/// head-of-line blocking). Hold one stream that sends a large amount and never
/// reads its echo, then assert fresh streams keep completing promptly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_stream_does_not_block_others() {
    let echo = spawn_echo().await;
    let (_dir, _server, _client, socks) = launch(true).await;
    wait_ready(&socks, &echo).await;

    // Stalled stream: send ~2 MB and never read the echo back.
    let stalled = socks5_connect(&socks, &echo).await.unwrap();
    let (mut sr, mut sw) = stalled.into_split();
    let writer = tokio::spawn(async move {
        let chunk = vec![0u8; 64 * 1024];
        // Keep pushing; will eventually backpressure on this stream only.
        for _ in 0..32 {
            if sw.write_all(&chunk).await.is_err() {
                break;
            }
        }
        // Hold the read half open but never drain it.
        let mut tmp = [0u8; 1];
        let _ = sr.read(&mut tmp).await;
    });

    // Meanwhile, other streams must stay responsive.
    for i in 0..20 {
        let payload = format!("fast-{:03}", i);
        let r = tokio::time::timeout(
            Duration::from_secs(5),
            socks5_roundtrip(&socks, &echo, payload.as_bytes()),
        )
        .await
        .expect("a healthy stream must not be blocked by a stalled one")
        .unwrap();
        assert_eq!(r, payload.as_bytes());
    }
    writer.abort();
}

/// SOCKS5 UDP ASSOCIATE round trip through the tunnel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_associate_round_trip() {
    let udp_echo = spawn_udp_echo().await;
    let tcp_echo = spawn_echo().await; // for wait_ready
    let (_dir, _server, _client, socks) = launch(true).await;
    wait_ready(&socks, &tcp_echo).await;

    // UDP ASSOCIATE handshake on a TCP control connection.
    let mut ctrl = TcpStream::connect(&socks).await.unwrap();
    ctrl.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut sel = [0u8; 2];
    ctrl.read_exact(&mut sel).await.unwrap();
    // CMD=UDP ASSOCIATE(3), ATYP=IPv4, 0.0.0.0:0
    ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.unwrap();
    let mut rep = [0u8; 10]; // VER REP RSV ATYP + 4 addr + 2 port (IPv4)
    ctrl.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0x00, "UDP associate should succeed");
    let relay_port = u16::from_be_bytes([rep[8], rep[9]]);
    let relay = format!("127.0.0.1:{}", relay_port);

    // Send a datagram to the relay targeting the UDP echo server.
    let (eh, ep) = udp_echo.rsplit_once(':').unwrap();
    let echo_ip: std::net::Ipv4Addr = eh.parse().unwrap();
    let echo_port: u16 = ep.parse().unwrap();
    let mut dg = vec![0x00, 0x00, 0x00, 0x01]; // RSV RSV FRAG ATYP=IPv4
    dg.extend_from_slice(&echo_ip.octets());
    dg.extend_from_slice(&echo_port.to_be_bytes());
    dg.extend_from_slice(b"ping-udp");

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&dg, &relay).await.unwrap();

    let mut buf = vec![0u8; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("UDP echo must come back through the tunnel")
        .unwrap();
    // Response header: RSV(2) FRAG(1) ATYP(1) ADDR PORT, then data.
    assert_eq!(buf[3], 0x01, "echo source should be IPv4");
    let data = &buf[10..n]; // 3 + 1 + 4 + 2
    assert_eq!(data, b"ping-udp");

    drop(ctrl); // closing control ends the association
}

// ---------------------------------------------------------------------------
// Backward compatibility: a v1 client (empty handshake payload, no flow
// control) must still work against the v2 server.
// ---------------------------------------------------------------------------

use bytes::BytesMut;
use phantom_tunnel::crypto::{NoiseHandshake, NoiseTransport, PublicKey};
use phantom_tunnel::tunnel::Frame;

/// Launch only the server; return its address and the keys.
async fn launch_server(allow_private: bool) -> (tempfile::TempDir, ChildGuard, String, KeyPair) {
    let dir = tempfile::tempdir().unwrap();
    let server_kp = KeyPair::generate().unwrap();
    let client_kp = KeyPair::generate().unwrap();
    let server_port = free_port().await;
    let server_addr = format!("127.0.0.1:{}", server_port);

    let server_cfg = format!(
        "[server]\nlisten = \"{}\"\nprivate_key = \"{}\"\npublic_key = \"{}\"\nallowed_clients = [\"{}\"]\nmax_connections = 1000\nallow_private_destinations = {}\n\n[logging]\nlevel = \"warn\"\nformat = \"compact\"\n",
        server_addr,
        server_kp.private.to_base64(),
        server_kp.public.to_base64(),
        client_kp.public.to_base64(),
        allow_private,
    );
    let path = dir.path().join("server.toml");
    std::fs::write(&path, server_cfg).unwrap();
    let server = std::process::Command::new(env!("CARGO_BIN_EXE_phantom-server"))
        .arg("-c")
        .arg(&path)
        .spawn()
        .expect("spawn server");
    tokio::time::sleep(Duration::from_millis(400)).await;
    (dir, ChildGuard(server), server_addr, client_kp)
}

async fn send_frame(stream: &mut TcpStream, noise: &mut NoiseTransport, frame: &Frame) {
    let pt = frame.encode();
    let mut out = vec![0u8; 2 + pt.len() + 16];
    let ct = noise.encrypt(&pt, &mut out[2..]).unwrap();
    out[0..2].copy_from_slice(&(ct as u16).to_be_bytes());
    out.truncate(2 + ct);
    stream.write_all(&out).await.unwrap();
}

async fn recv_frame(stream: &mut TcpStream, noise: &mut NoiseTransport) -> Frame {
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).await.unwrap();
    let n = u16::from_be_bytes(len) as usize;
    let mut ct = vec![0u8; n];
    stream.read_exact(&mut ct).await.unwrap();
    let mut pt = vec![0u8; 65536];
    let plen = noise.decrypt(&ct, &mut pt).unwrap();
    let mut bm = BytesMut::from(&pt[..plen]);
    Frame::decode(&mut bm).unwrap().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v1_client_still_works_against_v2_server() {
    let echo = spawn_echo().await;
    let (_dir, _server, server_addr, client_kp) = launch_server(true).await;

    // Need the server's public key; re-read it is not exposed, so derive from
    // the config we wrote is awkward — instead connect using the key we know by
    // reading it back from the server config file is simplest. We stored it in
    // the temp dir; load it.
    let cfg_path = _dir.path().join("server.toml");
    let cfg_text = std::fs::read_to_string(&cfg_path).unwrap();
    let server_pub_b64 = cfg_text
        .lines()
        .find_map(|l| l.strip_prefix("public_key = "))
        .unwrap()
        .trim()
        .trim_matches('"');
    let server_pub = PublicKey::from_base64(server_pub_b64).unwrap();

    let mut stream = TcpStream::connect(&server_addr).await.unwrap();
    stream.set_nodelay(true).ok();

    // v1 handshake: initiator with an EMPTY payload (no version byte).
    let mut hs = NoiseHandshake::new_initiator(&client_kp, &server_pub).unwrap();
    let mut buf = vec![0u8; 65535];
    let len = hs.write_message(&[], &mut buf).unwrap();
    stream.write_all(&(len as u16).to_be_bytes()).await.unwrap();
    stream.write_all(&buf[..len]).await.unwrap();

    let mut rlen = [0u8; 2];
    stream.read_exact(&mut rlen).await.unwrap();
    let rn = u16::from_be_bytes(rlen) as usize;
    let mut resp = vec![0u8; rn];
    stream.read_exact(&mut resp).await.unwrap();
    let mut pbuf = vec![0u8; 65535];
    hs.read_message(&resp, &mut pbuf).unwrap();
    let mut noise = hs.into_transport().unwrap();

    // Open a stream to the echo server and do a round trip, no flow control.
    send_frame(&mut stream, &mut noise, &Frame::stream_open(1, echo.as_bytes())).await;
    send_frame(&mut stream, &mut noise, &Frame::data(1, bytes::Bytes::from_static(b"legacy"))).await;

    let frame = tokio::time::timeout(Duration::from_secs(5), recv_frame(&mut stream, &mut noise))
        .await
        .expect("v1 client should receive the echo");
    assert_eq!(&frame.payload[..], b"legacy", "v1 round trip must work");
}
