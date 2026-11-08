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

/// A running server + client pair. Dropping it stops both processes.
struct Tunnel {
    _dir: tempfile::TempDir,
    _server: ChildGuard,
    _client: ChildGuard,
    /// Client SOCKS5 proxy address.
    socks: String,
    /// Client HTTP CONNECT proxy address.
    http: String,
}

/// Write server + client configs and launch both binaries.
///
/// The client config deliberately still contains `tls_profile` and
/// `enable_padding`, settings removed from the code, to prove older config
/// files keep working end to end.
async fn launch(allow_private: bool) -> Tunnel {
    launch_with(allow_private, None).await
}

/// Like [`launch`], but optionally puts a relay that delays every chunk by
/// `one_way` in each direction between client and server (simulated latency).
async fn launch_with(allow_private: bool, one_way: Option<Duration>) -> Tunnel {
    let dir = tempfile::tempdir().unwrap();
    let server_kp = KeyPair::generate().unwrap();
    let client_kp = KeyPair::generate().unwrap();

    let server_port = free_port().await;
    let socks_port = free_port().await;
    let http_port = free_port().await;
    let server_addr = format!("127.0.0.1:{}", server_port);
    let socks_addr = format!("127.0.0.1:{}", socks_port);
    let http_addr = format!("127.0.0.1:{}", http_port);

    let server_cfg = format!(
        "[server]\nlisten = \"{}\"\nprivate_key = \"{}\"\npublic_key = \"{}\"\nallowed_clients = [\"{}\"]\nmax_connections = 1000\nallow_private_destinations = {}\n\n[logging]\nlevel = \"warn\"\nformat = \"compact\"\n",
        server_addr,
        server_kp.private.to_base64(),
        server_kp.public.to_base64(),
        client_kp.public.to_base64(),
        allow_private,
    );
    // Where the client dials: the server itself, or a delay relay in front of it.
    let dial_addr = match one_way {
        Some(d) => spawn_delay_relay(server_addr.clone(), d).await,
        None => server_addr.clone(),
    };
    let client_cfg = format!(
        "[client]\nserver = \"{}\"\nserver_public_key = \"{}\"\nprivate_key = \"{}\"\npublic_key = \"{}\"\nsocks5_listen = \"{}\"\nhttp_listen = \"{}\"\ntls_profile = \"chrome\"\nenable_padding = false\n\n[logging]\nlevel = \"warn\"\nformat = \"compact\"\n",
        dial_addr,
        server_kp.public.to_base64(),
        client_kp.private.to_base64(),
        client_kp.public.to_base64(),
        socks_addr,
        http_addr,
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

    Tunnel {
        _dir: dir,
        _server: ChildGuard(server),
        _client: ChildGuard(client),
        socks: socks_addr,
        http: http_addr,
    }
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
    let t = launch(true).await;
    let socks = t.socks.clone();
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
    let t = launch(true).await;
    let socks = t.socks.clone();
    wait_ready(&socks, &echo).await;

    // ~256 KB exercises multiple frames and flow in both directions.
    let payload: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    let got = socks5_roundtrip(&socks, &echo, &payload).await.unwrap();
    assert_eq!(got, payload, "large payload must echo back byte-for-byte");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ssrf_guard_blocks_private_by_default() {
    let echo = spawn_echo().await; // echo is on 127.0.0.1 (private/loopback)
    let t = launch(false).await; // allow_private = false
    let socks = t.socks.clone();
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
        while let Ok((n, src)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..n], src).await;
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
    let t = launch(true).await;
    let socks = t.socks.clone();
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
    let t = launch(true).await;
    let socks = t.socks.clone();
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

// ---------------------------------------------------------------------------
// HTTP CONNECT proxy
// ---------------------------------------------------------------------------

/// Read an HTTP response head (up to the blank line) and return it as text.
async fn read_http_head(s: &mut TcpStream) -> std::io::Result<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read(&mut byte).await? == 0 {
            break;
        }
        head.push(byte[0]);
        if head.len() > 8192 {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

/// Send `CONNECT target` to the HTTP proxy; return the stream and the status line.
async fn http_connect(proxy: &str, target: &str) -> std::io::Result<(TcpStream, String)> {
    let mut s = TcpStream::connect(proxy).await?;
    s.set_nodelay(true).ok();
    let req = format!(
        "CONNECT {t} HTTP/1.1\r\nHost: {t}\r\nUser-Agent: e2e-test\r\nProxy-Connection: keep-alive\r\n\r\n",
        t = target
    );
    s.write_all(req.as_bytes()).await?;
    let head = read_http_head(&mut s).await?;
    let status = head.lines().next().unwrap_or("").to_string();
    Ok((s, status))
}

async fn http_roundtrip(proxy: &str, target: &str, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let (mut s, status) = http_connect(proxy, target).await?;
    if !status.starts_with("HTTP/1.1 200") {
        return Err(std::io::Error::other(format!("CONNECT refused: {}", status)));
    }
    s.write_all(payload).await?;
    let mut buf = vec![0u8; payload.len()];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_connect_round_trip_and_large_payload() {
    let echo = spawn_echo().await;
    let t = launch(true).await;
    wait_ready(&t.socks, &echo).await;

    let r = http_roundtrip(&t.http, &echo, b"hello over http connect").await.unwrap();
    assert_eq!(r, b"hello over http connect");

    // 1 MB crosses the 256 KB flow-control window several times in each direction.
    let payload: Vec<u8> = (0..1024 * 1024).map(|i| (i % 253) as u8).collect();
    let r = http_roundtrip(&t.http, &echo, &payload).await.unwrap();
    assert_eq!(r, payload, "1 MB must echo back byte-for-byte through the HTTP proxy");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_connect_many_sequential() {
    let echo = spawn_echo().await;
    let t = launch(true).await;
    wait_ready(&t.socks, &echo).await;
    for i in 0..300 {
        let msg = format!("http-{:04}", i);
        let r = http_roundtrip(&t.http, &echo, msg.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("HTTP CONNECT #{} failed: {}", i, e));
        assert_eq!(r, msg.as_bytes());
    }
}

/// Only CONNECT is supported: a plain `GET http://…` (what a system proxy sends
/// for http:// URLs) is refused with 405 rather than mishandled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_proxy_rejects_non_connect_requests() {
    let echo = spawn_echo().await;
    let t = launch(true).await;
    wait_ready(&t.socks, &echo).await;

    let mut s = TcpStream::connect(&t.http).await.unwrap();
    s.write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let head = tokio::time::timeout(Duration::from_secs(5), read_http_head(&mut s))
        .await
        .unwrap()
        .unwrap();
    assert!(head.starts_with("HTTP/1.1 405"), "got: {:?}", head);
}

/// With the SSRF guard on (the default), CONNECT to a loopback destination is
/// accepted by the local proxy but closed by the server without data.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_connect_to_private_destination_is_blocked() {
    let echo = spawn_echo().await; // 127.0.0.1 — private
    let t = launch(false).await;
    for _ in 0..100 {
        if TcpStream::connect(&t.http).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let err = http_roundtrip(&t.http, &echo, b"should-not-arrive")
        .await
        .expect_err("loopback must be refused when allow_private_destinations=false");
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof, "{}", err);
}

/// SOCKS5 and HTTP clients share the same tunnel concurrently.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks_and_http_concurrently_share_one_tunnel() {
    let echo = spawn_echo().await;
    let t = launch(true).await;
    wait_ready(&t.socks, &echo).await;

    let mut tasks = Vec::new();
    for i in 0..20 {
        let (socks, http, echo) = (t.socks.clone(), t.http.clone(), echo.clone());
        tasks.push(tokio::spawn(async move {
            let a = format!("socks-{:02}-{}", i, "x".repeat(i * 100));
            let b = format!("http-{:02}-{}", i, "y".repeat(i * 100));
            let (ra, rb) = tokio::join!(
                socks5_roundtrip(&socks, &echo, a.as_bytes()),
                http_roundtrip(&http, &echo, b.as_bytes())
            );
            assert_eq!(ra.unwrap(), a.as_bytes());
            assert_eq!(rb.unwrap(), b.as_bytes());
        }));
    }
    for task in tasks {
        tokio::time::timeout(Duration::from_secs(20), task)
            .await
            .expect("concurrent round trips must finish")
            .unwrap();
    }
}

// ---------------------------------------------------------------------------
// Throughput (on demand)
// ---------------------------------------------------------------------------

/// Measures download and upload throughput through the real binaries on
/// loopback. Ignored by default because the numbers depend on the machine;
/// run with:
///
///   cargo test --release --test e2e_proxy -- --ignored --nocapture throughput
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn throughput() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    const TOTAL: u64 = 256 * 1024 * 1024; // 256 MiB each way

    // Source: sends TOTAL bytes then closes.
    let src = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let src_addr = src.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = src.accept().await {
            tokio::spawn(async move {
                let chunk = vec![0x5Au8; 64 * 1024];
                let mut sent = 0u64;
                while sent < TOTAL {
                    if sock.write_all(&chunk).await.is_err() {
                        return;
                    }
                    sent += chunk.len() as u64;
                }
                let _ = sock.shutdown().await;
            });
        }
    });

    // Sink: counts bytes received.
    let sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sink_addr = sink.local_addr().unwrap().to_string();
    let received = Arc::new(AtomicU64::new(0));
    let rx = Arc::clone(&received);
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = sink.accept().await {
            let rx = Arc::clone(&rx);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    rx.fetch_add(n as u64, Ordering::Relaxed);
                }
            });
        }
    });

    let echo = spawn_echo().await;
    let t = launch(true).await;
    wait_ready(&t.socks, &echo).await;

    let report = |dir: &str, bytes: u64, secs: f64| {
        let mib_s = bytes as f64 / (1024.0 * 1024.0) / secs;
        println!(
            "{:>8}: {} MiB in {:.2}s = {:.1} MiB/s ({:.0} Mbit/s)",
            dir,
            bytes / (1024 * 1024),
            secs,
            mib_s,
            mib_s * 8.388_608
        );
    };

    // Download: server-side source -> client.
    let start = std::time::Instant::now();
    let mut s = socks5_connect(&t.socks, &src_addr).await.unwrap();
    let mut buf = vec![0u8; 256 * 1024];
    let mut got = 0u64;
    loop {
        let n = s.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        got += n as u64;
    }
    report("download", got, start.elapsed().as_secs_f64());
    assert_eq!(got, TOTAL, "download must deliver every byte");

    // Upload: client -> server-side sink. Timed until the sink has it all.
    let start = std::time::Instant::now();
    let mut s = socks5_connect(&t.socks, &sink_addr).await.unwrap();
    let chunk = vec![0xA5u8; 64 * 1024];
    let mut sent = 0u64;
    while sent < TOTAL {
        s.write_all(&chunk).await.unwrap();
        sent += chunk.len() as u64;
    }
    while received.load(Ordering::Relaxed) < TOTAL {
        assert!(start.elapsed() < Duration::from_secs(120), "upload stalled");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    report("upload", TOTAL, start.elapsed().as_secs_f64());
    drop(s);
}

// ---------------------------------------------------------------------------
// Simulated latency
// ---------------------------------------------------------------------------

/// Copy `r` to `w`, releasing each chunk `delay` after it was read. Chunks are
/// pipelined, so this adds latency without limiting bandwidth.
async fn delayed_pipe(
    mut r: tokio::net::tcp::OwnedReadHalf,
    mut w: tokio::net::tcp::OwnedWriteHalf,
    delay: Duration,
) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(tokio::time::Instant, Vec<u8>)>();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send((tokio::time::Instant::now() + delay, buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
            }
        }
    });
    while let Some((due, data)) = rx.recv().await {
        tokio::time::sleep_until(due).await;
        if w.write_all(&data).await.is_err() {
            break;
        }
    }
    let _ = w.shutdown().await;
}

/// A TCP relay to `upstream` that adds `one_way` delay in each direction.
async fn spawn_delay_relay(upstream: String, one_way: Duration) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((down, _)) = listener.accept().await {
            let upstream = upstream.clone();
            tokio::spawn(async move {
                let up = match TcpStream::connect(&upstream).await {
                    Ok(u) => u,
                    Err(_) => return,
                };
                down.set_nodelay(true).ok();
                up.set_nodelay(true).ok();
                let (dr, dw) = down.into_split();
                let (ur, uw) = up.into_split();
                tokio::spawn(delayed_pipe(dr, uw, one_way));
                delayed_pipe(ur, dw, one_way).await;
            });
        }
    });
    addr
}

/// Download throughput at a simulated 118 ms round trip, for 1 and 8
/// parallel connections (a speed test uses several). Ignored by default; run:
///
///   cargo test --release --test e2e_proxy -- --ignored --nocapture throughput_at_118ms
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn throughput_at_118ms_rtt() {
    // Source that streams data until the client goes away.
    let src = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let src_addr = src.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = src.accept().await {
            tokio::spawn(async move {
                let chunk = vec![0x5Au8; 64 * 1024];
                while sock.write_all(&chunk).await.is_ok() {}
            });
        }
    });

    let echo = spawn_echo().await;
    let t = launch_with(true, Some(Duration::from_millis(59))).await;
    wait_ready(&t.socks, &echo).await;

    for parallel in [1usize, 8] {
        let measure = Duration::from_secs(6);
        let mut tasks = Vec::new();
        for _ in 0..parallel {
            let (socks, src) = (t.socks.clone(), src_addr.clone());
            tasks.push(tokio::spawn(async move {
                let mut s = socks5_connect(&socks, &src).await.unwrap();
                let mut buf = vec![0u8; 256 * 1024];
                // 2 s warm-up, then count bytes for `measure`.
                let warm = tokio::time::Instant::now() + Duration::from_secs(2);
                while tokio::time::Instant::now() < warm {
                    if s.read(&mut buf).await.unwrap_or(0) == 0 {
                        return 0u64;
                    }
                }
                let end = tokio::time::Instant::now() + measure;
                let mut got = 0u64;
                while tokio::time::Instant::now() < end {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got += n as u64,
                    }
                }
                got
            }));
        }
        let mut total = 0u64;
        for task in tasks {
            total += task.await.unwrap();
        }
        let mbit = total as f64 * 8.0 / 1_000_000.0 / measure.as_secs_f64();
        println!("118 ms RTT, {} connection(s): {:.0} Mbit/s total", parallel, mbit);
    }
}

/// Regression test for the v2 slowdown: with a fixed 256 KB per-stream window
/// a single connection was capped at window/RTT (about 17 Mbit/s at a 118 ms
/// round trip). Receive windows must grow so one connection goes well beyond.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_stream_is_not_window_limited_at_high_latency() {
    let src = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let src_addr = src.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = src.accept().await {
            tokio::spawn(async move {
                let chunk = vec![0x5Au8; 64 * 1024];
                while sock.write_all(&chunk).await.is_ok() {}
            });
        }
    });

    let echo = spawn_echo().await;
    let t = launch_with(true, Some(Duration::from_millis(59))).await; // 118 ms RTT
    wait_ready(&t.socks, &echo).await;

    let mut s = socks5_connect(&t.socks, &src_addr).await.unwrap();
    let mut buf = vec![0u8; 256 * 1024];
    let warm = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < warm {
        assert!(s.read(&mut buf).await.unwrap() > 0);
    }
    let measure = Duration::from_secs(3);
    let end = tokio::time::Instant::now() + measure;
    let mut got = 0u64;
    while tokio::time::Instant::now() < end {
        got += s.read(&mut buf).await.unwrap() as u64;
    }
    let mbit = got as f64 * 8.0 / 1e6 / measure.as_secs_f64();
    println!("one connection at 118 ms RTT: {:.0} Mbit/s", mbit);
    assert!(
        mbit > 100.0,
        "one connection at 118 ms RTT reached only {:.0} Mbit/s; the receive window is not growing",
        mbit
    );
}
