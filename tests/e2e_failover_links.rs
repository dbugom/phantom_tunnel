//! End-to-end tests, with the real binaries, for backup-server failover and
//! for onboarding a client from a `phantom://` connect link.

use phantom_tunnel::crypto::{KeyPair, PublicKey};
use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Kills a child process when dropped so a failed assertion doesn't leak it.
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

async fn free_addr() -> String {
    format!("127.0.0.1:{}", free_port().await)
}

/// TCP echo server; returns its address.
async fn spawn_echo() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16384];
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

/// A listener that accepts connections and never says anything: a server that
/// is "up" at the TCP level but not answering (or a middlebox eating traffic).
async fn spawn_silent_listener() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock);
        }
    });
    addr
}

/// SOCKS5 CONNECT to `target` (an IPv4 `ip:port`) and echo `payload` back.
async fn socks5_roundtrip(socks: &str, target: &str, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(socks).await?;
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).await?;
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

/// Wait until a round-trip through the tunnel works, or panic after `limit`.
async fn wait_ready(socks: &str, echo: &str, limit: Duration) {
    let deadline = tokio::time::Instant::now() + limit;
    while tokio::time::Instant::now() < deadline {
        let attempt = tokio::time::timeout(
            Duration::from_secs(3),
            socks5_roundtrip(socks, echo, b"ready?"),
        )
        .await;
        if let Ok(Ok(r)) = attempt {
            if r == b"ready?" {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("tunnel did not become ready within {:?}", limit);
}

/// Write a server config; returns its path. Private destinations are allowed
/// because the echo server is on 127.0.0.1.
fn write_server_config(
    dir: &Path,
    name: &str,
    listen: &str,
    key: &KeyPair,
    allowed: &[&PublicKey],
) -> std::path::PathBuf {
    let allowed: Vec<String> = allowed
        .iter()
        .map(|k| format!("\"{}\"", k.to_base64()))
        .collect();
    let cfg = format!(
        "[server]\nlisten = \"{}\"\nprivate_key = \"{}\"\npublic_key = \"{}\"\nallowed_clients = [{}]\nmax_connections = 100\nallow_private_destinations = true\n",
        listen,
        key.private.to_base64(),
        key.public.to_base64(),
        allowed.join(", "),
    );
    let path = dir.join(format!("{}.toml", name));
    std::fs::write(&path, cfg).unwrap();
    path
}

/// Write a server config and start the server.
fn start_server(
    dir: &Path,
    name: &str,
    listen: &str,
    key: &KeyPair,
    allowed: &[&PublicKey],
) -> ChildGuard {
    let path = write_server_config(dir, name, listen, key, allowed);
    ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_phantom-server"))
            .arg("-c")
            .arg(&path)
            .args(["-v", "warn"])
            .spawn()
            .expect("spawn server"),
    )
}

/// Start the client with `config`, its logs going to `<dir>/client.log`.
fn start_client(dir: &Path, config: &Path, socks: &str, http: &str) -> ChildGuard {
    let log = std::fs::File::create(dir.join("client.log")).unwrap();
    ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_phantom-client"))
            .arg("-c")
            .arg(config)
            .args(["--socks5", socks, "--http", http, "-v", "info"])
            .stdout(Stdio::from(log))
            .spawn()
            .expect("spawn client"),
    )
}

fn client_log(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("client.log")).unwrap_or_default()
}

/// Client config whose primary is `primary` and whose backup list is the raw
/// TOML in `backups`.
fn write_client_config(
    dir: &Path,
    primary: &str,
    server_key: &PublicKey,
    me: &KeyPair,
    backups: &str,
) -> std::path::PathBuf {
    let cfg = format!(
        "[client]\nserver = \"{}\"\nserver_public_key = \"{}\"\nprivate_key = \"{}\"\npublic_key = \"{}\"\nsocks5_listen = \"127.0.0.1:1\"\n{}\n",
        primary,
        server_key.to_base64(),
        me.private.to_base64(),
        me.public.to_base64(),
        backups,
    );
    let path = dir.join("client.toml");
    std::fs::write(&path, cfg).unwrap();
    path
}

/// Nothing listens on the primary address: the client must move on to the
/// backup (a bare "host:port" entry sharing the primary's key) at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fails_over_when_primary_is_down() {
    let dir = tempfile::tempdir().unwrap();
    let echo = spawn_echo().await;
    let server_key = KeyPair::generate().unwrap();
    let me = KeyPair::generate().unwrap();
    let dead = free_addr().await;
    let backup = free_addr().await;
    let _server = start_server(dir.path(), "backup", &backup, &server_key, &[&me.public]);
    tokio::time::sleep(Duration::from_millis(300)).await;

    let cfg = write_client_config(
        dir.path(),
        &dead,
        &server_key.public,
        &me,
        &format!("backup_servers = [\"{}\"]", backup),
    );
    let (socks, http) = (free_addr().await, free_addr().await);
    let _client = start_client(dir.path(), &cfg, &socks, &http);

    // Well under the 1+2+4 s backoff a single-server client would need.
    wait_ready(&socks, &echo, Duration::from_secs(5)).await;
    let log = client_log(dir.path());
    assert!(
        log.contains("Trying backup server 1"),
        "client log:\n{}",
        log
    );
}

/// The primary is up but does not allow this client (it closes right after
/// the handshake). That must count as a failure: the client moves to the
/// backup — a different server with its own key — and logs a hint with the
/// key to authorise.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fails_over_when_primary_rejects_this_client() {
    let dir = tempfile::tempdir().unwrap();
    let echo = spawn_echo().await;
    let primary_key = KeyPair::generate().unwrap();
    let backup_key = KeyPair::generate().unwrap();
    let me = KeyPair::generate().unwrap();
    let someone_else = KeyPair::generate().unwrap();
    let (primary, backup) = (free_addr().await, free_addr().await);
    let _primary = start_server(
        dir.path(),
        "primary",
        &primary,
        &primary_key,
        &[&someone_else.public],
    );
    let _backup = start_server(dir.path(), "backup", &backup, &backup_key, &[&me.public]);
    tokio::time::sleep(Duration::from_millis(300)).await;

    let cfg = write_client_config(
        dir.path(),
        &primary,
        &primary_key.public,
        &me,
        &format!(
            "\n[[client.backup_servers]]\naddress = \"{}\"\npublic_key = \"{}\"",
            backup,
            backup_key.public.to_base64()
        ),
    );
    let (socks, http) = (free_addr().await, free_addr().await);
    let _client = start_client(dir.path(), &cfg, &socks, &http);

    wait_ready(&socks, &echo, Duration::from_secs(5)).await;
    let log = client_log(dir.path());
    assert!(
        log.contains("not in its allowed_clients"),
        "client log:\n{}",
        log
    );
    assert!(
        log.contains(&me.public.to_base64()),
        "hint must show the key to add:\n{}",
        log
    );
}

/// The primary accepts TCP but never answers the handshake. The client must
/// give up after its handshake timeout instead of hanging, and use the backup.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fails_over_when_primary_never_answers() {
    let dir = tempfile::tempdir().unwrap();
    let echo = spawn_echo().await;
    let server_key = KeyPair::generate().unwrap();
    let me = KeyPair::generate().unwrap();
    let silent = spawn_silent_listener().await;
    let backup = free_addr().await;
    let _server = start_server(dir.path(), "backup", &backup, &server_key, &[&me.public]);
    tokio::time::sleep(Duration::from_millis(300)).await;

    let cfg = write_client_config(
        dir.path(),
        &silent,
        &server_key.public,
        &me,
        &format!("backup_servers = [{{ address = \"{}\" }}]", backup),
    );
    let (socks, http) = (free_addr().await, free_addr().await);
    let _client = start_client(dir.path(), &cfg, &socks, &http);

    // 10 s handshake timeout plus slack.
    wait_ready(&socks, &echo, Duration::from_secs(20)).await;
    let log = client_log(dir.path());
    assert!(log.contains("handshake timed out"), "client log:\n{}", log);
}

/// Run `phantom-client --import -` feeding `link` on stdin; returns stdout.
fn import(config: &Path, link: &str, extra: &[&str]) -> (bool, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_phantom-client"))
        .arg("-c")
        .arg(config)
        .args(["--import", "-"])
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{}", link).unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Run `phantom-server -c <cfg> link ...`; returns (stdout, stderr).
fn make_link(server_cfg: &Path, args: &[&str]) -> (String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_phantom-server"))
        .arg("-c")
        .arg(server_cfg)
        .arg("link")
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "link failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    (
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// One-step onboarding: the admin issues a link with a client key, adds the
/// printed public key to allowed_clients, and the recipient imports the link
/// and connects — no key exchange back and forth.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn link_with_issued_key_imports_and_connects() {
    let dir = tempfile::tempdir().unwrap();
    let echo = spawn_echo().await;
    let server_key = KeyPair::generate().unwrap();
    let listen = free_addr().await;
    let port = listen.rsplit_once(':').unwrap().1.to_string();

    // A key-only server config, as the admin has before issuing links.
    let server_cfg = write_server_config(dir.path(), "server", &listen, &server_key, &[]);
    let (link, notes) = make_link(
        &server_cfg,
        &[
            "--address",
            "127.0.0.1",
            "--label",
            "test device",
            "--new-client-key",
        ],
    );
    assert!(
        link.starts_with("phantom://") && link.contains(&format!("@127.0.0.1:{}", port)),
        "{}",
        link
    );
    assert!(link.contains("key="), "{}", link);
    // The public key to authorise is printed as an allowed_clients line.
    let authorise = notes
        .lines()
        .find(|l| l.contains("# test device"))
        .and_then(|l| l.split('"').nth(1))
        .unwrap_or_else(|| panic!("no allowed_clients line in:\n{}", notes))
        .to_string();
    let client_pub = PublicKey::from_base64(&authorise).unwrap();

    let _server = start_server(dir.path(), "server", &listen, &server_key, &[&client_pub]);
    tokio::time::sleep(Duration::from_millis(300)).await;

    let cfg = dir.path().join("client.toml");
    let (ok, out, err) = import(&cfg, &link, &[]);
    assert!(ok, "import failed: {}", err);
    assert!(out.contains("issued by the server admin"), "{}", out);
    let written = std::fs::read_to_string(&cfg).unwrap();
    assert!(
        written.contains(&client_pub.to_base64()),
        "config must hold the issued key:\n{}",
        written
    );

    let (socks, http) = (free_addr().await, free_addr().await);
    let _client = start_client(dir.path(), &cfg, &socks, &http);
    wait_ready(&socks, &echo, Duration::from_secs(10)).await;
}

/// Two-step onboarding: a key-less link; the device generates its own key on
/// import and prints the public key, which the admin then authorises.
/// Re-importing an updated link (with --force) keeps that identity.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keyless_link_generates_key_and_reimport_keeps_it() {
    let dir = tempfile::tempdir().unwrap();
    let echo = spawn_echo().await;
    let server_key = KeyPair::generate().unwrap();
    let listen = free_addr().await;
    let server_cfg = write_server_config(dir.path(), "server", &listen, &server_key, &[]);
    let (link, _) = make_link(&server_cfg, &["--address", &listen]);
    assert!(!link.contains("key="), "{}", link);

    let cfg = dir.path().join("client.toml");
    let (ok, out, err) = import(&cfg, &link, &[]);
    assert!(ok, "import failed: {}", err);
    assert!(out.contains("Generated a new key"), "{}", out);
    // The printed public key is the line after "allowed_clients:".
    let printed = out
        .lines()
        .skip_while(|l| !l.contains("allowed_clients:"))
        .nth(1)
        .unwrap()
        .trim()
        .to_string();
    let device_pub = PublicKey::from_base64(&printed).unwrap();

    // Never rewrite a server config, even with --force.
    let (ok, _, err) = import(&server_cfg, &link, &["--force"]);
    assert!(!ok && err.contains("[server] section"), "{}", err);
    assert!(std::fs::read_to_string(&server_cfg).unwrap().contains("allow_private_destinations"));

    // Importing again without --force is refused; with --force the key stays.
    let (ok, _, err) = import(&cfg, &link, &[]);
    assert!(!ok && err.contains("--force"), "{}", err);
    let (updated, _) = make_link(
        &server_cfg,
        &["--address", &listen, "--backup", "127.0.0.1:9"],
    );
    let (ok, out, err) = import(&cfg, &updated, &["--force"]);
    assert!(ok, "re-import failed: {}", err);
    assert!(
        out.contains("Kept this device's existing key") && out.contains(&printed),
        "{}",
        out
    );
    assert!(dir.path().join("client.toml.bak").exists());
    assert!(std::fs::read_to_string(&cfg)
        .unwrap()
        .contains("127.0.0.1:9"));

    let _server = start_server(dir.path(), "server", &listen, &server_key, &[&device_pub]);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (socks, http) = (free_addr().await, free_addr().await);
    let _client = start_client(dir.path(), &cfg, &socks, &http);
    wait_ready(&socks, &echo, Duration::from_secs(10)).await;

    // --share-link reproduces the servers but never this device's private key.
    let shared = Command::new(env!("CARGO_BIN_EXE_phantom-client"))
        .arg("-c")
        .arg(&cfg)
        .arg("--share-link")
        .output()
        .unwrap();
    let shared = String::from_utf8_lossy(&shared.stdout).trim().to_string();
    assert_eq!(shared, updated, "shared link should match the imported one");
}
