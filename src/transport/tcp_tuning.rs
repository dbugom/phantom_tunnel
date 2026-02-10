//! TCP socket optimization for high-throughput encrypted tunnels.
//!
//! Applies BBR congestion control (per-socket on Linux), large send/receive
//! buffers, TCP_NODELAY, TCP_QUICKACK, and TCP keepalive.

use tokio::net::TcpStream;
use tracing::{debug, warn};

/// Apply all TCP optimizations to a connected socket.
/// Call immediately after TcpStream::connect() or TcpListener::accept().
pub fn optimize_tcp_stream(stream: &TcpStream) -> std::io::Result<()> {
    let sock = socket2::SockRef::from(stream);

    // 1. TCP_NODELAY — disable Nagle's algorithm
    sock.set_nodelay(true)?;
    debug!("TCP_NODELAY enabled");

    // 2. BBR congestion control (Linux only)
    #[cfg(target_os = "linux")]
    {
        set_congestion_control(stream, "bbr");
    }

    // 3. Socket buffer sizes — 4MB each (2x BDP for 100ms RTT @ 200Mbps)
    let buf_size = 4 * 1024 * 1024;
    if let Err(e) = sock.set_recv_buffer_size(buf_size) {
        warn!("Failed to set SO_RCVBUF to 4MB: {e}");
    }
    if let Err(e) = sock.set_send_buffer_size(buf_size) {
        warn!("Failed to set SO_SNDBUF to 4MB: {e}");
    }
    debug!(
        "Socket buffers: recv={}KB send={}KB",
        sock.recv_buffer_size().unwrap_or(0) / 1024,
        sock.send_buffer_size().unwrap_or(0) / 1024
    );

    // 4. TCP_QUICKACK — disable delayed ACKs (Linux only)
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        unsafe {
            let val: libc::c_int = 1;
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_QUICKACK,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        debug!("TCP_QUICKACK enabled");
    }

    Ok(())
}

/// Set TCP keepalive parameters for long-lived tunnel connections.
pub fn set_tcp_keepalive(stream: &TcpStream) -> std::io::Result<()> {
    let sock = socket2::SockRef::from(stream);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(15))
        .with_interval(std::time::Duration::from_secs(5));
    #[cfg(not(target_os = "windows"))]
    let keepalive = keepalive.with_retries(3);
    sock.set_tcp_keepalive(&keepalive)?;
    debug!("TCP keepalive: idle=15s interval=5s retries=3");
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_congestion_control(stream: &TcpStream, algo: &str) {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let algo_bytes = algo.as_bytes();
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CONGESTION,
            algo_bytes.as_ptr() as *const libc::c_void,
            algo_bytes.len() as libc::socklen_t,
        )
    };
    if result == 0 {
        debug!("Congestion control set to {algo}");
    } else {
        warn!("Failed to set congestion control to {algo} (is tcp_bbr module loaded?)");
    }
}
