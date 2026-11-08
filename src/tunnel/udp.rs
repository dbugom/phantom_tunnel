//! Encoding of the address header carried in `UdpData` frames.
//!
//! A `UdpData` payload is `ATYP | ADDR | PORT | datagram`, the same address
//! encoding SOCKS5 uses for its UDP request header (RFC 1928 §7), minus the
//! 2-byte reserved field and 1-byte fragment number. The client strips that
//! 3-byte prefix before tunnelling and re-adds it when delivering to the app.

use bytes::{BufMut, BytesMut};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

/// A datagram destination parsed from a `UdpData` header.
pub enum UdpTarget {
    /// A literal IP address (no resolution needed).
    Ip(SocketAddr),
    /// A domain name and port (must be resolved, then SSRF-checked).
    Domain(String, u16),
}

/// Parse `ATYP | ADDR | PORT` at the start of `payload`.
/// Returns the target and the offset where the datagram body begins.
pub fn parse_target(payload: &[u8]) -> Option<(UdpTarget, usize)> {
    match *payload.first()? {
        0x01 => {
            if payload.len() < 1 + 4 + 2 {
                return None;
            }
            let ip = Ipv4Addr::new(payload[1], payload[2], payload[3], payload[4]);
            let port = u16::from_be_bytes([payload[5], payload[6]]);
            Some((UdpTarget::Ip(SocketAddr::from((ip, port))), 7))
        }
        0x04 => {
            if payload.len() < 1 + 16 + 2 {
                return None;
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&payload[1..17]);
            let ip = Ipv6Addr::from(o);
            let port = u16::from_be_bytes([payload[17], payload[18]]);
            Some((UdpTarget::Ip(SocketAddr::from((ip, port))), 19))
        }
        0x03 => {
            if payload.len() < 2 {
                return None;
            }
            let len = payload[1] as usize;
            if payload.len() < 2 + len + 2 {
                return None;
            }
            let host = std::str::from_utf8(&payload[2..2 + len]).ok()?.to_string();
            let port = u16::from_be_bytes([payload[2 + len], payload[2 + len + 1]]);
            Some((UdpTarget::Domain(host, port), 2 + len + 2))
        }
        _ => None,
    }
}

/// Append `ATYP | ADDR | PORT` for an IP socket address to `buf`.
pub fn encode_ip(buf: &mut BytesMut, addr: SocketAddr) {
    match addr {
        SocketAddr::V4(a) => {
            buf.put_u8(0x01);
            buf.put_slice(&a.ip().octets());
            buf.put_u16(a.port());
        }
        SocketAddr::V6(a) => {
            buf.put_u8(0x04);
            buf.put_slice(&a.ip().octets());
            buf.put_u16(a.port());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_ipv4() {
        let mut buf = BytesMut::new();
        let addr: SocketAddr = "1.2.3.4:5353".parse().unwrap();
        encode_ip(&mut buf, addr);
        buf.extend_from_slice(b"hello");
        let (t, off) = parse_target(&buf).unwrap();
        match t {
            UdpTarget::Ip(a) => assert_eq!(a, addr),
            _ => panic!("expected ip"),
        }
        assert_eq!(&buf[off..], b"hello");
    }

    #[test]
    fn parse_domain() {
        let mut p = vec![0x03, 0x0b];
        p.extend_from_slice(b"example.com");
        p.extend_from_slice(&53u16.to_be_bytes());
        p.extend_from_slice(b"q");
        let (t, off) = parse_target(&p).unwrap();
        match t {
            UdpTarget::Domain(h, port) => {
                assert_eq!(h, "example.com");
                assert_eq!(port, 53);
            }
            _ => panic!("expected domain"),
        }
        assert_eq!(&p[off..], b"q");
    }
}
