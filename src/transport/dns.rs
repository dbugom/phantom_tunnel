//! DNS Tunneling Transport
//!
//! Provides a fallback transport mechanism for heavily censored environments
//! where standard HTTPS/TLS connections are blocked.
//!
//! Data is encoded in DNS queries using:
//! - TXT record responses for server->client data
//! - Subdomain labels for client->server data (base32 encoded)
//!
//! This transport is much slower than TLS but is extremely difficult to block
//! without breaking all DNS functionality.

use super::{Transport, TransportError};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

/// Maximum data per DNS query (using subdomain labels)
/// Each label can be max 63 bytes, we use base32 encoding (5/8 efficiency)
/// Using multiple labels: ~180 bytes raw data per query
const MAX_QUERY_DATA: usize = 180;

/// Maximum data per DNS response (TXT record)
/// TXT records can hold ~255 bytes per string, we use base64
const MAX_RESPONSE_DATA: usize = 180;

/// DNS query types
#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum DnsQueryType {
    A = 1,
    TXT = 16,
    AAAA = 28,
    CNAME = 5,
    NULL = 10,
}

/// DNS tunnel configuration
#[derive(Debug, Clone)]
pub struct DnsTunnelConfig {
    /// Base domain for tunneling (e.g., "tunnel.example.com")
    pub base_domain: String,
    /// DNS resolver address
    pub resolver: SocketAddr,
    /// Query type to use
    pub query_type: DnsQueryType,
    /// Poll interval in milliseconds
    pub poll_interval: u64,
    /// Maximum retries per query
    pub max_retries: u32,
    /// Query timeout in seconds
    pub query_timeout: u64,
}

impl Default for DnsTunnelConfig {
    fn default() -> Self {
        Self {
            base_domain: String::new(),
            resolver: "8.8.8.8:53".parse().unwrap(),
            query_type: DnsQueryType::TXT,
            poll_interval: 200,
            max_retries: 3,
            query_timeout: 5,
        }
    }
}

/// DNS Tunneling Transport
///
/// Encodes tunnel data as DNS queries/responses to bypass censorship.
/// This is a last-resort transport when all other methods fail.
pub struct DnsTransport {
    config: DnsTunnelConfig,
    socket: Option<UdpSocket>,
    connected: bool,
    /// Session ID assigned by server
    session_id: Option<String>,
    /// Sequence number for ordering
    send_seq: u32,
    recv_seq: u32,
    /// Buffer for reassembling fragmented data
    recv_buffer: VecDeque<u8>,
    /// Transaction ID counter
    tx_id: u16,
}

impl DnsTransport {
    /// Create a new DNS transport
    pub fn new(config: DnsTunnelConfig) -> Self {
        Self {
            config,
            socket: None,
            connected: false,
            session_id: None,
            send_seq: 0,
            recv_seq: 0,
            recv_buffer: VecDeque::new(),
            tx_id: rand::random(),
        }
    }

    /// Encode data as DNS subdomain labels (base32)
    fn encode_subdomain(&self, data: &[u8]) -> String {
        // Use base32 for DNS-safe encoding (case-insensitive)
        let encoded = base32_encode(data);

        // Split into labels (max 63 chars each)
        let mut labels = Vec::new();
        for chunk in encoded.as_bytes().chunks(63) {
            labels.push(std::str::from_utf8(chunk).unwrap_or(""));
        }

        // Add session ID and sequence
        let session = self.session_id.as_deref().unwrap_or("new");
        format!(
            "{}.{}.s{}.{}",
            labels.join("."),
            self.send_seq,
            session,
            self.config.base_domain
        )
    }

    /// Build a DNS query packet
    fn build_query(&mut self, qname: &str, qtype: DnsQueryType) -> Vec<u8> {
        let mut packet = Vec::with_capacity(512);

        // Transaction ID
        self.tx_id = self.tx_id.wrapping_add(1);
        packet.extend_from_slice(&self.tx_id.to_be_bytes());

        // Flags: standard query, recursion desired
        packet.extend_from_slice(&[0x01, 0x00]);

        // Question count: 1
        packet.extend_from_slice(&[0x00, 0x01]);
        // Answer count: 0
        packet.extend_from_slice(&[0x00, 0x00]);
        // Authority count: 0
        packet.extend_from_slice(&[0x00, 0x00]);
        // Additional count: 0
        packet.extend_from_slice(&[0x00, 0x00]);

        // Question section
        for label in qname.split('.') {
            let len = label.len() as u8;
            packet.push(len);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0); // Root label

        // Query type
        packet.extend_from_slice(&(qtype as u16).to_be_bytes());
        // Query class: IN
        packet.extend_from_slice(&[0x00, 0x01]);

        packet
    }

    /// Parse a DNS response and extract data from TXT records
    fn parse_response(&self, packet: &[u8]) -> Result<Vec<u8>, TransportError> {
        if packet.len() < 12 {
            return Err(TransportError::Dns("Response too short".to_string()));
        }

        // Check transaction ID
        let tx_id = u16::from_be_bytes([packet[0], packet[1]]);
        if tx_id != self.tx_id {
            return Err(TransportError::Dns("Transaction ID mismatch".to_string()));
        }

        // Check response code (RCODE in lower 4 bits of byte 3)
        let rcode = packet[3] & 0x0F;
        if rcode != 0 {
            return Err(TransportError::Dns(format!("DNS error: RCODE={}", rcode)));
        }

        // Get answer count
        let ancount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
        if ancount == 0 {
            return Ok(Vec::new()); // No data
        }

        // Skip question section
        let mut pos = 12;
        while pos < packet.len() && packet[pos] != 0 {
            let len = packet[pos] as usize;
            if len >= 0xC0 {
                // Compression pointer
                pos += 2;
                break;
            }
            pos += len + 1;
        }
        if pos < packet.len() && packet[pos] == 0 {
            pos += 1;
        }
        pos += 4; // Skip QTYPE and QCLASS

        // Parse answer records
        let mut data = Vec::new();
        for _ in 0..ancount {
            if pos >= packet.len() {
                break;
            }

            // Skip name (handle compression)
            while pos < packet.len() {
                let b = packet[pos];
                if b == 0 {
                    pos += 1;
                    break;
                } else if b >= 0xC0 {
                    pos += 2;
                    break;
                } else {
                    pos += (b as usize) + 1;
                }
            }

            if pos + 10 > packet.len() {
                break;
            }

            let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
            pos += 2;
            let _rclass = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
            pos += 2;
            let _ttl = u32::from_be_bytes([packet[pos], packet[pos + 1], packet[pos + 2], packet[pos + 3]]);
            pos += 4;
            let rdlength = u16::from_be_bytes([packet[pos], packet[pos + 1]]) as usize;
            pos += 2;

            if pos + rdlength > packet.len() {
                break;
            }

            // Extract TXT record data
            if rtype == DnsQueryType::TXT as u16 {
                let mut txt_pos = pos;
                while txt_pos < pos + rdlength {
                    let txt_len = packet[txt_pos] as usize;
                    txt_pos += 1;
                    if txt_pos + txt_len <= pos + rdlength {
                        data.extend_from_slice(&packet[txt_pos..txt_pos + txt_len]);
                    }
                    txt_pos += txt_len;
                }
            }

            pos += rdlength;
        }

        // Decode base64 data
        if !data.is_empty() {
            match URL_SAFE_NO_PAD.decode(&data) {
                Ok(decoded) => return Ok(decoded),
                Err(_) => return Ok(data), // Return raw if not base64
            }
        }

        Ok(data)
    }

    /// Send a DNS query and get the response
    async fn query(&mut self, qname: &str) -> Result<Vec<u8>, TransportError> {
        // Build query first to avoid borrow conflicts
        let query_type = self.config.query_type;
        let packet = self.build_query(qname, query_type);
        let resolver = self.config.resolver;
        let max_retries = self.config.max_retries;
        let query_timeout = self.config.query_timeout;

        let socket = self
            .socket
            .as_ref()
            .ok_or_else(|| TransportError::ConnectionFailed("Not connected".to_string()))?;

        // Send query with retries
        for attempt in 0..max_retries {
            socket
                .send_to(&packet, resolver)
                .await
                .map_err(|e| TransportError::Io(e))?;

            // Wait for response
            let mut buf = [0u8; 512];
            match timeout(
                Duration::from_secs(query_timeout),
                socket.recv_from(&mut buf),
            )
            .await
            {
                Ok(Ok((len, _))) => {
                    return self.parse_response(&buf[..len]);
                }
                Ok(Err(e)) => {
                    if attempt + 1 >= max_retries {
                        return Err(TransportError::Io(e));
                    }
                }
                Err(_) => {
                    if attempt + 1 >= max_retries {
                        return Err(TransportError::Timeout);
                    }
                }
            }
        }

        Err(TransportError::Timeout)
    }

    /// Perform initial handshake to establish session
    async fn handshake(&mut self) -> Result<(), TransportError> {
        // Send INIT query
        let qname = format!("init.0.snew.{}", self.config.base_domain);
        let response = self.query(&qname).await?;

        // Parse session ID from response
        if response.len() >= 8 {
            self.session_id = Some(hex::encode(&response[..8]));
            self.connected = true;
            Ok(())
        } else {
            Err(TransportError::Dns("Invalid handshake response".to_string()))
        }
    }
}

#[async_trait]
impl Transport for DnsTransport {
    async fn connect(&mut self, _addr: &str) -> Result<(), TransportError> {
        // Create UDP socket for DNS queries
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| TransportError::Io(e))?;

        self.socket = Some(socket);

        // Perform handshake
        self.handshake().await?;

        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        if !self.connected {
            return Err(TransportError::ConnectionFailed("Not connected".to_string()));
        }

        // Fragment data if necessary
        for chunk in data.chunks(MAX_QUERY_DATA) {
            let qname = self.encode_subdomain(chunk);
            self.query(&qname).await?;
            self.send_seq = self.send_seq.wrapping_add(1);
        }

        Ok(())
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        if !self.connected {
            return Err(TransportError::ConnectionFailed("Not connected".to_string()));
        }

        // If we have buffered data, return it
        if !self.recv_buffer.is_empty() {
            let len = std::cmp::min(buf.len(), self.recv_buffer.len());
            for (i, byte) in self.recv_buffer.drain(..len).enumerate() {
                buf[i] = byte;
            }
            return Ok(len);
        }

        // Poll for data
        let session = self.session_id.as_deref().unwrap_or("unknown");
        let qname = format!("poll.{}.s{}.{}", self.recv_seq, session, self.config.base_domain);

        let data = self.query(&qname).await?;

        if data.is_empty() {
            return Ok(0);
        }

        // Handle response
        let len = std::cmp::min(buf.len(), data.len());
        buf[..len].copy_from_slice(&data[..len]);

        // Buffer any remaining
        if data.len() > len {
            self.recv_buffer.extend(&data[len..]);
        }

        self.recv_seq = self.recv_seq.wrapping_add(1);
        Ok(len)
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        if self.connected {
            // Send close notification
            if let Some(session) = &self.session_id {
                let qname = format!("close.0.s{}.{}", session, self.config.base_domain);
                let _ = self.query(&qname).await;
            }
        }

        self.connected = false;
        self.socket = None;
        self.session_id = None;

        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }
}

/// Simple base32 encoding (RFC 4648)
fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let mut result = String::new();
    let mut buffer = 0u64;
    let mut bits = 0;

    for &byte in data {
        buffer = (buffer << 8) | (byte as u64);
        bits += 8;

        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1F) as usize;
            result.push(ALPHABET[idx] as char);
        }
    }

    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1F) as usize;
        result.push(ALPHABET[idx] as char);
    }

    result
}

/// Base32 decoding
fn base32_decode(data: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let mut result = Vec::new();
    let mut buffer = 0u64;
    let mut bits = 0;

    for c in data.chars() {
        let c = c.to_ascii_uppercase();
        let val = ALPHABET.iter().position(|&x| x == c as u8)?;

        buffer = (buffer << 5) | (val as u64);
        bits += 5;

        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
        }
    }

    Some(result)
}

/// DNS Tunnel Server Handler
///
/// This handles DNS requests on the server side, extracting tunnel data
/// from queries and encoding responses.
pub struct DnsTunnelServer {
    base_domain: String,
    sessions: Arc<Mutex<std::collections::HashMap<String, SessionState>>>,
}

struct SessionState {
    send_buffer: VecDeque<u8>,
    recv_seq: u32,
    send_seq: u32,
    last_activity: std::time::Instant,
}

impl DnsTunnelServer {
    /// Create a new DNS tunnel server
    pub fn new(base_domain: String) -> Self {
        Self {
            base_domain,
            sessions: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Process an incoming DNS query and generate a response
    pub async fn process_query(&self, packet: &[u8]) -> Result<Vec<u8>, TransportError> {
        if packet.len() < 12 {
            return Err(TransportError::Dns("Query too short".to_string()));
        }

        let tx_id = u16::from_be_bytes([packet[0], packet[1]]);

        // Parse query name
        let qname = self.parse_qname(&packet[12..])?;

        // Extract command from subdomain
        let labels: Vec<&str> = qname.split('.').collect();
        if labels.len() < 3 {
            return self.build_error_response(tx_id, 3); // NXDOMAIN
        }

        // Parse the command structure
        // Format: [data_labels...].seq.sSessionId.base_domain
        let base_start = qname.find(&self.base_domain).unwrap_or(qname.len());
        let prefix = &qname[..base_start.saturating_sub(1)];
        let parts: Vec<&str> = prefix.rsplitn(3, '.').collect();

        if parts.len() < 2 {
            return self.build_error_response(tx_id, 3);
        }

        let session_part = parts[0];
        let seq_part = parts.get(1).unwrap_or(&"0");
        let data_part = parts.get(2).unwrap_or(&"");

        // Extract session ID
        let session_id = if session_part.starts_with('s') {
            &session_part[1..]
        } else {
            session_part
        };

        // Handle commands
        if data_part.starts_with("init") {
            return self.handle_init(tx_id).await;
        } else if data_part.starts_with("poll") {
            return self.handle_poll(tx_id, session_id).await;
        } else if data_part.starts_with("close") {
            return self.handle_close(tx_id, session_id).await;
        } else {
            // Data transfer
            return self.handle_data(tx_id, session_id, data_part).await;
        }
    }

    fn parse_qname(&self, data: &[u8]) -> Result<String, TransportError> {
        let mut labels = Vec::new();
        let mut pos = 0;

        while pos < data.len() {
            let len = data[pos] as usize;
            if len == 0 {
                break;
            }
            if len >= 0xC0 {
                // Compression - not supported in queries typically
                break;
            }
            pos += 1;
            if pos + len > data.len() {
                return Err(TransportError::Dns("Invalid qname".to_string()));
            }
            labels.push(
                std::str::from_utf8(&data[pos..pos + len])
                    .map_err(|_| TransportError::Dns("Invalid UTF-8 in qname".to_string()))?,
            );
            pos += len;
        }

        Ok(labels.join("."))
    }

    async fn handle_init(&self, tx_id: u16) -> Result<Vec<u8>, TransportError> {
        // Generate session ID
        let mut session_bytes = [0u8; 8];
        crate::crypto::random_bytes(&mut session_bytes);
        let session_id = hex::encode(&session_bytes);

        // Create session
        let mut sessions = self.sessions.lock().await;
        sessions.insert(
            session_id.clone(),
            SessionState {
                send_buffer: VecDeque::new(),
                recv_seq: 0,
                send_seq: 0,
                last_activity: std::time::Instant::now(),
            },
        );

        // Return session ID in TXT record
        self.build_txt_response(tx_id, &session_bytes)
    }

    async fn handle_poll(&self, tx_id: u16, session_id: &str) -> Result<Vec<u8>, TransportError> {
        let mut sessions = self.sessions.lock().await;

        if let Some(session) = sessions.get_mut(session_id) {
            session.last_activity = std::time::Instant::now();

            // Get pending data
            let len = std::cmp::min(MAX_RESPONSE_DATA, session.send_buffer.len());
            let data: Vec<u8> = session.send_buffer.drain(..len).collect();
            session.send_seq = session.send_seq.wrapping_add(1);

            self.build_txt_response(tx_id, &data)
        } else {
            self.build_error_response(tx_id, 3)
        }
    }

    async fn handle_close(&self, tx_id: u16, session_id: &str) -> Result<Vec<u8>, TransportError> {
        let mut sessions = self.sessions.lock().await;
        sessions.remove(session_id);
        self.build_txt_response(tx_id, b"OK")
    }

    async fn handle_data(
        &self,
        tx_id: u16,
        session_id: &str,
        data_labels: &str,
    ) -> Result<Vec<u8>, TransportError> {
        // Decode data from labels
        let clean_labels = data_labels.replace('.', "");
        let decoded = base32_decode(&clean_labels)
            .ok_or_else(|| TransportError::Dns("Invalid base32 data".to_string()))?;

        let mut sessions = self.sessions.lock().await;

        if let Some(session) = sessions.get_mut(session_id) {
            session.last_activity = std::time::Instant::now();
            session.recv_seq = session.recv_seq.wrapping_add(1);

            // In a real implementation, this would forward to the tunnel
            // For now, just acknowledge
            self.build_txt_response(tx_id, &[])
        } else {
            self.build_error_response(tx_id, 3)
        }
    }

    fn build_txt_response(&self, tx_id: u16, data: &[u8]) -> Result<Vec<u8>, TransportError> {
        let mut packet = Vec::with_capacity(512);

        // Header
        packet.extend_from_slice(&tx_id.to_be_bytes());
        packet.extend_from_slice(&[0x81, 0x80]); // Response, no error
        packet.extend_from_slice(&[0x00, 0x01]); // Questions: 1
        packet.extend_from_slice(&[0x00, 0x01]); // Answers: 1
        packet.extend_from_slice(&[0x00, 0x00]); // Authority: 0
        packet.extend_from_slice(&[0x00, 0x00]); // Additional: 0

        // Question section (compressed reference)
        packet.extend_from_slice(&[0xC0, 0x0C]);
        packet.extend_from_slice(&(DnsQueryType::TXT as u16).to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x01]); // Class IN

        // Answer section
        packet.extend_from_slice(&[0xC0, 0x0C]); // Name pointer
        packet.extend_from_slice(&(DnsQueryType::TXT as u16).to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x01]); // Class IN
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL: 60

        // Encode data as base64
        let encoded = URL_SAFE_NO_PAD.encode(data);
        let txt_data = encoded.as_bytes();

        // RDLENGTH and RDATA
        let rdlength = txt_data.len() + 1; // +1 for length byte
        packet.extend_from_slice(&(rdlength as u16).to_be_bytes());
        packet.push(txt_data.len() as u8);
        packet.extend_from_slice(txt_data);

        Ok(packet)
    }

    fn build_error_response(&self, tx_id: u16, rcode: u8) -> Result<Vec<u8>, TransportError> {
        let mut packet = Vec::with_capacity(12);

        packet.extend_from_slice(&tx_id.to_be_bytes());
        packet.extend_from_slice(&[0x81, 0x80 | rcode]); // Response with error
        packet.extend_from_slice(&[0x00, 0x00]); // Questions: 0
        packet.extend_from_slice(&[0x00, 0x00]); // Answers: 0
        packet.extend_from_slice(&[0x00, 0x00]); // Authority: 0
        packet.extend_from_slice(&[0x00, 0x00]); // Additional: 0

        Ok(packet)
    }

    /// Queue data to send to a session
    pub async fn queue_send(&self, session_id: &str, data: &[u8]) -> Result<(), TransportError> {
        let mut sessions = self.sessions.lock().await;

        if let Some(session) = sessions.get_mut(session_id) {
            session.send_buffer.extend(data);
            Ok(())
        } else {
            Err(TransportError::Dns("Session not found".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base32_encode_decode() {
        let data = b"Hello, World!";
        let encoded = base32_encode(data);
        let decoded = base32_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base32_empty() {
        let data = b"";
        let encoded = base32_encode(data);
        assert_eq!(encoded, "");
        let decoded = base32_decode(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_dns_config_default() {
        let config = DnsTunnelConfig::default();
        assert_eq!(config.poll_interval, 200);
        assert_eq!(config.max_retries, 3);
    }

    #[test]
    fn test_dns_transport_new() {
        let config = DnsTunnelConfig {
            base_domain: "tunnel.example.com".to_string(),
            ..Default::default()
        };
        let transport = DnsTransport::new(config);
        assert!(!transport.is_connected());
        assert!(transport.session_id.is_none());
    }

    #[test]
    fn test_build_query() {
        let config = DnsTunnelConfig {
            base_domain: "tunnel.example.com".to_string(),
            ..Default::default()
        };
        let mut transport = DnsTransport::new(config);

        let query = transport.build_query("test.tunnel.example.com", DnsQueryType::TXT);

        // Check header structure
        assert!(query.len() >= 12);
        // Check flags (standard query, RD=1)
        assert_eq!(query[2], 0x01);
        assert_eq!(query[3], 0x00);
        // Check question count
        assert_eq!(query[4], 0x00);
        assert_eq!(query[5], 0x01);
    }

    #[test]
    fn test_subdomain_encoding() {
        let config = DnsTunnelConfig {
            base_domain: "tunnel.example.com".to_string(),
            ..Default::default()
        };
        let mut transport = DnsTransport::new(config);
        transport.session_id = Some("abc123".to_string());

        let encoded = transport.encode_subdomain(b"Hello");

        // Should contain the base domain
        assert!(encoded.contains("tunnel.example.com"));
        // Should contain session reference
        assert!(encoded.contains("sabc123"));
    }
}
