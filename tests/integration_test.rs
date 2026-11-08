//! Integration tests for the Phantom Tunnel library:
//! - Noise IK handshake over real TCP sockets
//! - Encrypted data transfer
//! - Frame format, including its exact on-wire layout

use bytes::Bytes;
use phantom_tunnel::crypto::{KeyPair, NoiseHandshake};
use phantom_tunnel::tunnel::{Frame, FrameType, FRAME_HEADER_SIZE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Test basic Noise IK handshake between client and server
#[tokio::test]
async fn test_noise_handshake() {
    // Generate keypairs
    let server_keypair = KeyPair::generate().expect("Failed to generate server keypair");
    let client_keypair = KeyPair::generate().expect("Failed to generate client keypair");

    // Start a test server
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let server_pubkey = server_keypair.public.clone();

    // Server task
    let server_kp = server_keypair.clone();
    let server_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // Responder handshake
        let mut handshake =
            NoiseHandshake::new_responder(&server_kp).expect("Failed to create responder");

        // Read first message
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.unwrap();
        let msg_len = u16::from_be_bytes(len_buf) as usize;

        let mut buf = vec![0u8; msg_len];
        stream.read_exact(&mut buf).await.unwrap();

        let mut payload_buf = [0u8; 65535];
        handshake
            .read_message(&buf, &mut payload_buf)
            .expect("Failed to read handshake message");

        // Get client's public key
        let client_pub = handshake
            .get_remote_static()
            .expect("Failed to get remote static");

        // Send response
        let mut response_buf = [0u8; 65535];
        let resp_len = handshake
            .write_message(&[], &mut response_buf)
            .expect("Failed to write response");

        let len_bytes = (resp_len as u16).to_be_bytes();
        stream.write_all(&len_bytes).await.unwrap();
        stream.write_all(&response_buf[..resp_len]).await.unwrap();

        // Convert to transport
        let transport = handshake
            .into_transport()
            .expect("Failed to enter transport mode");

        (transport, client_pub)
    });

    // Client task
    let mut client_stream = TcpStream::connect(server_addr).await.unwrap();

    // Initiator handshake
    let mut client_handshake =
        NoiseHandshake::new_initiator(&client_keypair, &server_pubkey)
            .expect("Failed to create initiator");

    // Send first message
    let mut buf = [0u8; 65535];
    let msg_len = client_handshake
        .write_message(&[], &mut buf)
        .expect("Failed to write handshake");

    let len_bytes = (msg_len as u16).to_be_bytes();
    client_stream.write_all(&len_bytes).await.unwrap();
    client_stream.write_all(&buf[..msg_len]).await.unwrap();

    // Read response
    let mut len_buf = [0u8; 2];
    client_stream.read_exact(&mut len_buf).await.unwrap();
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    let mut resp_buf = vec![0u8; resp_len];
    client_stream.read_exact(&mut resp_buf).await.unwrap();

    let mut payload_buf = [0u8; 65535];
    client_handshake
        .read_message(&resp_buf, &mut payload_buf)
        .expect("Failed to read response");

    // Convert to transport
    let _client_transport = client_handshake
        .into_transport()
        .expect("Failed to enter transport mode");

    // Wait for server
    let (_server_transport, client_pub_from_server) = server_handle.await.unwrap();

    // Verify handshake completed
    assert_eq!(
        client_pub_from_server.to_base64(),
        client_keypair.public.to_base64()
    );
}

/// Test encrypted message exchange after handshake
#[tokio::test]
async fn test_encrypted_communication() {
    let server_keypair = KeyPair::generate().unwrap();
    let client_keypair = KeyPair::generate().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let server_pubkey = server_keypair.public.clone();

    let server_kp = server_keypair.clone();
    let server_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // Complete handshake
        let mut handshake = NoiseHandshake::new_responder(&server_kp).unwrap();

        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.unwrap();
        let msg_len = u16::from_be_bytes(len_buf) as usize;

        let mut buf = vec![0u8; msg_len];
        stream.read_exact(&mut buf).await.unwrap();

        let mut payload_buf = [0u8; 65535];
        handshake.read_message(&buf, &mut payload_buf).unwrap();

        let mut response_buf = [0u8; 65535];
        let resp_len = handshake.write_message(&[], &mut response_buf).unwrap();

        let len_bytes = (resp_len as u16).to_be_bytes();
        stream.write_all(&len_bytes).await.unwrap();
        stream.write_all(&response_buf[..resp_len]).await.unwrap();

        let mut transport = handshake.into_transport().unwrap();

        // Receive encrypted message
        stream.read_exact(&mut len_buf).await.unwrap();
        let ct_len = u16::from_be_bytes(len_buf) as usize;

        let mut ciphertext = vec![0u8; ct_len];
        stream.read_exact(&mut ciphertext).await.unwrap();

        let mut plaintext = vec![0u8; ct_len];
        let pt_len = transport.decrypt(&ciphertext, &mut plaintext).unwrap();

        String::from_utf8(plaintext[..pt_len].to_vec()).unwrap()
    });

    // Client side
    let mut client_stream = TcpStream::connect(server_addr).await.unwrap();

    let mut client_handshake =
        NoiseHandshake::new_initiator(&client_keypair, &server_pubkey).unwrap();

    let mut buf = [0u8; 65535];
    let msg_len = client_handshake.write_message(&[], &mut buf).unwrap();

    let len_bytes = (msg_len as u16).to_be_bytes();
    client_stream.write_all(&len_bytes).await.unwrap();
    client_stream.write_all(&buf[..msg_len]).await.unwrap();

    let mut len_buf = [0u8; 2];
    client_stream.read_exact(&mut len_buf).await.unwrap();
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    let mut resp_buf = vec![0u8; resp_len];
    client_stream.read_exact(&mut resp_buf).await.unwrap();

    let mut payload_buf = [0u8; 65535];
    client_handshake.read_message(&resp_buf, &mut payload_buf).unwrap();

    let mut client_transport = client_handshake.into_transport().unwrap();

    // Send encrypted message
    let message = b"Hello, Phantom Tunnel!";
    let mut ciphertext = vec![0u8; message.len() + 16]; // +16 for auth tag

    let ct_len = client_transport.encrypt(message, &mut ciphertext).unwrap();

    let len_bytes = (ct_len as u16).to_be_bytes();
    client_stream.write_all(&len_bytes).await.unwrap();
    client_stream.write_all(&ciphertext[..ct_len]).await.unwrap();

    // Verify server received correct message
    let received = server_handle.await.unwrap();
    assert_eq!(received, "Hello, Phantom Tunnel!");
}

/// Test frame encoding and decoding
#[tokio::test]
async fn test_frame_roundtrip() {
    let test_data = b"Test frame payload data";
    let stream_id = 42;

    // Create data frame
    let frame = Frame::data(stream_id, Bytes::from_static(test_data));
    let encoded = frame.encode();

    // Decode frame
    let mut buf = bytes::BytesMut::from(&encoded[..]);
    let decoded = Frame::decode(&mut buf).unwrap().unwrap();

    assert_eq!(decoded.frame_type, FrameType::Data);
    assert_eq!(decoded.stream_id, stream_id);
    assert_eq!(&decoded.payload[..], test_data);
}

/// The frame layout on the wire must not change: deployed v1 and v2 peers
/// depend on it. type(1) | stream_id(3, BE) | payload_len(2, BE) | padding_len(1)
/// | payload | padding.
#[test]
fn test_frame_wire_layout_is_stable() {
    let frame = Frame::data(0x010203, Bytes::from_static(b"hi"));
    let encoded = frame.encode();
    assert_eq!(
        &encoded[..],
        &[0x00, 0x01, 0x02, 0x03, 0x00, 0x02, 0x00, b'h', b'i'],
        "frame wire format changed"
    );
    assert_eq!(FRAME_HEADER_SIZE, 7);
    assert_eq!(frame.encoded_size(), encoded.len());
}

/// Ping/Pong frames carry an 8-byte big-endian value that must survive a
/// round trip (the peer echoes it back).
#[test]
fn test_ping_pong_frames() {
    for (frame, ty) in [
        (Frame::ping(0xDEAD_BEEF_0000_0042), FrameType::Ping),
        (Frame::pong(0xDEAD_BEEF_0000_0042), FrameType::Pong),
    ] {
        let mut buf = frame.encode();
        let decoded = Frame::decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.frame_type, ty);
        assert_eq!(decoded.stream_id, 0);
        assert_eq!(
            u64::from_be_bytes(decoded.payload[..8].try_into().unwrap()),
            0xDEAD_BEEF_0000_0042
        );
        assert!(buf.is_empty(), "decode must consume the whole frame");
    }
}

/// Padding frames carry random padding and no payload; the decoder discards
/// the padding.
#[test]
fn test_padding_frame() {
    let frame = Frame::padding(255);
    let a = frame.encode();
    let b = frame.encode();
    assert_eq!(a.len(), FRAME_HEADER_SIZE + 255);
    assert_ne!(a[FRAME_HEADER_SIZE..], b[FRAME_HEADER_SIZE..], "padding must be random");

    let mut buf = a;
    let decoded = Frame::decode(&mut buf).unwrap().unwrap();
    assert_eq!(decoded.frame_type, FrameType::Padding);
    assert_eq!(decoded.padding_len, 255);
    assert!(decoded.payload.is_empty());
    assert!(buf.is_empty());
}

/// Several frames back to back in one buffer decode one at a time, and a
/// truncated frame waits for more bytes instead of failing.
#[test]
fn test_frames_back_to_back_and_partial() {
    let mut buf = bytes::BytesMut::new();
    buf.extend_from_slice(&Frame::stream_open(1, b"example.com:443").encode());
    buf.extend_from_slice(&Frame::window_update(1, 65536).encode());
    buf.extend_from_slice(&Frame::udp_data(3, Bytes::from_static(b"dgram")).encode());
    buf.extend_from_slice(&Frame::stream_close(1).encode());

    let kinds: Vec<FrameType> = std::iter::from_fn(|| Frame::decode(&mut buf).unwrap())
        .map(|f| f.frame_type)
        .collect();
    assert_eq!(
        kinds,
        vec![FrameType::StreamOpen, FrameType::WindowUpdate, FrameType::UdpData, FrameType::StreamClose]
    );

    // Every proper prefix of a frame is "not enough data yet", never an error.
    let full = Frame::data(9, Bytes::from_static(b"payload")).encode();
    for cut in 0..full.len() {
        let mut part = bytes::BytesMut::from(&full[..cut]);
        assert!(Frame::decode(&mut part).unwrap().is_none(), "prefix of {} bytes", cut);
    }
}

/// An unknown frame type is rejected, not misread.
#[test]
fn test_unknown_frame_type_rejected() {
    let mut buf = bytes::BytesMut::from(&[0x7f, 0, 0, 1, 0, 0, 0][..]);
    assert!(Frame::decode(&mut buf).is_err());
}

/// Test bidirectional encrypted data transfer
#[tokio::test]
async fn test_bidirectional_transfer() {
    let server_keypair = KeyPair::generate().unwrap();
    let client_keypair = KeyPair::generate().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let server_pubkey = server_keypair.public.clone();

    let server_kp = server_keypair.clone();
    let server_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // Handshake
        let mut handshake = NoiseHandshake::new_responder(&server_kp).unwrap();

        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.unwrap();
        let msg_len = u16::from_be_bytes(len_buf) as usize;

        let mut buf = vec![0u8; msg_len];
        stream.read_exact(&mut buf).await.unwrap();

        let mut payload_buf = [0u8; 65535];
        handshake.read_message(&buf, &mut payload_buf).unwrap();

        let mut response_buf = [0u8; 65535];
        let resp_len = handshake.write_message(&[], &mut response_buf).unwrap();

        let len_bytes = (resp_len as u16).to_be_bytes();
        stream.write_all(&len_bytes).await.unwrap();
        stream.write_all(&response_buf[..resp_len]).await.unwrap();

        let mut transport = handshake.into_transport().unwrap();

        // Receive message from client
        stream.read_exact(&mut len_buf).await.unwrap();
        let ct_len = u16::from_be_bytes(len_buf) as usize;

        let mut ciphertext = vec![0u8; ct_len];
        stream.read_exact(&mut ciphertext).await.unwrap();

        let mut plaintext = vec![0u8; ct_len];
        let pt_len = transport.decrypt(&ciphertext, &mut plaintext).unwrap();
        let client_msg = String::from_utf8(plaintext[..pt_len].to_vec()).unwrap();

        // Send response back
        let response = b"Hello from server!";
        let mut response_ct = vec![0u8; response.len() + 16];
        let ct_len = transport.encrypt(response, &mut response_ct).unwrap();

        let len_bytes = (ct_len as u16).to_be_bytes();
        stream.write_all(&len_bytes).await.unwrap();
        stream.write_all(&response_ct[..ct_len]).await.unwrap();

        client_msg
    });

    // Client
    let mut client_stream = TcpStream::connect(server_addr).await.unwrap();

    let mut client_handshake =
        NoiseHandshake::new_initiator(&client_keypair, &server_pubkey).unwrap();

    let mut buf = [0u8; 65535];
    let msg_len = client_handshake.write_message(&[], &mut buf).unwrap();

    let len_bytes = (msg_len as u16).to_be_bytes();
    client_stream.write_all(&len_bytes).await.unwrap();
    client_stream.write_all(&buf[..msg_len]).await.unwrap();

    let mut len_buf = [0u8; 2];
    client_stream.read_exact(&mut len_buf).await.unwrap();
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    let mut resp_buf = vec![0u8; resp_len];
    client_stream.read_exact(&mut resp_buf).await.unwrap();

    let mut payload_buf = [0u8; 65535];
    client_handshake.read_message(&resp_buf, &mut payload_buf).unwrap();

    let mut client_transport = client_handshake.into_transport().unwrap();

    // Send message to server
    let message = b"Hello from client!";
    let mut ciphertext = vec![0u8; message.len() + 16];
    let ct_len = client_transport.encrypt(message, &mut ciphertext).unwrap();

    let len_bytes = (ct_len as u16).to_be_bytes();
    client_stream.write_all(&len_bytes).await.unwrap();
    client_stream.write_all(&ciphertext[..ct_len]).await.unwrap();

    // Receive response
    client_stream.read_exact(&mut len_buf).await.unwrap();
    let resp_ct_len = u16::from_be_bytes(len_buf) as usize;

    let mut resp_ct = vec![0u8; resp_ct_len];
    client_stream.read_exact(&mut resp_ct).await.unwrap();

    let mut resp_pt = vec![0u8; resp_ct_len];
    let pt_len = client_transport.decrypt(&resp_ct, &mut resp_pt).unwrap();
    let server_response = String::from_utf8(resp_pt[..pt_len].to_vec()).unwrap();

    // Verify both directions
    let client_msg_received = server_handle.await.unwrap();
    assert_eq!(client_msg_received, "Hello from client!");
    assert_eq!(server_response, "Hello from server!");
}

/// Test large data transfer
#[tokio::test]
async fn test_large_data_transfer() {
    let server_keypair = KeyPair::generate().unwrap();
    let client_keypair = KeyPair::generate().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let server_pubkey = server_keypair.public.clone();

    // Create large test data (1 MB)
    let test_data: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();
    let test_data_clone = test_data.clone();

    let server_kp = server_keypair.clone();
    let server_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // Quick handshake
        let mut handshake = NoiseHandshake::new_responder(&server_kp).unwrap();

        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.unwrap();
        let msg_len = u16::from_be_bytes(len_buf) as usize;

        let mut buf = vec![0u8; msg_len];
        stream.read_exact(&mut buf).await.unwrap();

        let mut payload_buf = [0u8; 65535];
        handshake.read_message(&buf, &mut payload_buf).unwrap();

        let mut response_buf = [0u8; 65535];
        let resp_len = handshake.write_message(&[], &mut response_buf).unwrap();

        let len_bytes = (resp_len as u16).to_be_bytes();
        stream.write_all(&len_bytes).await.unwrap();
        stream.write_all(&response_buf[..resp_len]).await.unwrap();

        let mut transport = handshake.into_transport().unwrap();

        // Receive all data chunks
        let mut received_data = Vec::new();
        loop {
            if stream.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let ct_len = u16::from_be_bytes(len_buf) as usize;
            if ct_len == 0 {
                break;
            }

            let mut ciphertext = vec![0u8; ct_len];
            stream.read_exact(&mut ciphertext).await.unwrap();

            let mut plaintext = vec![0u8; ct_len];
            let pt_len = transport.decrypt(&ciphertext, &mut plaintext).unwrap();
            received_data.extend_from_slice(&plaintext[..pt_len]);
        }

        received_data
    });

    // Client
    let mut client_stream = TcpStream::connect(server_addr).await.unwrap();

    let mut client_handshake =
        NoiseHandshake::new_initiator(&client_keypair, &server_pubkey).unwrap();

    let mut buf = [0u8; 65535];
    let msg_len = client_handshake.write_message(&[], &mut buf).unwrap();

    let len_bytes = (msg_len as u16).to_be_bytes();
    client_stream.write_all(&len_bytes).await.unwrap();
    client_stream.write_all(&buf[..msg_len]).await.unwrap();

    let mut len_buf = [0u8; 2];
    client_stream.read_exact(&mut len_buf).await.unwrap();
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    let mut resp_buf = vec![0u8; resp_len];
    client_stream.read_exact(&mut resp_buf).await.unwrap();

    let mut payload_buf = [0u8; 65535];
    client_handshake.read_message(&resp_buf, &mut payload_buf).unwrap();

    let mut client_transport = client_handshake.into_transport().unwrap();

    // Send data in chunks (max 16KB per chunk for Noise)
    const CHUNK_SIZE: usize = 16384;
    for chunk in test_data.chunks(CHUNK_SIZE) {
        let mut ciphertext = vec![0u8; chunk.len() + 16];
        let ct_len = client_transport.encrypt(chunk, &mut ciphertext).unwrap();

        let len_bytes = (ct_len as u16).to_be_bytes();
        client_stream.write_all(&len_bytes).await.unwrap();
        client_stream.write_all(&ciphertext[..ct_len]).await.unwrap();
    }

    // Signal end
    client_stream.shutdown().await.unwrap();

    // Verify
    let received = server_handle.await.unwrap();
    assert_eq!(received.len(), test_data_clone.len());
    assert_eq!(received, test_data_clone);
}

/// Test keypair serialization
#[test]
fn test_keypair_serialization() {
    let keypair = KeyPair::generate().unwrap();
    let public_b64 = keypair.public.to_base64();
    let private_b64 = keypair.private.to_base64();

    // Deserialize
    use phantom_tunnel::crypto::{PrivateKey, PublicKey};
    let restored_public = PublicKey::from_base64(&public_b64).unwrap();
    let restored_private = PrivateKey::from_base64(&private_b64).unwrap();

    assert_eq!(keypair.public.to_base64(), restored_public.to_base64());
    assert_eq!(keypair.private.to_base64(), restored_private.to_base64());
}
