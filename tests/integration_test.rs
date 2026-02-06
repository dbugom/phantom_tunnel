//! Integration tests for Phantom Tunnel
//!
//! Tests the full client-server communication flow including:
//! - Noise Protocol handshake
//! - Stream multiplexing
//! - Encrypted data transfer
//! - Flow control

use bytes::Bytes;
use phantom_tunnel::crypto::{KeyPair, NoiseHandshake};
use phantom_tunnel::tunnel::{Frame, FrameType, Multiplexer, FRAME_HEADER_SIZE};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

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
    let client_transport = client_handshake
        .into_transport()
        .expect("Failed to enter transport mode");

    // Wait for server
    let (server_transport, client_pub_from_server) = server_handle.await.unwrap();

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

/// Test stream multiplexer
#[tokio::test]
async fn test_multiplexer_operations() {
    let mut client_mux = Multiplexer::new_client();

    // Client opens stream
    let stream_handle = client_mux.open_stream("example.com:443".to_string()).unwrap();
    assert_eq!(stream_handle.id(), 1); // Odd for client

    // Get queued STREAM_OPEN frame
    let frames = client_mux.take_send_queue();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].frame_type, FrameType::StreamOpen);

    // Verify the frame structure
    assert_eq!(frames[0].stream_id, 1);
    // The payload contains the destination as raw bytes
    assert!(!frames[0].payload.is_empty());
}

/// Test ping/pong keepalive
#[tokio::test]
async fn test_ping_pong() {
    let mut mux = Multiplexer::new_client();

    // Send ping
    mux.send_ping();
    let frames = mux.take_send_queue();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].frame_type, FrameType::Ping);

    // Simulate receiving ping on other side
    let mut other_mux = Multiplexer::new_server();
    other_mux.handle_frame(frames[0].clone()).await.unwrap();

    // Should have pong queued
    let pong_frames = other_mux.take_send_queue();
    assert_eq!(pong_frames.len(), 1);
    assert_eq!(pong_frames[0].frame_type, FrameType::Pong);
}

/// Test traffic padding
#[tokio::test]
async fn test_padding_frames() {
    let mut mux = Multiplexer::new_client();

    // Send padding (max 255 due to u8 padding_len field)
    mux.send_padding(255);
    let frames = mux.take_send_queue();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].frame_type, FrameType::Padding);
    // Padding is stored in padding_len, not payload
    assert_eq!(frames[0].padding_len, 255);
    assert!(frames[0].payload.is_empty()); // No actual payload data
}

/// Test multiple concurrent streams
#[tokio::test]
async fn test_multiple_streams() {
    let mut mux = Multiplexer::new_client();

    // Open multiple streams
    let stream1 = mux.open_stream("example.com:443".to_string()).unwrap();
    let stream2 = mux.open_stream("example.org:443".to_string()).unwrap();
    let stream3 = mux.open_stream("example.net:443".to_string()).unwrap();

    assert_eq!(stream1.id(), 1);
    assert_eq!(stream2.id(), 3);
    assert_eq!(stream3.id(), 5);

    assert_eq!(mux.stream_count(), 3);

    // All should be odd (client-initiated)
    assert!(stream1.id() % 2 == 1);
    assert!(stream2.id() % 2 == 1);
    assert!(stream3.id() % 2 == 1);
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

/// Test key derivation consistency
#[test]
fn test_key_derivation_consistency() {
    use phantom_tunnel::crypto::Hkdf;

    let ikm = b"input key material";
    let salt = b"salt value";
    let info = b"info value";

    let hkdf1 = Hkdf::new(Some(salt), ikm);
    let hkdf2 = Hkdf::new(Some(salt), ikm);

    let mut output1 = [0u8; 32];
    let mut output2 = [0u8; 32];

    hkdf1.expand(info, &mut output1).unwrap();
    hkdf2.expand(info, &mut output2).unwrap();

    assert_eq!(output1, output2);
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
