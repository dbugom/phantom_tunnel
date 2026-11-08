//! Micro-benchmarks for the data path.
//!
//! Run with:  cargo bench --bench tunnel_bench
//!
//! - `frame/encode_decode`: Frame encode + decode only
//! - `noise/seal_open`: Noise encrypt on one side + decrypt on the other
//! - `path/send_recv`: the full per-frame work the binaries do — encode,
//!   encrypt into a length-prefixed buffer, then decrypt and decode on the
//!   receiving side
//! - `handshake/noise_ik`: one complete Noise IK handshake (connection setup)
//!
//! Throughput is reported in bytes of application payload per second.

use bytes::{Bytes, BytesMut};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use phantom_tunnel::crypto::{KeyPair, NoiseHandshake, NoiseTransport};
use phantom_tunnel::tunnel::Frame;

/// Payload sizes: a small request, a typical TLS record, and the binaries'
/// 32 KB read buffer (the largest frame they produce).
const SIZES: [usize; 3] = [1024, 16 * 1024, 32 * 1024];

/// Complete an IK handshake in memory and return (client, server) transports.
fn handshake(server_kp: &KeyPair, client_kp: &KeyPair) -> (NoiseTransport, NoiseTransport) {
    let mut client = NoiseHandshake::new_initiator(client_kp, &server_kp.public).unwrap();
    let mut server = NoiseHandshake::new_responder(server_kp).unwrap();
    let mut msg = vec![0u8; 1024];
    let mut payload = vec![0u8; 1024];
    let n = client.write_message(&[2], &mut msg).unwrap();
    server.read_message(&msg[..n], &mut payload).unwrap();
    let n = server.write_message(&[2], &mut msg).unwrap();
    client.read_message(&msg[..n], &mut payload).unwrap();
    (client.into_transport().unwrap(), server.into_transport().unwrap())
}

fn transports() -> (NoiseTransport, NoiseTransport) {
    handshake(&KeyPair::generate().unwrap(), &KeyPair::generate().unwrap())
}

fn bench_frame(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame/encode_decode");
    for size in SIZES {
        let payload = Bytes::from(vec![0xAB; size]);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &payload, |b, payload| {
            b.iter(|| {
                let mut buf = Frame::data(7, payload.clone()).encode();
                let f = Frame::decode(&mut buf).unwrap().unwrap();
                black_box(f.payload.len())
            })
        });
    }
    group.finish();
}

fn bench_noise(c: &mut Criterion) {
    let mut group = c.benchmark_group("noise/seal_open");
    for size in SIZES {
        let (mut tx, mut rx) = transports();
        let plaintext = vec![0xCD; size];
        let mut ct = vec![0u8; size + 16];
        let mut pt = vec![0u8; size + 16];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            b.iter(|| {
                let n = tx.encrypt(black_box(&plaintext), &mut ct).unwrap();
                let m = rx.decrypt(&ct[..n], &mut pt).unwrap();
                black_box(m)
            })
        });
    }
    group.finish();
}

/// Mirrors `send_frame_write` + the reader/decrypt/decode loop in the binaries.
fn bench_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("path/send_recv");
    for size in SIZES {
        let (mut tx, mut rx) = transports();
        let payload = Bytes::from(vec![0xEF; size]);
        let mut frame_buf = vec![0u8; 65536];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &payload, |b, payload| {
            b.iter(|| {
                // Sender: encode, encrypt into one length-prefixed buffer.
                let plaintext = Frame::data(1, payload.clone()).encode();
                let mut out = vec![0u8; 2 + plaintext.len() + 16];
                let ct_len = tx.encrypt(&plaintext, &mut out[2..]).unwrap();
                out[0..2].copy_from_slice(&(ct_len as u16).to_be_bytes());
                out.truncate(2 + ct_len);

                // Receiver: strip length, decrypt, decode.
                let len = u16::from_be_bytes([out[0], out[1]]) as usize;
                let pt_len = rx.decrypt(&out[2..2 + len], &mut frame_buf).unwrap();
                let mut bytes = BytesMut::from(&frame_buf[..pt_len]);
                let f = Frame::decode(&mut bytes).unwrap().unwrap();
                black_box(f.payload.len())
            })
        });
    }
    group.finish();
}

/// Keys are generated once, as in real use (both sides already hold their
/// static keys); only the two handshake messages are timed.
fn bench_handshake(c: &mut Criterion) {
    let server_kp = KeyPair::generate().unwrap();
    let client_kp = KeyPair::generate().unwrap();
    c.bench_function("handshake/noise_ik", |b| {
        b.iter(|| black_box(handshake(&server_kp, &client_kp)))
    });
}

criterion_group!(benches, bench_frame, bench_noise, bench_path, bench_handshake);
criterion_main!(benches);
