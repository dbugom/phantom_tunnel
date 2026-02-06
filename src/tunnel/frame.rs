//! Frame encoding/decoding for the tunnel protocol
//!
//! Frame format:
//! ```text
//! +--------+--------+--------+--------+
//! |  Type  |      Stream ID (3B)      |
//! +--------+--------+--------+--------+
//! |         Length (2B)               |
//! +--------+--------+--------+--------+
//! |         Padding Length (1B)       |
//! +--------+--------+--------+--------+
//! |              Payload              |
//! +--------+--------+--------+--------+
//! |              Padding              |
//! +--------+--------+--------+--------+
//! ```

use super::TunnelError;
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Frame header size in bytes
pub const FRAME_HEADER_SIZE: usize = 6;

/// Maximum payload size (64 KB - header)
pub const MAX_PAYLOAD_SIZE: usize = 65535 - FRAME_HEADER_SIZE;

/// Frame types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Data frame
    Data = 0x00,
    /// Stream open request
    StreamOpen = 0x01,
    /// Stream close
    StreamClose = 0x02,
    /// Window update (flow control)
    WindowUpdate = 0x03,
    /// Ping (keepalive)
    Ping = 0x04,
    /// Pong (keepalive response)
    Pong = 0x05,
    /// Go away (connection closing)
    GoAway = 0x06,
    /// Padding only (for traffic shaping)
    Padding = 0x07,
}

impl TryFrom<u8> for FrameType {
    type Error = TunnelError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(FrameType::Data),
            0x01 => Ok(FrameType::StreamOpen),
            0x02 => Ok(FrameType::StreamClose),
            0x03 => Ok(FrameType::WindowUpdate),
            0x04 => Ok(FrameType::Ping),
            0x05 => Ok(FrameType::Pong),
            0x06 => Ok(FrameType::GoAway),
            0x07 => Ok(FrameType::Padding),
            _ => Err(TunnelError::InvalidFrame(format!(
                "Unknown frame type: {}",
                value
            ))),
        }
    }
}

/// A protocol frame
#[derive(Debug, Clone)]
pub struct Frame {
    /// Frame type
    pub frame_type: FrameType,
    /// Stream ID (0 for connection-level frames)
    pub stream_id: u32,
    /// Payload data
    pub payload: Bytes,
    /// Padding length (for traffic analysis resistance)
    pub padding_len: u8,
}

impl Frame {
    /// Create a new data frame
    pub fn data(stream_id: u32, payload: Bytes) -> Self {
        Self {
            frame_type: FrameType::Data,
            stream_id,
            payload,
            padding_len: 0,
        }
    }

    /// Create a new data frame with padding
    pub fn data_with_padding(stream_id: u32, payload: Bytes, padding_len: u8) -> Self {
        Self {
            frame_type: FrameType::Data,
            stream_id,
            payload,
            padding_len,
        }
    }

    /// Create a stream open frame
    pub fn stream_open(stream_id: u32, destination: &[u8]) -> Self {
        Self {
            frame_type: FrameType::StreamOpen,
            stream_id,
            payload: Bytes::copy_from_slice(destination),
            padding_len: 0,
        }
    }

    /// Create a stream close frame
    pub fn stream_close(stream_id: u32) -> Self {
        Self {
            frame_type: FrameType::StreamClose,
            stream_id,
            payload: Bytes::new(),
            padding_len: 0,
        }
    }

    /// Create a window update frame
    pub fn window_update(stream_id: u32, increment: u32) -> Self {
        let mut payload = BytesMut::with_capacity(4);
        payload.put_u32(increment);
        Self {
            frame_type: FrameType::WindowUpdate,
            stream_id,
            payload: payload.freeze(),
            padding_len: 0,
        }
    }

    /// Create a ping frame
    pub fn ping(data: u64) -> Self {
        let mut payload = BytesMut::with_capacity(8);
        payload.put_u64(data);
        Self {
            frame_type: FrameType::Ping,
            stream_id: 0,
            payload: payload.freeze(),
            padding_len: 0,
        }
    }

    /// Create a pong frame
    pub fn pong(data: u64) -> Self {
        let mut payload = BytesMut::with_capacity(8);
        payload.put_u64(data);
        Self {
            frame_type: FrameType::Pong,
            stream_id: 0,
            payload: payload.freeze(),
            padding_len: 0,
        }
    }

    /// Create a padding-only frame
    pub fn padding(len: usize) -> Self {
        Self {
            frame_type: FrameType::Padding,
            stream_id: 0,
            payload: Bytes::new(),
            padding_len: len.min(255) as u8,
        }
    }

    /// Encode frame to bytes
    pub fn encode(&self) -> BytesMut {
        let payload_len = self.payload.len();
        let total_len = FRAME_HEADER_SIZE + payload_len + self.padding_len as usize;

        let mut buf = BytesMut::with_capacity(total_len);

        // Type (1 byte)
        buf.put_u8(self.frame_type as u8);

        // Stream ID (3 bytes, big endian)
        buf.put_u8((self.stream_id >> 16) as u8);
        buf.put_u16(self.stream_id as u16);

        // Payload length (2 bytes)
        buf.put_u16(payload_len as u16);

        // Padding length (1 byte)
        buf.put_u8(self.padding_len);

        // Payload
        buf.extend_from_slice(&self.payload);

        // Padding (random bytes for traffic analysis resistance)
        if self.padding_len > 0 {
            let mut padding = vec![0u8; self.padding_len as usize];
            crate::crypto::random_bytes(&mut padding);
            buf.extend_from_slice(&padding);
        }

        buf
    }

    /// Decode frame from bytes
    pub fn decode(buf: &mut BytesMut) -> Result<Option<Self>, TunnelError> {
        if buf.len() < FRAME_HEADER_SIZE {
            return Ok(None);
        }

        // Peek at header to get lengths
        let frame_type = FrameType::try_from(buf[0])?;
        let stream_id =
            ((buf[1] as u32) << 16) | ((buf[2] as u32) << 8) | (buf[3] as u32);
        let payload_len = ((buf[4] as usize) << 8) | (buf[5] as usize);
        let padding_len = buf[6] as usize;

        let total_len = FRAME_HEADER_SIZE + 1 + payload_len + padding_len;

        if buf.len() < total_len {
            return Ok(None);
        }

        // Consume header
        buf.advance(FRAME_HEADER_SIZE + 1);

        // Read payload
        let payload = buf.split_to(payload_len).freeze();

        // Discard padding
        buf.advance(padding_len);

        Ok(Some(Self {
            frame_type,
            stream_id,
            payload,
            padding_len: padding_len as u8,
        }))
    }

    /// Get the total encoded size of this frame
    pub fn encoded_size(&self) -> usize {
        FRAME_HEADER_SIZE + 1 + self.payload.len() + self.padding_len as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_encode_decode() {
        let original = Frame::data(42, Bytes::from_static(b"Hello, World!"));
        let mut encoded = original.encode();

        let decoded = Frame::decode(&mut encoded).unwrap().unwrap();

        assert_eq!(decoded.frame_type, original.frame_type);
        assert_eq!(decoded.stream_id, original.stream_id);
        assert_eq!(decoded.payload, original.payload);
    }

    #[test]
    fn test_frame_with_padding() {
        let original = Frame::data_with_padding(1, Bytes::from_static(b"Test"), 16);
        let encoded = original.encode();

        assert_eq!(
            encoded.len(),
            FRAME_HEADER_SIZE + 1 + 4 + 16
        );
    }

    #[test]
    fn test_stream_open_frame() {
        let dest = b"example.com:443";
        let frame = Frame::stream_open(1, dest);

        let mut encoded = frame.encode();
        let decoded = Frame::decode(&mut encoded).unwrap().unwrap();

        assert_eq!(decoded.frame_type, FrameType::StreamOpen);
        assert_eq!(decoded.stream_id, 1);
        assert_eq!(&decoded.payload[..], dest);
    }
}
