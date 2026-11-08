//! Channel from the tunnel event loop to the task that writes a stream's data
//! to its local socket.
//!
//! - [`InboundTx::credit`] (protocol v2 TCP streams): unbounded, never blocks
//!   the event loop. Memory is bounded by flow-control credit instead — the
//!   event loop checks every frame against the stream's [`super::RecvWindow`].
//! - [`InboundTx::blocking`] (v1 peers, which have no flow control): bounded;
//!   a full channel makes the event loop wait, as the v1 protocol requires.
//! - [`InboundTx::datagram`] (UDP): bounded; a full channel drops the datagram.

use bytes::Bytes;
use tokio::sync::mpsc;

/// The receiving task is gone; the stream should be torn down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InboundClosed;

/// Sending half, held by the event loop.
pub enum InboundTx {
    Credit(mpsc::UnboundedSender<Bytes>),
    Blocking(mpsc::Sender<Bytes>),
    Datagram(mpsc::Sender<Bytes>),
}

/// Receiving half, held by the task writing to the local socket.
pub enum InboundRx {
    Unbounded(mpsc::UnboundedReceiver<Bytes>),
    Bounded(mpsc::Receiver<Bytes>),
}

impl InboundTx {
    /// Flow-controlled stream (v2).
    pub fn credit() -> (Self, InboundRx) {
        let (tx, rx) = mpsc::unbounded_channel();
        (InboundTx::Credit(tx), InboundRx::Unbounded(rx))
    }

    /// Stream with a v1 peer: bounded, applies backpressure by waiting.
    pub fn blocking(capacity: usize) -> (Self, InboundRx) {
        let (tx, rx) = mpsc::channel(capacity);
        (InboundTx::Blocking(tx), InboundRx::Bounded(rx))
    }

    /// UDP association: bounded, drops when full.
    pub fn datagram(capacity: usize) -> (Self, InboundRx) {
        let (tx, rx) = mpsc::channel(capacity);
        (InboundTx::Datagram(tx), InboundRx::Bounded(rx))
    }

    /// Hand one payload to the receiving task. Only the `Blocking` kind can
    /// wait; the others return immediately.
    pub async fn send(&self, data: Bytes) -> Result<(), InboundClosed> {
        match self {
            InboundTx::Credit(tx) => tx.send(data).map_err(|_| InboundClosed),
            InboundTx::Blocking(tx) => tx.send(data).await.map_err(|_| InboundClosed),
            InboundTx::Datagram(tx) => match tx.try_send(data) {
                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
                Err(mpsc::error::TrySendError::Closed(_)) => Err(InboundClosed),
            },
        }
    }
}

impl InboundRx {
    /// Next payload, or `None` once the event loop has dropped the stream.
    pub async fn recv(&mut self) -> Option<Bytes> {
        match self {
            InboundRx::Unbounded(rx) => rx.recv().await,
            InboundRx::Bounded(rx) => rx.recv().await,
        }
    }
}
