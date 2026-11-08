//! Per-stream send-side flow control (credit window).
//!
//! Each stream has a *send window*: the number of bytes the peer has said it is
//! ready to receive. The task that reads a stream's data source calls
//! [`StreamFlow::acquire`] before sending; if the window is empty it waits. The
//! event loop calls [`StreamFlow::add`] when a `WindowUpdate` frame grants more
//! credit. Because only that one source task calls `acquire` for a given stream,
//! a slow stream backpressures only its own source socket and never the shared
//! event loop or other streams.

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use tokio::sync::Notify;

/// Credit-based send window for a single stream.
pub struct StreamFlow {
    /// Bytes of credit currently available to send.
    send_window: AtomicI64,
    /// Set when the stream is torn down, to release a blocked sender.
    closed: AtomicBool,
    /// Notified whenever credit is added or the flow is closed.
    notify: Notify,
}

impl StreamFlow {
    /// Create a flow with `initial` bytes of send credit.
    pub fn new(initial: i64) -> Self {
        Self {
            send_window: AtomicI64::new(initial),
            closed: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    /// Wait until at least one byte of credit is available, then reserve up to
    /// `want` bytes (never more than is available) and return the amount
    /// reserved (`>= 1`). Returns `0` if the stream has been closed, which the
    /// caller should treat as "stop sending". Only one task per stream may call
    /// this.
    pub async fn acquire(&self, want: usize) -> usize {
        debug_assert!(want > 0);
        loop {
            // Register interest BEFORE checking, so an `add`/`close` that happens
            // between the check and the await is not lost.
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            if self.closed.load(Ordering::Acquire) {
                return 0;
            }
            let avail = self.send_window.load(Ordering::Acquire);
            if avail > 0 {
                let take = (avail as usize).min(want);
                self.send_window.fetch_sub(take as i64, Ordering::AcqRel);
                return take;
            }

            notified.await;
        }
    }

    /// Add `inc` bytes of send credit (from a received `WindowUpdate`) and wake
    /// the waiting source task, if any.
    pub fn add(&self, inc: i64) {
        if inc == 0 {
            return;
        }
        self.send_window.fetch_add(inc, Ordering::AcqRel);
        self.notify.notify_waiters();
    }

    /// Mark the flow closed and wake any waiting sender so it can stop.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn acquire_returns_up_to_available() {
        let flow = StreamFlow::new(100);
        assert_eq!(flow.acquire(40).await, 40);
        assert_eq!(flow.acquire(1000).await, 60); // only 60 left
    }

    #[tokio::test]
    async fn acquire_blocks_until_credit_added() {
        let flow = Arc::new(StreamFlow::new(0));
        let f2 = Arc::clone(&flow);

        // This task must block until credit arrives.
        let waiter = tokio::spawn(async move { f2.acquire(10).await });

        // Give the waiter time to park.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiter.is_finished(), "should still be waiting with 0 credit");

        flow.add(10);
        let got = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("acquire should wake after add")
            .unwrap();
        assert_eq!(got, 10);
    }
}

/// Receive-side window bookkeeping for one stream, with auto-tuning.
///
/// The receiver decides how much the peer may have in flight. It starts at
/// [`crate::tunnel::DEFAULT_WINDOW_SIZE`] (which both ends assume) and grows by
/// granting extra credit in `WindowUpdate` frames, so this needs no protocol
/// change: a sender simply uses whatever credit it is given.
///
/// Growth rule: each time half the window has been drained, a `WindowUpdate`
/// is sent. If at that moment little data is still waiting for the local
/// reader, the reader is keeping up and the window (not the reader) is what
/// limits throughput, so the window doubles, up to `max_window`. A stream whose
/// reader is slow never grows, which keeps memory bounded where it matters.
///
/// Invariant for a well-behaved sender: `buffered <= window`. Receiving more
/// than that is a flow-control violation.
#[derive(Debug, Clone)]
pub struct RecvWindow {
    window: u32,
    max_window: u32,
    /// Received but not yet drained to the local reader.
    buffered: u64,
    /// Drained since the last `WindowUpdate`.
    drained: u32,
}

/// Returned by [`RecvWindow::on_received`] when the peer sent more than its
/// credit allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowViolation;

impl RecvWindow {
    /// New window starting at the protocol default, growing up to `max_window`.
    pub fn new(max_window: u32) -> Self {
        let start = crate::tunnel::DEFAULT_WINDOW_SIZE;
        Self {
            window: start,
            max_window: max_window.max(start),
            buffered: 0,
            drained: 0,
        }
    }

    /// Current window size in bytes.
    pub fn window(&self) -> u32 {
        self.window
    }

    /// Bytes received but not yet drained to the reader.
    pub fn buffered(&self) -> u64 {
        self.buffered
    }

    /// Account for `n` bytes received from the peer.
    pub fn on_received(&mut self, n: usize) -> Result<(), WindowViolation> {
        self.buffered += n as u64;
        if self.buffered > self.window as u64 {
            Err(WindowViolation)
        } else {
            Ok(())
        }
    }

    /// Account for `n` bytes drained to the local reader. Returns the
    /// increment to send in a `WindowUpdate`, if one is due.
    pub fn on_drained(&mut self, n: u32) -> Option<u32> {
        self.buffered = self.buffered.saturating_sub(n as u64);
        self.drained = self.drained.saturating_add(n);
        if self.drained < self.window / 2 {
            return None;
        }
        let mut increment = self.drained;
        self.drained = 0;
        if self.buffered <= (self.window / 4) as u64 && self.window < self.max_window {
            let grown = self.window.saturating_mul(2).min(self.max_window);
            increment += grown - self.window;
            self.window = grown;
        }
        Some(increment)
    }
}

#[cfg(test)]
mod recv_window_tests {
    use super::*;
    use crate::tunnel::DEFAULT_WINDOW_SIZE as START;

    const MAX: u32 = 16 * 1024 * 1024;

    /// Simulates a sender honouring its credit against a reader that drains
    /// `drain_per_step` bytes per step, and checks the invariant throughout.
    fn simulate(drain_per_step: u32, steps: usize) -> RecvWindow {
        let mut rw = RecvWindow::new(MAX);
        let mut credit = START as u64; // what the sender may still send
        let mut queued = 0u64; // received, not drained
        for _ in 0..steps {
            // Sender sends everything its credit allows, in 32 KB frames.
            while credit > 0 {
                let n = credit.min(32 * 1024);
                rw.on_received(n as usize).expect("honest sender must never violate");
                credit -= n;
                queued += n;
            }
            // Reader drains.
            let d = (drain_per_step as u64).min(queued) as u32;
            queued -= d as u64;
            if let Some(inc) = rw.on_drained(d) {
                credit += inc as u64;
            }
            assert!(rw.buffered() <= rw.window() as u64);
        }
        rw
    }

    #[test]
    fn fast_reader_grows_window_to_max() {
        let rw = simulate(u32::MAX, 200);
        assert_eq!(rw.window(), MAX, "a reader that keeps up should reach the max window");
    }

    #[test]
    fn slow_reader_does_not_grow_window() {
        // Drains 1 KB per step: never keeps up, so the window must stay small.
        let rw = simulate(1024, 5000);
        assert_eq!(rw.window(), START);
    }

    #[test]
    fn sending_beyond_credit_is_a_violation() {
        let mut rw = RecvWindow::new(MAX);
        assert!(rw.on_received(START as usize).is_ok());
        assert_eq!(rw.on_received(1), Err(WindowViolation));
    }

    #[test]
    fn update_is_sent_at_half_window() {
        let mut rw = RecvWindow::new(START); // growth disabled (max == start)
        rw.on_received(START as usize).unwrap();
        assert_eq!(rw.on_drained(START / 2 - 1), None);
        assert_eq!(rw.on_drained(1), Some(START / 2));
        assert_eq!(rw.window(), START);
    }
}
