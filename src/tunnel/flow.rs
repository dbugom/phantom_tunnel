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
