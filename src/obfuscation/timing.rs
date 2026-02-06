//! Timing obfuscation to defeat traffic analysis
//!
//! Censors can fingerprint proxy traffic by analyzing:
//! - Inter-packet timing
//! - Burst patterns
//! - Cross-layer RTT discrepancies
//!
//! This module provides timing jitter and dummy packet injection
//! to make traffic patterns less distinguishable.

use crate::crypto::random_bytes;
use std::time::Duration;
use tokio::time::{sleep, Instant};

/// Timing obfuscation configuration
#[derive(Debug, Clone)]
pub struct TimingConfig {
    /// Enable timing obfuscation
    pub enabled: bool,
    /// Minimum delay between packets (microseconds)
    pub min_delay_us: u64,
    /// Maximum random jitter (microseconds)
    pub max_jitter_us: u64,
    /// Interval for dummy packets during idle (milliseconds, 0 = disabled)
    pub idle_dummy_interval_ms: u64,
    /// Enable ACK delay obfuscation
    pub ack_delay: bool,
    /// ACK delay amount (milliseconds)
    pub ack_delay_ms: u64,
}

impl Default for TimingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_delay_us: 100,        // 0.1ms minimum
            max_jitter_us: 50_000,    // 50ms max jitter
            idle_dummy_interval_ms: 5000, // 5s idle dummy
            ack_delay: true,
            ack_delay_ms: 50,         // 50ms ACK delay
        }
    }
}

impl TimingConfig {
    /// Create config with no timing obfuscation (for testing)
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            min_delay_us: 0,
            max_jitter_us: 0,
            idle_dummy_interval_ms: 0,
            ack_delay: false,
            ack_delay_ms: 0,
        }
    }

    /// Create aggressive timing obfuscation (for highly censored environments)
    pub fn aggressive() -> Self {
        Self {
            enabled: true,
            min_delay_us: 500,
            max_jitter_us: 100_000,   // 100ms max jitter
            idle_dummy_interval_ms: 2000,
            ack_delay: true,
            ack_delay_ms: 100,
        }
    }
}

/// Timing obfuscator for adding jitter to packet transmission
pub struct TimingObfuscator {
    config: TimingConfig,
    last_send: Option<Instant>,
    last_recv: Option<Instant>,
}

impl TimingObfuscator {
    /// Create a new timing obfuscator
    pub fn new(config: TimingConfig) -> Self {
        Self {
            config,
            last_send: None,
            last_recv: None,
        }
    }

    /// Get random jitter duration
    fn random_jitter(&self) -> Duration {
        if !self.config.enabled || self.config.max_jitter_us == 0 {
            return Duration::ZERO;
        }

        let mut buf = [0u8; 8];
        random_bytes(&mut buf);
        let random_value = u64::from_le_bytes(buf);
        let jitter_us = random_value % self.config.max_jitter_us;

        Duration::from_micros(jitter_us)
    }

    /// Delay before sending a packet (call before send)
    pub async fn delay_before_send(&mut self) {
        if !self.config.enabled {
            return;
        }

        // Ensure minimum inter-packet delay
        if let Some(last) = self.last_send {
            let elapsed = last.elapsed();
            let min_delay = Duration::from_micros(self.config.min_delay_us);

            if elapsed < min_delay {
                sleep(min_delay - elapsed).await;
            }
        }

        // Add random jitter
        let jitter = self.random_jitter();
        if !jitter.is_zero() {
            sleep(jitter).await;
        }

        self.last_send = Some(Instant::now());
    }

    /// Delay before processing received data (for ACK delay)
    pub async fn delay_before_ack(&mut self) {
        if !self.config.enabled || !self.config.ack_delay {
            return;
        }

        let delay = Duration::from_millis(self.config.ack_delay_ms);
        let jitter = self.random_jitter();

        sleep(delay + jitter).await;
        self.last_recv = Some(Instant::now());
    }

    /// Check if we should send a dummy packet (during idle)
    pub fn should_send_dummy(&self) -> bool {
        if !self.config.enabled || self.config.idle_dummy_interval_ms == 0 {
            return false;
        }

        if let Some(last) = self.last_send {
            let idle_duration = Duration::from_millis(self.config.idle_dummy_interval_ms);
            return last.elapsed() >= idle_duration;
        }

        false
    }

    /// Get the idle dummy interval
    pub fn idle_interval(&self) -> Option<Duration> {
        if self.config.enabled && self.config.idle_dummy_interval_ms > 0 {
            Some(Duration::from_millis(self.config.idle_dummy_interval_ms))
        } else {
            None
        }
    }

    /// Record that a packet was sent (call after send)
    pub fn record_send(&mut self) {
        self.last_send = Some(Instant::now());
    }

    /// Record that a packet was received
    pub fn record_recv(&mut self) {
        self.last_recv = Some(Instant::now());
    }

    /// Get time since last send
    pub fn time_since_send(&self) -> Option<Duration> {
        self.last_send.map(|t| t.elapsed())
    }

    /// Get time since last receive
    pub fn time_since_recv(&self) -> Option<Duration> {
        self.last_recv.map(|t| t.elapsed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timing_config_default() {
        let config = TimingConfig::default();
        assert!(config.enabled);
        assert!(config.max_jitter_us > 0);
    }

    #[test]
    fn test_timing_config_disabled() {
        let config = TimingConfig::disabled();
        assert!(!config.enabled);
    }

    #[tokio::test]
    async fn test_timing_obfuscator() {
        let config = TimingConfig {
            enabled: true,
            min_delay_us: 1000, // 1ms
            max_jitter_us: 1000, // 1ms max jitter
            idle_dummy_interval_ms: 100,
            ack_delay: false,
            ack_delay_ms: 0,
        };

        let mut obfuscator = TimingObfuscator::new(config);

        // First send should be immediate (plus jitter)
        let start = Instant::now();
        obfuscator.delay_before_send().await;
        let elapsed = start.elapsed();
        assert!(elapsed < Duration::from_millis(10)); // Should be fast

        // Second send should respect min delay
        let start = Instant::now();
        obfuscator.delay_before_send().await;
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_micros(1000)); // At least 1ms
    }

    #[test]
    fn test_dummy_packet_timing() {
        let config = TimingConfig {
            enabled: true,
            idle_dummy_interval_ms: 100,
            ..Default::default()
        };

        let obfuscator = TimingObfuscator::new(config);

        // No last send, should return false
        assert!(!obfuscator.should_send_dummy());
    }
}
