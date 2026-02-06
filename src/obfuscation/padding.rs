//! Traffic padding for anti-fingerprinting

use crate::crypto::random_bytes;

/// Padding strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingStrategy {
    /// No padding
    None,
    /// Pad to fixed block size
    Block(usize),
    /// Random padding up to max bytes
    Random(usize),
    /// Pad to power of 2
    PowerOfTwo,
}

/// Padding configuration
#[derive(Debug, Clone)]
pub struct PaddingConfig {
    /// Strategy for outgoing packets
    pub strategy: PaddingStrategy,
    /// Minimum packet size (pad small packets)
    pub min_size: usize,
    /// Maximum padding to add
    pub max_padding: usize,
}

impl Default for PaddingConfig {
    fn default() -> Self {
        Self {
            strategy: PaddingStrategy::Block(64),
            min_size: 64,
            max_padding: 256,
        }
    }
}

impl PaddingConfig {
    /// Calculate padding for a given data length
    pub fn calculate_padding(&self, data_len: usize) -> usize {
        let base_padding = if data_len < self.min_size {
            self.min_size - data_len
        } else {
            0
        };

        let strategy_padding = match self.strategy {
            PaddingStrategy::None => 0,
            PaddingStrategy::Block(block_size) => {
                let total = data_len + base_padding;
                let remainder = total % block_size;
                if remainder == 0 {
                    0
                } else {
                    block_size - remainder
                }
            }
            PaddingStrategy::Random(max) => {
                let mut buf = [0u8; 1];
                random_bytes(&mut buf);
                (buf[0] as usize) % max.min(self.max_padding)
            }
            PaddingStrategy::PowerOfTwo => {
                let total = data_len + base_padding;
                let next_power = total.next_power_of_two();
                next_power - total
            }
        };

        (base_padding + strategy_padding).min(self.max_padding)
    }

    /// Generate random padding bytes
    pub fn generate_padding(&self, len: usize) -> Vec<u8> {
        let mut padding = vec![0u8; len];
        random_bytes(&mut padding);
        padding
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_padding() {
        let config = PaddingConfig {
            strategy: PaddingStrategy::Block(64),
            min_size: 0,
            max_padding: 256,
        };

        assert_eq!(config.calculate_padding(60), 4);
        assert_eq!(config.calculate_padding(64), 0);
        assert_eq!(config.calculate_padding(65), 63);
    }

    #[test]
    fn test_min_size_padding() {
        let config = PaddingConfig {
            strategy: PaddingStrategy::None,
            min_size: 100,
            max_padding: 256,
        };

        assert_eq!(config.calculate_padding(50), 50);
        assert_eq!(config.calculate_padding(100), 0);
        assert_eq!(config.calculate_padding(150), 0);
    }

    #[test]
    fn test_power_of_two_padding() {
        let config = PaddingConfig {
            strategy: PaddingStrategy::PowerOfTwo,
            min_size: 0,
            max_padding: 512,
        };

        assert_eq!(config.calculate_padding(100), 28); // 128 - 100
        assert_eq!(config.calculate_padding(128), 0);
        assert_eq!(config.calculate_padding(200), 56); // 256 - 200
    }
}
