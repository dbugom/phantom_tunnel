//! Raw TCP transport (for testing and internal networks)

use super::{Transport, TransportConfig, TransportError};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Raw TCP transport
pub struct TcpTransport {
    stream: Option<TcpStream>,
    config: TransportConfig,
}

impl TcpTransport {
    /// Create a new TCP transport
    pub fn new(config: TransportConfig) -> Self {
        Self {
            stream: None,
            config,
        }
    }

    /// Create with default configuration
    pub fn new_default() -> Self {
        Self::new(TransportConfig::default())
    }
}

#[async_trait]
impl Transport for TcpTransport {
    async fn connect(&mut self, addr: &str) -> Result<(), TransportError> {
        let timeout = std::time::Duration::from_secs(self.config.connect_timeout);

        let stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(TransportError::Io)?;

        // Configure TCP options
        stream.set_nodelay(true).ok();

        self.stream = Some(stream);
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        let stream = self.stream.as_mut().ok_or(TransportError::Closed)?;

        let timeout = std::time::Duration::from_secs(self.config.write_timeout);

        tokio::time::timeout(timeout, stream.write_all(data))
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(TransportError::Io)?;

        Ok(())
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        let stream = self.stream.as_mut().ok_or(TransportError::Closed)?;

        let timeout = std::time::Duration::from_secs(self.config.read_timeout);

        let n = tokio::time::timeout(timeout, stream.read(buf))
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(TransportError::Io)?;

        if n == 0 {
            return Err(TransportError::Closed);
        }

        Ok(n)
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        if let Some(mut stream) = self.stream.take() {
            stream.shutdown().await.ok();
        }
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.stream.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_tcp_transport() {
        // Start a simple echo server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            socket.write_all(&buf[..n]).await.unwrap();
        });

        // Connect client
        let mut transport = TcpTransport::new_default();
        transport.connect(&addr.to_string()).await.unwrap();

        // Send and receive
        let msg = b"Hello, TCP!";
        transport.send(msg).await.unwrap();

        let mut buf = [0u8; 1024];
        let n = transport.recv(&mut buf).await.unwrap();

        assert_eq!(&buf[..n], msg);

        transport.close().await.unwrap();
        server.await.unwrap();
    }
}
