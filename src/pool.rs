use std::{
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_speed_limit::{Limiter, Resource, clock::StandardClock};
use deadpool::managed::{Manager, Object, Pool, RecycleResult};
use russh::{ChannelStream, server::Msg};
use tokio::io::{AsyncRead, AsyncWrite};

// A pool manager for SSH connections.
pub(crate) struct SshPoolManager {
    // The size of the managed pool.
    pub(crate) pool_size: Arc<AtomicUsize>,
    // Handle to the SSH connection, in order to create remote forwarding channels.
    pub(crate) handle: russh::server::Handle,
    // Address used for the remote forwarding, required for the client to open the correct session channels.
    pub(crate) address: String,
    // Port used for the remote forwarding, required for the client to open the correct session channels.
    pub(crate) port: u32,
    // Limiter for rate limiting.
    pub(crate) limiter: Limiter,
}

impl Manager for SshPoolManager {
    type Type = Resource<ChannelStream<Msg>, StandardClock>;

    type Error = russh::Error;

    async fn create(&self) -> Result<Self::Type, Self::Error> {
        Ok(self.limiter.clone().limit(
            self.handle
                .channel_open_forwarded_tcpip(self.address.clone(), self.port, "", 0)
                .await?
                .into_stream(),
        ))
    }

    async fn recycle(
        &self,
        instance: &mut Self::Type,
        _: &deadpool::managed::Metrics,
    ) -> RecycleResult<Self::Error> {

        Ok(())
    }
}

pub(crate) type SshPool = Pool<SshPoolManager>;

pub(crate) struct SshPoolObject(Object<SshPoolManager>);

impl SshPoolObject {
    pub(crate) fn new(inner: Object<SshPoolManager>) -> Self {
        Self(inner)
    }
}

impl AsyncRead for SshPoolObject {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        pin!(self.0.as_mut().expect("not taken").as_mut()).poll_read(cx, buf)
    }
}

impl AsyncWrite for SshPoolObject {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        pin!(self.0.as_mut().expect("not taken").as_mut()).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        pin!(self.0.as_mut().expect("not taken").as_mut()).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        pin!(self.0.as_mut().expect("not taken").as_mut()).poll_shutdown(cx)
    }
}
