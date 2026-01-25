use async_speed_limit::{Limiter, Resource, clock::StandardClock};
use deadpool::managed::{Manager, Object, Pool, RecycleResult};
use russh::{ChannelStream, server::Msg};

// A pool manager for SSH connections.
pub(crate) struct SshPoolManager {
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
        _: &mut Self::Type,
        _: &deadpool::managed::Metrics,
    ) -> RecycleResult<Self::Error> {
        Ok(())
    }
}

pub(crate) type SshPool = Pool<SshPoolManager>;

pub(crate) type SshPoolObject = Object<SshPoolManager>;
