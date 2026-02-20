use std::{
    net::{IpAddr, SocketAddr},
    pin::pin,
    sync::{Arc, RwLock},
    time::Duration,
};

use ahash::RandomState;
use async_speed_limit::{Limiter, Resource, clock::StandardClock};
use dashmap::DashMap;
use russh::{ChannelStream, keys::ssh_key::Fingerprint, server::Msg};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{OwnedSemaphorePermit, Semaphore},
    time::timeout,
};

use crate::{
    connection_handler::{ConnectionHandler, ConnectionHttpData},
    error::ServerError,
    ip::IpFilter,
    ssh::{FingerprintFn, ServerHandlerSender},
};

struct IpConnectionGuard {
    ip: IpAddr,
    _permit: OwnedSemaphorePermit,
    ip_connections: Arc<DashMap<IpAddr, Arc<Semaphore>, RandomState>>,
}

impl Drop for IpConnectionGuard {
    fn drop(&mut self) {
        self.ip_connections
            .remove_if(&self.ip, |_, semaphore| Arc::strong_count(semaphore) == 1);
    }
}

// Reference-counted wrapper of an SSH channel stream.
pub(crate) struct SshChannel {
    // AsyncRead + AsyncWrite implementer being wrapped.
    inner: Resource<ChannelStream<Msg>, StandardClock>,
    // IP connection guard that the connection is being used until it is dropped.
    _ip_connection_guard: IpConnectionGuard,
    // Pool permit that signals that the connection is being used until it is dropped.
    _pool_permit: OwnedSemaphorePermit,
}

impl AsyncRead for SshChannel {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        pin!(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for SshChannel {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        pin!(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        pin!(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        pin!(&mut self.inner).poll_shutdown(cx)
    }
}

// Struct for generating tunneling/aliasing channels from an underlying SSH connection,
// via remote forwarding. It also includes a log channel to communicate messages
// (such as HTTP logs) back to the SSH connection.
#[derive(Clone)]
pub(crate) struct SshTunnelHandler {
    // Closure to verify valid fingerprints for local forwardings. Default is to allow all.
    pub(crate) allow_fingerprint: Arc<RwLock<Box<FingerprintFn>>>,
    // Optional extra data available for HTTP tunneling/aliasing connections.
    pub(crate) http_data: Option<Arc<RwLock<ConnectionHttpData>>>,
    // Handler of simultaneous connections for this handler.
    pub(crate) pool: Arc<Semaphore>,
    // How long should a connection wait for a spot in the pool before being timed out.
    pub(crate) pool_timeout: Option<Duration>,
    // Track number of active connections per IP.
    pub(crate) ip_connections: Arc<DashMap<IpAddr, Arc<Semaphore>, RandomState>>,
    // Maximum connections allowed per IP.
    pub(crate) max_connections_per_ip: usize,
    // Optional IP filtering for this handler's tunneling and aliasing channels.
    pub(crate) ip_filter: Arc<RwLock<Option<IpFilter>>>,
    // Handle to the SSH connection, in order to create remote forwarding channels.
    pub(crate) handle: russh::server::Handle,
    // Sender to the opened data session for logging.
    pub(crate) tx: ServerHandlerSender,
    // IP and port of the SSH connection, for logging.
    pub(crate) peer: SocketAddr,
    // Address used for the remote forwarding, required for the client to open the correct session channels.
    pub(crate) address: String,
    // Port used for the remote forwarding, required for the client to open the correct session channels.
    pub(crate) port: u32,
    // Limiter for rate limiting.
    pub(crate) limiter: Limiter,
}

impl Drop for SshTunnelHandler {
    fn drop(&mut self) {
        // Notify user of their handler being dropped, i.e. when using LoadBalancing::Replace.
        let _ = self.tx.send(
            format!(
                "\x1b[1;33mWARNING:\x1b[0m The handler for {}:{} has been dropped. \
                No new connections will be accepted.\r\n",
                self.address, self.port
            )
            .into_bytes(),
        );
    }
}

impl ConnectionHandler<SshChannel> for SshTunnelHandler {
    fn log_channel(&self) -> ServerHandlerSender {
        self.tx.clone()
    }

    async fn tunneling_channel(&self, ip: IpAddr, port: u16) -> Result<SshChannel, ServerError> {
        // Check if this IP is not blocked
        let tunneling_allowed = self
            .ip_filter
            .read()
            .expect("not poisoned")
            .as_ref()
            .is_none_or(|filter| filter.is_allowed(ip));
        if tunneling_allowed {
            let ip_connection_guard = self.acquire_ip_guard(ip)?;
            let pool = Arc::clone(&self.pool);
            let pool_permit = if let Some(duration) = self.pool_timeout {
                let Ok(Ok(pool_permit)) =
                    timeout(duration, async move { pool.acquire_owned().await }).await
                else {
                    return Err(ServerError::PoolLimitReached);
                };
                pool_permit
            } else {
                let Ok(pool_permit) = pool.try_acquire_owned() else {
                    return Err(ServerError::PoolLimitReached);
                };
                pool_permit
            };
            let channel = self
                .handle
                .channel_open_forwarded_tcpip(
                    self.address.clone(),
                    self.port,
                    ip.to_string(),
                    port.into(),
                )
                .await?
                .into_stream();
            Ok(SshChannel {
                inner: self.limiter.clone().limit(channel),
                _ip_connection_guard: ip_connection_guard,
                _pool_permit: pool_permit,
            })
        } else {
            Err(ServerError::TunnelingNotAllowed)
        }
    }

    fn can_alias(&self, ip: IpAddr, _port: u16, fingerprint: Option<&'_ Fingerprint>) -> bool {
        // Check if this IP is not blocked for the alias
        self.ip_filter
            .read()
            .expect("not poisoned")
            .as_ref()
            .is_none_or(|filter| filter.is_allowed(ip))
            // Check if the given fingerprint is allowed to local-forward this alias
            && (self.allow_fingerprint.read().expect("not poisoned"))(fingerprint)
    }

    async fn aliasing_channel(
        &self,
        ip: IpAddr,
        port: u16,
        fingerprint: Option<&'_ Fingerprint>,
    ) -> Result<SshChannel, ServerError> {
        if self.can_alias(ip, port, fingerprint) {
            let ip_connection_guard = self.acquire_ip_guard(ip)?;
            let pool = Arc::clone(&self.pool);
            let pool_permit = if let Some(duration) = self.pool_timeout {
                let Ok(Ok(pool_permit)) =
                    timeout(duration, async move { pool.acquire_owned().await }).await
                else {
                    return Err(ServerError::PoolLimitReached);
                };
                pool_permit
            } else {
                let Ok(pool_permit) = pool.try_acquire_owned() else {
                    return Err(ServerError::PoolLimitReached);
                };
                pool_permit
            };
            let channel = self
                .handle
                .channel_open_forwarded_tcpip(
                    self.address.clone(),
                    self.port,
                    ip.to_string(),
                    port.into(),
                )
                .await?
                .into_stream();
            Ok(SshChannel {
                inner: self.limiter.clone().limit(channel),
                _ip_connection_guard: ip_connection_guard,
                _pool_permit: pool_permit,
            })
        } else {
            Err(ServerError::AliasingNotAllowed)
        }
    }

    fn http_data(&self) -> Option<ConnectionHttpData> {
        Some(
            self.http_data
                .as_ref()?
                .read()
                .expect("not poisoned")
                .clone(),
        )
    }
}

impl SshTunnelHandler {
    fn acquire_ip_guard(&self, ip: IpAddr) -> Result<IpConnectionGuard, ServerError> {
        let semaphore = {
            let entry = self
                .ip_connections
                .entry(ip)
                .or_insert(Arc::new(Semaphore::new(self.max_connections_per_ip)));
            Arc::clone(&entry.value())
        };
        let Ok(_permit) = semaphore.try_acquire_owned() else {
            return Err(ServerError::IpConnectionLimitReached);
        };
        Ok(IpConnectionGuard {
            ip,
            ip_connections: Arc::clone(&self.ip_connections),
            _permit,
        })
    }
}
