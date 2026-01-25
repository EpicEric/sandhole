use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, RwLock},
    time::Duration,
};

use deadpool::managed::Timeouts;
use russh::keys::ssh_key::Fingerprint;

use crate::{
    connection_handler::{ConnectionHandler, ConnectionHttpData},
    error::ServerError,
    ip::IpFilter,
    pool::{SshPool, SshPoolObject},
    ssh::{FingerprintFn, ServerHandlerSender},
};

// Struct for generating tunneling/aliasing channels from an underlying SSH connection,
// via remote forwarding. It also includes a log channel to communicate messages
// (such as HTTP logs) back to the SSH connection.
#[derive(Clone)]
pub(crate) struct SshTunnelHandler {
    // Closure to verify valid fingerprints for local forwardings. Default is to allow all.
    pub(crate) allow_fingerprint: Arc<RwLock<Box<FingerprintFn>>>,
    // Optional extra data available for HTTP tunneling/aliasing connections.
    pub(crate) http_data: Option<Arc<RwLock<ConnectionHttpData>>>,
    // Optional IP filtering for this handler's tunneling and aliasing channels.
    pub(crate) ip_filter: Arc<RwLock<Option<IpFilter>>>,
    // Time to wait for a remote forwarding to be available before giving up.
    pub(crate) wait_timeout: Arc<RwLock<Duration>>,
    // Time to keep a remote forwarding channel around for.
    pub(crate) idle_timeout: Arc<RwLock<Duration>>,
    // SSH connection pool, in order to create remote forwarding channels.
    pub(crate) pool: SshPool,
    // Sender to the opened data session for logging.
    pub(crate) tx: ServerHandlerSender,
    // IP and port of the SSH connection, for logging.
    pub(crate) peer: SocketAddr,
    // Address used for the remote forwarding, required for the client to open the correct session channels.
    pub(crate) address: String,
    // Port used for the remote forwarding, required for the client to open the correct session channels.
    pub(crate) port: u32,
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

impl ConnectionHandler<SshPoolObject> for SshTunnelHandler {
    fn log_channel(&self) -> ServerHandlerSender {
        self.tx.clone()
    }

    async fn tunneling_channel(
        &self,
        ip: IpAddr,
        _port: u16,
    ) -> Result<SshPoolObject, ServerError> {
        // Check if this IP is not blocked
        let tunneling_allowed = self
            .ip_filter
            .read()
            .expect("not poisoned")
            .as_ref()
            .is_none_or(|filter| filter.is_allowed(ip));
        if tunneling_allowed {
            let timeouts = Timeouts {
                wait: Some(*self.wait_timeout.read().expect("not poisoned")),
                recycle: Some(*self.idle_timeout.read().expect("not poisoned")),
                create: None,
            };
            Ok(SshPoolObject::new(self.pool.timeout_get(&timeouts).await?))
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
    ) -> Result<SshPoolObject, ServerError> {
        if self.can_alias(ip, port, fingerprint) {
            let timeouts = Timeouts {
                wait: Some(*self.wait_timeout.read().expect("not poisoned")),
                recycle: Some(*self.idle_timeout.read().expect("not poisoned")),
                create: None,
            };
            Ok(SshPoolObject::new(self.pool.timeout_get(&timeouts).await?))
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
