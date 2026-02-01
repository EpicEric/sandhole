use std::{
    collections::HashMap,
    fmt::Display,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicIsize, AtomicUsize, Ordering},
    },
    time::Duration,
};

use ahash::RandomState;
use async_speed_limit::Limiter;
use ipnet::IpNet;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

use crate::{
    admin::interface::AdminInterface, connection_handler::ConnectionHttpData,
    droppable_handle::DroppableHandle, ip::IpFilter, quota::TokenHolder, ssh::FingerprintFn,
    tcp_alias::TcpAlias,
};

pub(crate) struct ProxyAutoCancellation {
    // Channel to communicate that this connection must be closed.
    pub(crate) cancellation_token: CancellationToken,
    // How long until an unauthed connection is closed AFTER it successfully local forwards.
    pub(crate) unproxied_connection_timeout: Duration,
    // The amount of proxy auto cancellation clones.
    pub(crate) proxy_count: Arc<AtomicIsize>,
    // A handle to a task that disconnects unauthed users after a while.
    pub(crate) timeout_handle: Arc<Mutex<Option<DroppableHandle<()>>>>,
}

impl ProxyAutoCancellation {
    pub(crate) fn start_timeout(&mut self, timeout: Duration) {
        let cancellation_token = self.cancellation_token.clone();
        *self.timeout_handle.lock().expect("not poisoned") =
            Some(DroppableHandle(tokio::spawn(async move {
                sleep(timeout).await;
                cancellation_token.cancel();
            })));
    }
}

impl Clone for ProxyAutoCancellation {
    fn clone(&self) -> Self {
        self.timeout_handle.lock().expect("not poisoned").take();
        self.proxy_count.fetch_add(1, Ordering::Release);
        Self {
            unproxied_connection_timeout: self.unproxied_connection_timeout,
            cancellation_token: self.cancellation_token.clone(),
            proxy_count: self.proxy_count.clone(),
            timeout_handle: self.timeout_handle.clone(),
        }
    }
}

impl Drop for ProxyAutoCancellation {
    fn drop(&mut self) {
        if self.proxy_count.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.start_timeout(self.unproxied_connection_timeout);
        }
    }
}

#[derive(Debug)]
pub(crate) enum UserSessionRestriction {
    // No restriction on the session.
    None,
    // Whether this session only has aliases, from the `tcp-alias` or `allowed-fingerprints` options.
    TcpAliasOnly,
    // Whether this session only has SNI proxies, from the `sni-proxy` option.
    SniProxyOnly,
}

// Data shared by user and admin SSH sessions,
pub(crate) struct UserData {
    // Closure to verify valid fingerprints for local forwardings. Default is to allow all.
    pub(crate) allow_fingerprint: Arc<RwLock<Box<FingerprintFn>>>,
    // Extra data available for HTTP tunneling/aliasing connections.
    pub(crate) http_data: Arc<RwLock<ConnectionHttpData>>,
    // Maximum amount of simultaneous connections for each handler.
    pub(crate) max_pool_size: Arc<AtomicUsize>,
    // Optional IP filtering for this connection's tunneling and aliasing channels.
    pub(crate) ip_filter: Arc<RwLock<Option<IpFilter>>>,
    // What kind of restriction to impose on tunnels and aliases for this session.
    pub(crate) session_restriction: UserSessionRestriction,
    // Identifier for the user, used for creating quota tokens.
    pub(crate) quota_key: TokenHolder,
    // Map to keep track of opened host-based connections (HTTP and SSH), to clean up when the forwarding is canceled.
    pub(crate) host_addressing: HashMap<TcpAlias, String, RandomState>,
    // Map to keep track of opened port-based connections (TCP), to clean up when the forwarding is canceled.
    pub(crate) port_addressing: HashMap<TcpAlias, u16, RandomState>,
    // Map to keep track of opened alias-based connections (aliases), to clean up when the forwarding is canceled.
    pub(crate) alias_addressing: HashMap<TcpAlias, TcpAlias, RandomState>,
    // IPs allowed to connect to this user's services.
    pub(crate) allowlist: Option<Vec<IpNet>>,
    // IPs disallowed from connecting to this user's services.
    pub(crate) blocklist: Option<Vec<IpNet>>,
    // Rate limiter for this user's services.
    pub(crate) limiter: Limiter,
}

impl UserData {
    pub(crate) fn new(quota_key: TokenHolder, limiter: Limiter, max_pool_size: usize) -> Self {
        Self {
            allow_fingerprint: Arc::new(RwLock::new(Box::new(|_| true))),
            http_data: Arc::new(RwLock::new(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
                http2: false,
                host: None,
            })),
            max_pool_size: Arc::new(AtomicUsize::new(max_pool_size)),
            ip_filter: Arc::new(RwLock::new(None)),
            session_restriction: UserSessionRestriction::None,
            quota_key,
            host_addressing: Default::default(),
            port_addressing: Default::default(),
            alias_addressing: Default::default(),
            allowlist: Default::default(),
            blocklist: Default::default(),
            limiter,
        }
    }
}

// Data exclusive to the admin SSH session.
pub(crate) struct AdminData {
    // Flag indicating whether this session has any forwardings associated with it.
    // Used to prevent forwardings and the admin interface from being used together in a single session.
    pub(crate) is_forwarding: bool,
    // An allocated pseudo-terminal with the admin TUI.
    pub(crate) admin_interface: Option<AdminInterface>,
    // Width (in columns) of the user's pseudo-terminal.
    pub(crate) col_width: Option<u32>,
    // Height (in rows) of the user's pseudo-terminal.
    pub(crate) row_height: Option<u32>,
}

impl AdminData {
    pub(crate) fn new() -> Self {
        Self {
            is_forwarding: false,
            admin_interface: None,
            col_width: Default::default(),
            row_height: Default::default(),
        }
    }
}

// Possible authentication states and data.
pub(crate) enum AuthenticatedData {
    // User is not authenticated; only allowed to local forward connections.
    None {
        proxy_data: Box<ProxyAutoCancellation>,
    },
    // User is authenticated, and allowed to remote forward connections.
    User {
        user_data: Box<UserData>,
    },
    // User is authenticated, and allowed to remote forward connections or access the admin TUI.
    Admin {
        user_data: Box<UserData>,
        admin_data: Box<AdminData>,
    },
}

impl Display for AuthenticatedData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthenticatedData::None { .. } => f.write_str("NONE"),
            AuthenticatedData::User { .. } => f.write_str("USER"),
            AuthenticatedData::Admin { .. } => f.write_str("ADMIN"),
        }
    }
}
