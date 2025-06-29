#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//!
#![doc = include_str!("../README.md")]
//!

use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    sync::{Arc, Mutex, RwLock, atomic::AtomicUsize},
    time::Duration,
};

use ahash::RandomState;
use async_speed_limit::{Limiter, Resource, clock::StandardClock};
use russh::{ChannelStream, keys::ssh_key::Fingerprint, server::Msg};
use tokio_util::sync::CancellationToken;

use crate::{
    addressing::{AddressDelegator, DnsResolver},
    connections::ConnectionMap,
    connections::HttpAliasingConnection,
    fingerprints::FingerprintsValidator,
    http::ProxyData,
    login::{ApiLogin, WebpkiVerifierConfigurer},
    reactor::{AliasReactor, HttpReactor, SniReactor, SshReactor, TcpReactor},
    ssh::SshTunnelHandler,
    tcp::TcpHandler,
    tcp_alias::TcpAlias,
    telemetry::Telemetry,
};

#[doc(hidden)]
pub use crate::{
    config::{ApplicationConfig, BindHostnames, LoadBalancing, RandomSubdomainSeed},
    entrypoint::entrypoint,
};

mod acme;
mod addressing;
mod admin;
mod certificates;
mod config;
mod connection_handler;
mod connections;
mod directory;
mod droppable_handle;
mod entrypoint;
mod error;
mod fingerprints;
mod http;
mod ip;
mod login;
mod quota;
mod reactor;
mod ssh;
mod ssh_exec;
mod ssh_forwarding;
mod tcp;
mod tcp_alias;
mod telemetry;
mod tls;

// Data collected from the system and displayed on the admin interface.
#[derive(Default, Clone)]
struct SystemData {
    used_memory: u64,
    total_memory: u64,
    network_tx: u64,
    network_rx: u64,
    cpu_usage: f32,
}

// A list of sessions and their cancelation channels.
type SessionMap = (Limiter, HashMap<usize, CancellationToken, RandomState>);
// A generic table with data for the admin interface.
type DataTable<K, V> = Arc<RwLock<BTreeMap<K, V>>>;
// Helper type for HTTP proxy data types.
type HttpProxyData<C> =
    Arc<ProxyData<Arc<C>, SshTunnelHandler, Resource<ChannelStream<Msg>, StandardClock>>>;
// HTTP proxy data used by the tunneling connections.
type TunnelingProxyData = HttpProxyData<ConnectionMap<String, Arc<SshTunnelHandler>, HttpReactor>>;
// HTTP proxy data used by the local forwarding aliasing connections.
type AliasingProxyData = HttpProxyData<HttpAliasingConnection>;

pub(crate) struct SandholeServer {
    // A unique ID assigned for each SSH session.
    pub(crate) session_id: AtomicUsize,
    // A map of all sessions for a given user authenticated with a username+password pair.
    pub(crate) sessions_password: Mutex<HashMap<String, SessionMap, RandomState>>,
    // A map of all sessions for a given user authenticated with a public key.
    pub(crate) sessions_publickey: Mutex<BTreeMap<Fingerprint, SessionMap>>,
    // The map for forwarded SSH connections.
    pub(crate) ssh: Arc<ConnectionMap<String, Arc<SshTunnelHandler>, SshReactor>>,
    // The map for forwarded HTTP connections.
    pub(crate) http: Arc<ConnectionMap<String, Arc<SshTunnelHandler>, HttpReactor>>,
    // The map for forwarded SNI connections.
    pub(crate) sni: Arc<ConnectionMap<String, Arc<SshTunnelHandler>, SniReactor>>,
    // The map for forwarded TCP connections.
    pub(crate) tcp: Arc<ConnectionMap<u16, Arc<SshTunnelHandler>, TcpReactor>>,
    // The map for forwarded aliased connections.
    pub(crate) alias: Arc<ConnectionMap<TcpAlias, Arc<SshTunnelHandler>, AliasReactor>>,
    // A collection of telemetry for the multiple systems, in order to display data in the admin interface.
    pub(crate) telemetry: Arc<Telemetry>,
    // Data related to the SSH forwardings for the admin interface.
    pub(crate) ssh_data: DataTable<String, (BTreeMap<SocketAddr, String>, f64)>,
    // Data related to the HTTP forwardings for the admin interface.
    pub(crate) http_data: DataTable<String, (BTreeMap<SocketAddr, String>, f64)>,
    // Data related to the SNI forwardings for the admin interface.
    pub(crate) sni_data: DataTable<String, (BTreeMap<SocketAddr, String>, f64)>,
    // Data related to the TCP forwardings for the admin interface.
    pub(crate) tcp_data: DataTable<u16, (BTreeMap<SocketAddr, String>, f64)>,
    // Data related to the alias forwardings for the admin interface.
    pub(crate) alias_data: DataTable<TcpAlias, (BTreeMap<SocketAddr, String>, f64)>,
    // System data for the admin interface.
    pub(crate) system_data: Arc<RwLock<SystemData>>,
    // HTTP proxy data used by the local forwarding aliasing connections.
    pub(crate) aliasing_proxy_data: AliasingProxyData,
    // Service for validating fingerprint authentications and automatically update its data when the filesystem changes.
    pub(crate) fingerprints_validator: FingerprintsValidator,
    // Service for user+password authentication via a login API via a config-provided URL.
    pub(crate) api_login: Option<ApiLogin<WebpkiVerifierConfigurer>>,
    // Service for assigning automatic addresses according to the addressing policies.
    pub(crate) address_delegator: Arc<AddressDelegator<DnsResolver>>,
    // Service for handling opening and closing TCP sockets for non-aliased services.
    pub(crate) tcp_handler: Arc<TcpHandler>,
    // The base domain of Sandhole.
    pub(crate) domain: String,
    // Which port Sandhole listens to for HTTP connections.
    pub(crate) http_port: u16,
    // Which port Sandhole listens to for HTTPS connections.
    pub(crate) https_port: u16,
    // Which port Sandhole listens to for SSH connections.
    pub(crate) ssh_port: u16,
    // If true, allows users to select the TCP ports assigned by tcp_handler.
    pub(crate) force_random_ports: bool,
    // If true, HTTP is disabled.
    pub(crate) disable_http: bool,
    // If true, HTTPS is disabled.
    pub(crate) disable_https: bool,
    // If true, SNI is disabled.
    pub(crate) disable_sni: bool,
    // If true, TCP is disabled for all ports except for HTTP.
    pub(crate) disable_tcp: bool,
    // If true, aliasing is disabled, including SSH and all local forwarding connections.
    pub(crate) disable_aliasing: bool,
    // Buffer size for bidirectional copying.
    pub(crate) buffer_size: usize,
    // Rate limit per second for services of a single user.
    pub(crate) rate_limit: f64,
    // How long until a login API request is timed out.
    pub(crate) authentication_request_timeout: Duration,
    // How long until an unauthed connection is closed.
    pub(crate) idle_connection_timeout: Duration,
    // How long until an unauthed connection is closed AFTER it successfully local forwards.
    pub(crate) unproxied_connection_timeout: Duration,
    // How long until TCP, WebSocket, and local forwarding connections are closed.
    pub(crate) tcp_connection_timeout: Option<Duration>,
}

impl SandholeServer {
    // Returns true if the address is an alias and not localhost/empty/*
    pub(crate) fn is_alias(&self, address: &str) -> bool {
        address != "localhost" && !address.is_empty() && address != "*" && address != self.domain
    }
}
