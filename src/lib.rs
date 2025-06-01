#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//!
#![doc = include_str!("../README.md")]
//!

use std::{
    collections::{BTreeMap, HashMap},
    convert::Infallible,
    future,
    net::SocketAddr,
    num::NonZero,
    sync::{Arc, Mutex, RwLock, atomic::AtomicUsize},
    time::Duration,
};

use anyhow::Context;
use axum::response::IntoResponse;
use hyper::{Request, StatusCode, body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use log::{debug, error, info, warn};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use russh::{
    ChannelStream,
    keys::{
        decode_secret_key,
        ssh_key::{Fingerprint, LineEnding, private::Ed25519Keypair},
    },
    server::{Config, Msg},
};
use rustls::ServerConfig;
use rustls_acme::acme::ACME_TLS_ALPN_NAME;
use rustrict::CensorStr;
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, Networks, RefreshKind, System};
use tokio::{
    fs,
    io::{AsyncWriteExt, copy_bidirectional_with_sizes},
    net::{TcpListener, TcpStream},
    pin,
    time::{sleep, timeout},
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::{
    acme::AcmeResolver,
    acme::AlpnAcmeResolver,
    addressing::{AddressDelegator, DnsResolver},
    certificates::{AlpnChallengeResolver, CertificateResolver, DummyAlpnChallengeResolver},
    connection_handler::ConnectionHandler,
    connections::ConnectionMap,
    connections::HttpAliasingConnection,
    droppable_handle::DroppableHandle,
    error::ServerError,
    fingerprints::FingerprintsValidator,
    http::{DomainRedirect, ProxyData, ProxyType},
    http::{Protocol, proxy_handler},
    ip::{IpFilter, IpFilterConfig},
    login::{ApiLogin, WebpkiVerifierConfigurer},
    quota::{DummyQuotaHandler, QuotaHandler, QuotaMap},
    reactor::{AliasReactor, HttpReactor, SniReactor, SshReactor, TcpReactor},
    ssh::{Server, SshTunnelHandler},
    tcp::TcpHandler,
    tcp_alias::TcpAlias,
    telemetry::Telemetry,
    tls::{TlsPeekData, peek_sni_and_alpn},
};

#[doc(hidden)]
pub use crate::config::{ApplicationConfig, BindHostnames, LoadBalancing, RandomSubdomainSeed};

mod acme;
mod addressing;
mod admin;
mod certificates;
mod config;
mod connection_handler;
mod connections;
mod directory;
mod droppable_handle;
mod error;
mod fingerprints;
mod http;
mod ip;
mod login;
mod quota;
mod reactor;
mod ssh;
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
type SessionMap = HashMap<usize, CancellationToken>;
// A generic table with data for the admin interface.
type DataTable<K, V> = Arc<RwLock<BTreeMap<K, V>>>;
// Helper type for HTTP proxy data types.
type HttpProxyData<C> = Arc<ProxyData<Arc<C>, SshTunnelHandler, ChannelStream<Msg>>>;
// HTTP proxy data used by the tunneling connections.
type TunnelingProxyData = HttpProxyData<ConnectionMap<String, Arc<SshTunnelHandler>, HttpReactor>>;
// HTTP proxy data used by the local forwarding aliasing connections.
type AliasingProxyData = HttpProxyData<HttpAliasingConnection>;

pub(crate) struct SandholeServer {
    // A unique ID assigned for each SSH session.
    pub(crate) session_id: AtomicUsize,
    // A map of all sessions for a given user authenticated with a username+password pair.
    pub(crate) sessions_password: Mutex<HashMap<String, SessionMap>>,
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
    // If true, SNI is disabled.
    pub(crate) disable_sni: bool,
    // If true, TCP is disabled for all ports except for HTTP.
    pub(crate) disable_tcp: bool,
    // If true, aliasing is disabled, including SSH and all local forwarding connections.
    pub(crate) disable_aliasing: bool,
    // Buffer size for bidirectional copying.
    pub(crate) buffer_size: usize,
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

#[doc(hidden)]
// Main entrypoint of the application.
pub async fn entrypoint(config: ApplicationConfig) -> anyhow::Result<()> {
    info!("Starting Sandhole...");
    // Check configuration flags for issues or other operations
    if config.disable_http && config.disable_tcp && config.disable_aliasing {
        return Err(ServerError::InvalidConfig(
            "One of HTTP, TCP, or aliasing must be enabled".into(),
        )
        .into());
    }
    let http_request_timeout = config.http_request_timeout;
    let tcp_connection_timeout = config.tcp_connection_timeout;
    // Initialize crypto and credentials
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    // Find the private SSH key for Sandhole or create a new one.
    let key = match fs::read_to_string(config.private_key_file.as_path()).await {
        Ok(key) => decode_secret_key(&key, None).with_context(|| "Error decoding secret key")?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            info!("Key file not found. Creating...");
            let key = russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(
                &ChaCha20Rng::from_os_rng().random(),
            ));
            if !config.disable_directory_creation {
                fs::create_dir_all(
                    config
                        .private_key_file
                        .as_path()
                        .parent()
                        .ok_or(ServerError::InvalidFilePath)
                        .with_context(|| "Error parsing secret key path")?,
                )
                .await
                .with_context(|| "Error creating secret key directory")?;
            }
            let key_string = key.to_openssh(LineEnding::LF)?;
            let key = decode_secret_key(&key_string, None)
                .with_context(|| "Error decoding secret key")?;
            fs::write(config.private_key_file.as_path(), key_string)
                .await
                .with_context(|| "Error saving secret key to filesystem")?;
            key
        }
        Err(err) => return Err(err).with_context(|| "Error reading secret key"),
    };

    // Initialize modules
    if !config.disable_directory_creation {
        fs::create_dir_all(config.user_keys_directory.as_path())
            .await
            .with_context(|| "Error creating user keys directory")?;
        fs::create_dir_all(config.admin_keys_directory.as_path())
            .await
            .with_context(|| "Error creating admin keys directory")?;
    }
    // Listen on the user_keys and admin_keys directories for new SSH public keys.
    let fingerprints =
        FingerprintsValidator::watch(config.user_keys_directory, config.admin_keys_directory)
            .await
            .with_context(|| "Error setting up public keys watcher")?;
    // Initialize the login API service if a URL has been set.
    let api_login = config
        .password_authentication_url
        .map(|url| ApiLogin::from(WebpkiVerifierConfigurer, url, http_request_timeout))
        .transpose()
        .with_context(|| "Error intializing login API")?;
    // Initialize the ACME ALPN service if a contact email has been provided.
    let alpn_resolver: Box<dyn AlpnChallengeResolver> = match config.acme_contact_email {
        _ if config.disable_https => Box::new(DummyAlpnChallengeResolver),
        Some(contact) if config.https_port == NonZero::new(443).unwrap() => {
            Box::new(AcmeResolver::new(
                AlpnAcmeResolver,
                config.acme_cache_directory,
                contact,
                config.acme_use_staging,
            ))
        }
        Some(_) => {
            warn!(
                "ACME challenges are only supported on HTTPS port 443 (currently {}). Disabling.",
                config.https_port
            );
            Box::new(DummyAlpnChallengeResolver)
        }
        None => Box::new(DummyAlpnChallengeResolver),
    };
    if !config.disable_directory_creation {
        fs::create_dir_all(config.certificates_directory.as_path())
            .await
            .with_context(|| "Error creating certificates directory")?;
    }
    // Listen on the certificates sub-directories for updates to Let's Encrypt certificates.
    let certificates = Arc::new(
        CertificateResolver::watch(config.certificates_directory, RwLock::new(alpn_resolver))
            .await
            .with_context(|| "Error setting up certificates watcher")?,
    );
    // Initialize the IP address allowlist/blocklist service.
    let ip_filter = Arc::new(IpFilter::from(IpFilterConfig {
        allowlist: config.ip_allowlist,
        blocklist: config.ip_blocklist,
    })?);
    let telemetry = Arc::new(Telemetry::new());
    let quota_handler: Arc<Box<dyn QuotaHandler + Send + Sync>> = match config.quota_per_user {
        Some(max_quota) => Arc::new(Box::new(Arc::new(QuotaMap::new(max_quota.into())))),
        None => Arc::new(Box::new(DummyQuotaHandler)),
    };
    let http_connections = Arc::new(
        ConnectionMap::builder()
            .load_balancing(config.load_balancing)
            .quota_handler(Arc::clone(&quota_handler))
            .reactor(HttpReactor {
                certificates: Arc::clone(&certificates),
                telemetry: Arc::clone(&telemetry),
            })
            .build(),
    );
    let sni_connections = Arc::new(
        ConnectionMap::builder()
            .load_balancing(config.load_balancing)
            .quota_handler(Arc::clone(&quota_handler))
            .reactor(SniReactor(Arc::clone(&telemetry)))
            .build(),
    );
    let ssh_connections = Arc::new(
        ConnectionMap::builder()
            .load_balancing(config.load_balancing)
            .quota_handler(Arc::clone(&quota_handler))
            .reactor(SshReactor(Arc::clone(&telemetry)))
            .build(),
    );
    let tcp_connections = Arc::new(
        ConnectionMap::builder()
            .load_balancing(config.load_balancing)
            .quota_handler(Arc::clone(&quota_handler))
            .build(),
    );
    let alias_connections = Arc::new(
        ConnectionMap::builder()
            .load_balancing(config.load_balancing)
            .quota_handler(Arc::clone(&quota_handler))
            .reactor(AliasReactor(Arc::clone(&telemetry)))
            .build(),
    );
    let tcp_handler: Arc<TcpHandler> = Arc::new(
        TcpHandler::builder()
            .listen_address(config.listen_address)
            .conn_manager(Arc::clone(&tcp_connections))
            .telemetry(Arc::clone(&telemetry))
            .ip_filter(Arc::clone(&ip_filter))
            .buffer_size(config.buffer_size)
            .disable_tcp_logs(config.disable_tcp_logs)
            .maybe_tcp_connection_timeout(tcp_connection_timeout)
            .build(),
    );
    // Add TCP handler service as a listener for TCP port updates.
    tcp_connections.update_reactor(Some(TcpReactor {
        handler: Arc::clone(&tcp_handler),
        telemetry: Arc::clone(&telemetry),
    }));
    // Add addressing service with optional profanity filtering
    let requested_domain_filter: Option<&'static rustrict::Trie> =
        if config.requested_domain_filter_profanities {
            let mut trie = rustrict::Trie::default();
            if config.domain.is_inappropriate() {
                warn!(
                    "Domain \"{}\" is considered a profanity; adding to safe word list",
                    config.domain
                );
                trie.set(&config.domain, rustrict::Type::SAFE);
            }
            Some(Box::leak(Box::new(trie)))
        } else {
            None
        };
    let addressing = Arc::new(
        AddressDelegator::builder()
            .resolver(DnsResolver::new())
            .txt_record_prefix(config.txt_record_prefix)
            .root_domain(config.domain.clone())
            .bind_hostnames(config.bind_hostnames)
            .force_random_subdomains(!config.allow_requested_subdomains)
            .maybe_random_subdomain_seed(config.random_subdomain_seed)
            .random_subdomain_length(config.random_subdomain_length)
            .random_subdomain_filter_profanities(config.random_subdomain_filter_profanities)
            .maybe_requested_domain_filter(requested_domain_filter)
            .build(),
    );
    // Configure the default domain redirect for Sandhole.
    let domain_redirect = Arc::new(DomainRedirect {
        from: config.domain.clone(),
        to: config.domain_redirect,
    });

    // Telemetry tasks
    let ssh_data = Arc::new(RwLock::default());
    if !config.disable_aliasing {
        let data_clone = Arc::clone(&ssh_data);
        let connections_clone = Arc::clone(&ssh_connections);
        let telemetry_clone = Arc::clone(&telemetry);
        // Periodically update SSH data, based on the connection map.
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_millis(3_000)).await;
                let data = connections_clone.data();
                let telemetry = telemetry_clone.get_ssh_connections_per_minute();
                let data = data
                    .into_iter()
                    .map(|(alias, addresses)| {
                        let connections_per_minute = *telemetry.get(&alias).unwrap_or(&0f64);
                        (alias, (addresses, connections_per_minute))
                    })
                    .collect();
                *data_clone.write().unwrap() = data;
            }
        });
    }
    let http_data = Arc::new(RwLock::default());
    let sni_data = Arc::new(RwLock::default());
    if !config.disable_http {
        let data_clone = Arc::clone(&http_data);
        let connections_clone = Arc::clone(&http_connections);
        let telemetry_clone = Arc::clone(&telemetry);
        // Periodically update HTTP data, based on the connection map and the telemetry counters.
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_millis(3_000)).await;
                let data = connections_clone.data();
                let telemetry = telemetry_clone.get_http_requests_per_minute();
                let data = data
                    .into_iter()
                    .map(|(hostname, addresses)| {
                        let requests_per_minute = *telemetry.get(&hostname).unwrap_or(&0f64);
                        (hostname, (addresses, requests_per_minute))
                    })
                    .collect();
                *data_clone.write().unwrap() = data;
            }
        });
        if !config.disable_sni {
            let data_clone = Arc::clone(&sni_data);
            let connections_clone = Arc::clone(&sni_connections);
            let telemetry_clone = Arc::clone(&telemetry);
            // Periodically update SNI data, based on the connection map and the telemetry counters.
            tokio::spawn(async move {
                loop {
                    sleep(Duration::from_millis(3_000)).await;
                    let data = connections_clone.data();
                    let telemetry = telemetry_clone.get_sni_connections_per_minute();
                    let data = data
                        .into_iter()
                        .map(|(hostname, addresses)| {
                            let connections_per_minute = *telemetry.get(&hostname).unwrap_or(&0f64);
                            (hostname, (addresses, connections_per_minute))
                        })
                        .collect();
                    *data_clone.write().unwrap() = data;
                }
            });
        }
    }
    let tcp_data = Arc::new(RwLock::default());
    if !config.disable_tcp {
        let data_clone = Arc::clone(&tcp_data);
        let connections_clone = Arc::clone(&tcp_connections);
        let telemetry_clone = Arc::clone(&telemetry);
        // Periodically update TCP data, based on the connection map.
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_millis(3_000)).await;
                let data = connections_clone.data();
                let telemetry = telemetry_clone.get_tcp_connections_per_minute();
                let data = data
                    .into_iter()
                    .map(|(port, addresses)| {
                        let connections_per_minute = *telemetry.get(&port).unwrap_or(&0f64);
                        (port, (addresses, connections_per_minute))
                    })
                    .collect();
                *data_clone.write().unwrap() = data;
            }
        });
    }
    let alias_data = Arc::new(RwLock::default());
    if !config.disable_aliasing {
        let data_clone = Arc::clone(&alias_data);
        let connections_clone = Arc::clone(&alias_connections);
        let telemetry_clone = Arc::clone(&telemetry);
        // Periodically update alias data, based on the connection map.
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_millis(3_000)).await;
                let data = connections_clone.data();
                let telemetry = telemetry_clone.get_alias_connections_per_minute();
                let data = data
                    .into_iter()
                    .map(|(alias, addresses)| {
                        let connections_per_minute = *telemetry.get(&alias).unwrap_or(&0f64);
                        (alias, (addresses, connections_per_minute))
                    })
                    .collect();
                *data_clone.write().unwrap() = data;
            }
        });
    }
    let system_data = Arc::new(RwLock::default());
    let data_clone = Arc::clone(&system_data);
    // Periodically update system data (every second, as to keep network TX/RX rates accurate).
    tokio::spawn(async move {
        let system_refresh = RefreshKind::nothing()
            .with_cpu(CpuRefreshKind::nothing().with_cpu_usage())
            .with_memory(MemoryRefreshKind::nothing().with_ram());
        let mut system = System::new_with_specifics(system_refresh);
        let mut networks = Networks::new_with_refreshed_list();
        loop {
            sleep(Duration::from_millis(1_000)).await;
            system.refresh_specifics(system_refresh);
            networks.refresh(true);
            let (network_tx, network_rx) = match networks
                .values()
                .map(|data| (data.transmitted(), data.received()))
                .reduce(|acc, elem| (acc.0 + elem.0, acc.1 + elem.1))
            {
                Some((tx, rx)) => (tx, rx),
                None => (0, 0),
            };
            let data = SystemData {
                cpu_usage: system.global_cpu_usage() / system.cpus().len() as f32,
                used_memory: system.used_memory(),
                total_memory: system.total_memory(),
                network_tx,
                network_rx,
            };
            *data_clone.write().unwrap() = data;
        }
    });

    // SSH server
    let ssh_config = Arc::new(Config {
        inactivity_timeout: Some(Duration::from_secs(3_600)),
        auth_rejection_time: Duration::from_secs(2),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        keepalive_interval: Some(Duration::from_secs(30)),
        maximum_packet_size: config
            .buffer_size
            .try_into()
            .with_context(|| "buffer_size must fit in 32 bits")?,
        keepalive_max: 4,
        keys: vec![key],
        ..Default::default()
    });
    // Create the local forwarding-specific HTTP proxy data.
    let aliasing_proxy_data = Arc::new(
        ProxyData::builder()
            .conn_manager(Arc::new(HttpAliasingConnection::new(
                Arc::clone(&http_connections),
                Arc::clone(&alias_connections),
            )))
            .telemetry(Arc::clone(&telemetry))
            .domain_redirect(Arc::clone(&domain_redirect))
            // HTTP only.
            .protocol(Protocol::Http {
                port: config.http_port.into(),
            })
            // Always use aliasing channels instead of tunneling channels.
            .proxy_type(ProxyType::Aliasing)
            .buffer_size(config.buffer_size)
            .maybe_http_request_timeout(http_request_timeout)
            .maybe_websocket_timeout(tcp_connection_timeout)
            .disable_http_logs(config.disable_http_logs)
            .build(),
    );
    let mut sandhole = Arc::new(SandholeServer {
        session_id: AtomicUsize::new(0),
        sessions_password: Mutex::default(),
        sessions_publickey: Mutex::default(),
        http: Arc::clone(&http_connections),
        sni: sni_connections,
        ssh: ssh_connections,
        tcp: tcp_connections,
        alias: alias_connections,
        telemetry: Arc::clone(&telemetry),
        http_data,
        sni_data,
        ssh_data,
        tcp_data,
        alias_data,
        system_data,
        aliasing_proxy_data,
        fingerprints_validator: fingerprints,
        api_login,
        address_delegator: addressing,
        tcp_handler,
        domain: config.domain,
        http_port: config.http_port.into(),
        https_port: config.https_port.into(),
        ssh_port: config.ssh_port.into(),
        force_random_ports: !config.allow_requested_ports,
        disable_http: config.disable_http,
        disable_sni: config.disable_sni,
        disable_tcp: config.disable_tcp,
        disable_aliasing: config.disable_aliasing,
        buffer_size: config.buffer_size,
        authentication_request_timeout: config.authentication_request_timeout,
        idle_connection_timeout: config.idle_connection_timeout,
        unproxied_connection_timeout: config
            .unproxied_connection_timeout
            .unwrap_or(config.idle_connection_timeout),
        tcp_connection_timeout,
    });

    // HTTP handler
    let mut join_handle_http = if config.disable_http {
        DroppableHandle(tokio::spawn(future::pending()))
    } else {
        let http_listener = TcpListener::bind((config.listen_address, config.http_port.into()))
            .await
            .with_context(|| "Error listening to HTTP port")?;
        info!(
            "Listening for HTTP connections on port {}.",
            config.http_port
        );
        let ip_filter_clone = Arc::clone(&ip_filter);
        let http_proxy_data = Arc::new(
            ProxyData::builder()
                .conn_manager(Arc::clone(&http_connections))
                .telemetry(Arc::clone(&telemetry))
                .domain_redirect(Arc::clone(&domain_redirect))
                // Use TLS redirect if --force-https is set, otherwise allow HTTP.
                .protocol(if config.force_https {
                    Protocol::TlsRedirect {
                        from: config.http_port.into(),
                        to: config.https_port.into(),
                    }
                } else {
                    Protocol::Http {
                        port: config.http_port.into(),
                    }
                })
                // Always use tunneling channels.
                .proxy_type(ProxyType::Tunneling)
                .buffer_size(config.buffer_size)
                .maybe_http_request_timeout(http_request_timeout)
                .maybe_websocket_timeout(tcp_connection_timeout)
                .disable_http_logs(config.disable_http_logs)
                .build(),
        );
        DroppableHandle(tokio::spawn(async move {
            loop {
                let proxy_data = Arc::clone(&http_proxy_data);
                let (stream, address) = match http_listener.accept().await {
                    Ok((stream, address)) => (stream, address),
                    Err(err) => {
                        error!("Unable to accept HTTP connection: {}", err);
                        break;
                    }
                };
                let ip = address.ip();
                if !ip_filter_clone.is_allowed(ip) {
                    info!("Rejecting HTTP connection for {}: not allowed", ip);
                    continue;
                }
                if let Err(err) = stream.set_nodelay(true) {
                    warn!("Error setting nodelay for {}: {}", address, err);
                }
                // Create a Hyper service and serve over the accepted TCP connection.
                let service = service_fn(move |req: Request<Incoming>| {
                    proxy_handler(req, address, None, Arc::clone(&proxy_data))
                });
                let io = TokioIo::new(stream);
                tokio::spawn(async move {
                    let server = auto::Builder::new(TokioExecutor::new());
                    let conn = server.serve_connection_with_upgrades(io, service);
                    match tcp_connection_timeout {
                        Some(duration) => {
                            let _ = timeout(duration, conn).await;
                        }
                        None => {
                            let _ = conn.await;
                        }
                    }
                });
            }
        }))
    };

    // HTTPS handler (with optional SSH handling)
    let mut join_handle_https = if config.disable_http || config.disable_https {
        DroppableHandle(tokio::spawn(future::pending()))
    } else {
        let https_listener = TcpListener::bind((config.listen_address, config.https_port.into()))
            .await
            .with_context(|| "Error listening to HTTPS port")?;
        info!(
            "Listening for HTTPS connections on port {}.",
            config.https_port
        );
        let certificates_clone = Arc::clone(&certificates);
        let mut http11_server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(certificates);
        let mut http2_server_config = http11_server_config.clone();
        http11_server_config
            .alpn_protocols
            .extend_from_slice(&[b"http/1.1".to_vec()]);
        let http11_server_config = Arc::new(http11_server_config);
        http2_server_config
            .alpn_protocols
            .extend_from_slice(&[b"h2".to_vec(), b"http/1.1".to_vec()]);
        let http2_server_config = Arc::new(http2_server_config);
        let ip_filter_clone = Arc::clone(&ip_filter);
        let https_proxy_data = Arc::new(
            ProxyData::builder()
                .conn_manager(Arc::clone(&http_connections))
                .telemetry(Arc::clone(&telemetry))
                .domain_redirect(Arc::clone(&domain_redirect))
                .protocol(Protocol::Https {
                    port: config.https_port.into(),
                })
                // Always use tunneling channels.
                .proxy_type(ProxyType::Tunneling)
                .buffer_size(config.buffer_size)
                .maybe_http_request_timeout(http_request_timeout)
                .maybe_websocket_timeout(tcp_connection_timeout)
                .disable_http_logs(config.disable_http_logs)
                .build(),
        );
        let sandhole_clone = Arc::clone(&sandhole);
        let ssh_config_clone = Arc::clone(&ssh_config);
        DroppableHandle(tokio::spawn(async move {
            loop {
                let (stream, address) = match https_listener.accept().await {
                    Ok((stream, address)) => (stream, address),
                    Err(err) => {
                        error!("Unable to accept HTTPS connection: {}", err);
                        break;
                    }
                };
                let ip = address.ip();
                if !ip_filter_clone.is_allowed(ip) {
                    info!("Rejecting HTTPS connection for {}: not allowed", ip);
                    continue;
                }
                if let Err(err) = stream.set_nodelay(true) {
                    warn!("Error setting nodelay for {}: {}", address, err);
                }
                handle_https_connection(HandleHttpsConnectionConfig {
                    stream,
                    address,
                    connect_ssh_on_https_port: config.connect_ssh_on_https_port,
                    proxy_data: Arc::clone(&https_proxy_data),
                    ssh_config: Arc::clone(&ssh_config_clone),
                    sandhole: Arc::clone(&sandhole_clone),
                    certificates: Arc::clone(&certificates_clone),
                    http2_server_config: Arc::clone(&http2_server_config),
                    http11_server_config: Arc::clone(&http11_server_config),
                });
            }
        }))
    };

    // Start Sandhole on SSH port
    let ssh_listener = TcpListener::bind((config.listen_address, config.ssh_port.into()))
        .await
        .with_context(|| "Error listening to SSH port")?;
    info!("Listening for SSH connections on port {}.", config.ssh_port);
    info!("Sandhole is now running.");
    // Add OS signal handlers for termination.
    let signal_handler = wait_for_signal();
    pin!(signal_handler);
    loop {
        tokio::select! {
            conn = ssh_listener.accept() => {
                let (stream, address) = match conn {
                    Ok((stream, address)) => (stream, address),
                    Err(err) => {
                        error!("Unable to accept SSH connection: {}", err);
                        break;
                    },
                };
                let ip = address.ip();
                if !ip_filter.is_allowed(ip) {
                    info!("Rejecting SSH connection for {}: not allowed", ip);
                    continue;
                }
                if let Err(err) = stream.set_nodelay(true) {
                    warn!("Error setting nodelay for {}: {}", address, err);
                }
                handle_ssh_connection(HandleSshConnectionConfig {
                    stream,
                    address,
                    config: Arc::clone(&ssh_config),
                    server: &mut sandhole,
                });
            }
            _ = &mut signal_handler => {
                break;
            }
            _ = &mut join_handle_http.0 => {
                break;
            }
            _ = &mut join_handle_https.0 => {
                break;
            }
        }
    }
    info!("Sandhole is shutting down.");
    Ok(())
}

struct HandleHttpsConnectionConfig {
    stream: TcpStream,
    address: SocketAddr,
    connect_ssh_on_https_port: bool,
    proxy_data: TunnelingProxyData,
    ssh_config: Arc<Config>,
    sandhole: Arc<SandholeServer>,
    certificates: Arc<CertificateResolver>,
    http2_server_config: Arc<ServerConfig>,
    http11_server_config: Arc<ServerConfig>,
}

fn handle_https_connection(
    HandleHttpsConnectionConfig {
        mut stream,
        address,
        connect_ssh_on_https_port,
        proxy_data,
        ssh_config,
        mut sandhole,
        certificates,
        http2_server_config,
        http11_server_config,
    }: HandleHttpsConnectionConfig,
) {
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        let Ok(n) = stream.peek(&mut buf).await else {
            return;
        };
        if connect_ssh_on_https_port && buf[..n].starts_with(b"SSH-2.0-") {
            // Handle as an SSH connection instead of HTTPS.
            handle_ssh_connection(HandleSshConnectionConfig {
                stream,
                address,
                config: Arc::clone(&ssh_config),
                server: &mut sandhole,
            });
            return;
        }
        let Some(TlsPeekData { sni, alpn }) = peek_sni_and_alpn(&buf[..n]) else {
            return;
        };
        if alpn == [ACME_TLS_ALPN_NAME] {
            if let Some(challenge_config) = certificates.challenge_rustls_config() {
                let mut tls = TlsAcceptor::from(challenge_config)
                    .accept(stream)
                    .await
                    .unwrap();
                tls.shutdown().await.unwrap();
            } else {
                warn!("Unable to get ACME challenge TLS config");
            }
            return;
        }
        if let Some(tunnel_handler) = sandhole.sni.get(&sni) {
            let Ok(mut channel) = tunnel_handler
                .tunneling_channel(address.ip(), address.port())
                .await
            else {
                let io = TokioIo::new(stream);
                let service = service_fn(async move |_: Request<Incoming>| {
                    Ok::<_, Infallible>((StatusCode::NOT_FOUND, "").into_response())
                });
                let server = auto::Builder::new(TokioExecutor::new());
                let _ = server.serve_connection(io, service).await;
                return;
            };
            sandhole.telemetry.add_sni_connection(sni);
            match sandhole.tcp_connection_timeout {
                Some(duration) => {
                    let _ = timeout(duration, async {
                        let _ = copy_bidirectional_with_sizes(
                            &mut stream,
                            &mut channel,
                            sandhole.buffer_size,
                            sandhole.buffer_size,
                        )
                        .await;
                    })
                    .await;
                }
                None => {
                    let _ = copy_bidirectional_with_sizes(
                        &mut stream,
                        &mut channel,
                        sandhole.buffer_size,
                        sandhole.buffer_size,
                    )
                    .await;
                }
            }
            return;
        };
        let tunnel_handler = sandhole.http.get(&sni);
        let is_http2 = match tunnel_handler.as_ref() {
            Some(conn) => conn
                .http_data()
                .await
                .map(|data| data.http2)
                .unwrap_or_default(),
            None => false,
        };
        let server_config = if is_http2 {
            http2_server_config
        } else {
            http11_server_config
        };
        match TlsAcceptor::from(server_config).accept(stream).await {
            Ok(stream) => {
                // Create a Hyper service and serve over the accepted TLS connection.
                let io = TokioIo::new(stream);
                let service = service_fn(move |req: Request<Incoming>| {
                    proxy_handler(req, address, None, Arc::clone(&proxy_data))
                });
                let server = auto::Builder::new(TokioExecutor::new());
                let conn = server.serve_connection_with_upgrades(io, service);
                match sandhole.tcp_connection_timeout {
                    Some(duration) => {
                        let _ = timeout(duration, conn).await;
                    }
                    None => {
                        let _ = conn.await;
                    }
                }
            }
            Err(err) => {
                warn!(
                    "Error establishing TLS connection with {}: {}",
                    address, err
                );
            }
        }
    });
}

struct HandleSshConnectionConfig<'a> {
    stream: TcpStream,
    address: SocketAddr,
    config: Arc<Config>,
    server: &'a mut Arc<SandholeServer>,
}

fn handle_ssh_connection(
    HandleSshConnectionConfig {
        stream,
        address,
        config,
        server,
    }: HandleSshConnectionConfig,
) {
    let cancellation_token = CancellationToken::new();
    // Create a new SSH handler.
    let handler = server.new_client(address, cancellation_token.clone());
    tokio::spawn(async move {
        let mut session = match russh::server::run_stream(config, stream, handler).await {
            Ok(session) => session,
            Err(err) => {
                warn!("Connection setup failed: {}", err);
                return;
            }
        };
        tokio::select! {
            result = &mut session => {
                if let Err(err) = result {
                    warn!("Connection with {} closed with error: {}", address, err);
                }
            }
            _ = cancellation_token.cancelled() => {
                info!("Disconnecting client {}...", address);
                let _ = session.handle().disconnect(russh::Disconnect::ByApplication, "".into(), "English".into()).await;
            },
        }
    });
}

#[cfg(unix)]
async fn wait_for_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut signal_terminate = signal(SignalKind::terminate()).unwrap();
    let mut signal_interrupt = signal(SignalKind::interrupt()).unwrap();

    tokio::select! {
        _ = signal_terminate.recv() => debug!("Received SIGTERM."),
        _ = signal_interrupt.recv() => debug!("Received SIGINT."),
    };
}

#[cfg(windows)]
async fn wait_for_signal() {
    use tokio::signal::windows;

    let mut signal_c = windows::ctrl_c().unwrap();
    let mut signal_break = windows::ctrl_break().unwrap();
    let mut signal_close = windows::ctrl_close().unwrap();
    let mut signal_shutdown = windows::ctrl_shutdown().unwrap();

    tokio::select! {
        _ = signal_c.recv() => debug!("Received CTRL_C."),
        _ = signal_break.recv() => debug!("Received CTRL_BREAK."),
        _ = signal_close.recv() => debug!("Received CTRL_CLOSE."),
        _ = signal_shutdown.recv() => debug!("Received CTRL_SHUTDOWN."),
    };
}
