//!
#![doc = include_str!("../README.md")]
//!

use std::{
    collections::BTreeMap,
    marker::PhantomData,
    net::{IpAddr, SocketAddr},
    sync::{Arc, RwLock},
    time::Duration,
};

use anyhow::Context;
use connections::ConnectionMapReactor;
use http::{DomainRedirect, ProxyData};
use hyper::{body::Incoming, server::conn::http1, service::service_fn, Request};
use hyper_util::rt::TokioIo;
use log::{info, warn};
use login::ApiLogin;
use quota::{DummyQuotaHandler, QuotaHandler, QuotaMap};
use rand::rngs::OsRng;
use russh::server::Config;
use russh_keys::decode_secret_key;
use rustls::ServerConfig;
use rustls_acme::is_tls_alpn_challenge;
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, Networks, RefreshKind, System};
use tcp::TcpHandler;
use tcp_alias::TcpAlias;
use telemetry::Telemetry;
use tokio::{
    fs,
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::sleep,
};
use tokio_rustls::LazyConfigAcceptor;

use crate::{
    acme::AcmeResolver,
    addressing::{AddressDelegator, DnsResolver},
    certificates::{AlpnChallengeResolver, CertificateResolver, DummyAlpnChallengeResolver},
    connections::ConnectionMap,
    error::ServerError,
    fingerprints::FingerprintsValidator,
    http::{proxy_handler, Protocol},
    ssh::{Server, SshTunnelHandler},
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
mod login;
mod quota;
mod ssh;
mod tcp;
mod tcp_alias;
mod telemetry;

type DataTable<K, V> = Arc<RwLock<BTreeMap<K, V>>>;

struct HttpReactor {
    certificates: Arc<CertificateResolver>,
    telemetry: Arc<Telemetry>,
}

impl ConnectionMapReactor<String> for HttpReactor {
    fn call(&self, identifiers: Vec<String>) {
        self.certificates.call(identifiers.clone());
        self.telemetry.call(identifiers);
    }
}

#[derive(Default, Clone)]
struct SystemData {
    used_memory: u64,
    total_memory: u64,
    network_tx: u64,
    network_rx: u64,
    cpu_usage: f32,
}

pub(crate) struct SandholeServer {
    pub(crate) http: Arc<ConnectionMap<String, Arc<SshTunnelHandler>, HttpReactor>>,
    pub(crate) ssh: Arc<ConnectionMap<String, Arc<SshTunnelHandler>>>,
    pub(crate) tcp: Arc<ConnectionMap<TcpAlias, Arc<SshTunnelHandler>, Arc<TcpHandler>>>,
    pub(crate) http_data: DataTable<String, (BTreeMap<SocketAddr, String>, f64)>,
    pub(crate) ssh_data: DataTable<String, BTreeMap<SocketAddr, String>>,
    pub(crate) tcp_data: DataTable<TcpAlias, BTreeMap<SocketAddr, String>>,
    pub(crate) system_data: Arc<RwLock<SystemData>>,
    pub(crate) fingerprints_validator: FingerprintsValidator,
    pub(crate) api_login: Option<ApiLogin>,
    pub(crate) address_delegator: Arc<AddressDelegator<DnsResolver>>,
    pub(crate) tcp_handler: Arc<TcpHandler>,
    pub(crate) domain: String,
    pub(crate) http_port: u16,
    pub(crate) https_port: u16,
    pub(crate) ssh_port: u16,
    pub(crate) force_random_ports: bool,
    pub(crate) authentication_request_timeout: Duration,
    pub(crate) idle_connection_timeout: Duration,
}

#[doc(hidden)]
// Main entrypoint of the application.
pub async fn entrypoint(config: ApplicationConfig) -> anyhow::Result<()> {
    // Initialize crypto and credentials
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Unable to install CryptoProvider");
    let key = match fs::read_to_string(config.private_key_file.as_path()).await {
        Ok(key) => decode_secret_key(&key, None).with_context(|| "Error decoding secret key")?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            info!("Key file not found. Creating...");
            let key = ssh_key::PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519)
                .with_context(|| "Error creating secret key")?;
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
            let key_string = key.to_openssh(ssh_key::LineEnding::LF)?;
            let key = decode_secret_key(&key_string, None)
                .with_context(|| "Error decoding secret key")?;
            fs::write(config.private_key_file.as_path(), key_string)
                .await
                .with_context(|| "Error saving secret key to filesystem")?;
            key
        }
        Err(err) => return Err(err).with_context(|| "Error reading secret key"),
    };
    let listen_address: IpAddr = config
        .listen_address
        .parse()
        .with_context(|| "Couldn't parse listen address")?;

    // Initialize modules
    if !config.disable_directory_creation {
        fs::create_dir_all(config.user_keys_directory.as_path())
            .await
            .with_context(|| "Error creating user keys directory")?;
        fs::create_dir_all(config.admin_keys_directory.as_path())
            .await
            .with_context(|| "Error creating admin keys directory")?;
    }
    let fingerprints = FingerprintsValidator::watch(
        config.user_keys_directory.clone(),
        config.admin_keys_directory.clone(),
    )
    .await
    .with_context(|| "Error setting up public keys watcher")?;
    let api_login = config
        .password_authentication_url
        .as_ref()
        .map(|url| ApiLogin::new(url))
        .transpose()
        .with_context(|| "Error intializing login API")?;
    let alpn_resolver: Box<dyn AlpnChallengeResolver> = match config.acme_contact_email {
        Some(contact) if config.https_port == 443 => Box::new(AcmeResolver::new(
            config.acme_cache_directory,
            contact,
            config.acme_use_staging,
        )),
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
    let certificates = Arc::new(
        CertificateResolver::watch(
            config.certificates_directory.clone(),
            RwLock::new(alpn_resolver),
        )
        .await
        .with_context(|| "Error setting up certificates watcher")?,
    );
    let telemetry = Arc::new(Telemetry::new());
    let quota_handler: Arc<Box<dyn QuotaHandler + Send + Sync>> = match config.quota_per_user {
        Some(max_quota) => Arc::new(Box::new(Arc::new(QuotaMap::new(max_quota)))),
        None => Arc::new(Box::new(DummyQuotaHandler)),
    };
    let http_connections = Arc::new(ConnectionMap::new(
        config.load_balancing,
        Arc::clone(&quota_handler),
        Some(HttpReactor {
            certificates: Arc::clone(&certificates),
            telemetry: Arc::clone(&telemetry),
        }),
    ));
    let ssh_connections = Arc::new(ConnectionMap::new(
        config.load_balancing,
        Arc::clone(&quota_handler),
        None,
    ));
    let tcp_connections = Arc::new(ConnectionMap::new(
        config.load_balancing,
        Arc::clone(&quota_handler),
        None,
    ));
    let tcp_handler: Arc<TcpHandler> = Arc::new(TcpHandler::new(
        config.listen_address,
        Arc::clone(&tcp_connections),
        config.tcp_connection_timeout,
        config.disable_tcp_logs,
    ));
    tcp_connections.update_reactor(Some(Arc::clone(&tcp_handler)));
    let addressing = Arc::new(AddressDelegator::new(
        DnsResolver::new(),
        config.txt_record_prefix.trim_matches('.').to_string(),
        config.domain.trim_matches('.').to_string(),
        config.bind_hostnames,
        !config.allow_requested_subdomains,
        config.random_subdomain_seed,
    ));
    let domain_redirect = Arc::new(DomainRedirect {
        from: config.domain.clone(),
        to: config.domain_redirect,
    });

    // Telemetry tasks
    let http_data = Arc::new(RwLock::default());
    let data_clone = Arc::clone(&http_data);
    let connections_clone = Arc::clone(&http_connections);
    let telemetry_clone = Arc::clone(&telemetry);
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
    let ssh_data = Arc::new(RwLock::default());
    let data_clone = Arc::clone(&ssh_data);
    let connections_clone = Arc::clone(&ssh_connections);
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_millis(3_000)).await;
            let data = connections_clone.data();
            *data_clone.write().unwrap() = data;
        }
    });
    let tcp_data = Arc::new(RwLock::default());
    let data_clone = Arc::clone(&tcp_data);
    let connections_clone = Arc::clone(&tcp_connections);
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_millis(3_000)).await;
            let data = connections_clone.data();
            *data_clone.write().unwrap() = data;
        }
    });
    let system_data = Arc::new(RwLock::default());
    let data_clone = Arc::clone(&system_data);
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
        keys: vec![key],
        ..Default::default()
    });
    let mut sandhole = Arc::new(SandholeServer {
        http: Arc::clone(&http_connections),
        ssh: ssh_connections,
        tcp: tcp_connections,
        http_data,
        ssh_data,
        tcp_data,
        system_data,
        fingerprints_validator: fingerprints,
        api_login,
        address_delegator: addressing,
        tcp_handler,
        domain: config.domain,
        http_port: config.http_port,
        https_port: config.https_port,
        ssh_port: config.ssh_port,
        force_random_ports: !config.allow_requested_ports,
        authentication_request_timeout: config.authentication_request_timeout,
        idle_connection_timeout: config.idle_connection_timeout,
    });

    // HTTP handler
    let http_listener = TcpListener::bind((listen_address, config.http_port))
        .await
        .with_context(|| "Error listening to HTTP port")?;
    info!(
        "Listening for HTTP connections on port {}",
        config.http_port
    );
    let http_proxy_data = Arc::new(ProxyData {
        conn_manager: Arc::clone(&http_connections),
        telemetry: Arc::clone(&telemetry),
        domain_redirect: Arc::clone(&domain_redirect),
        protocol: if config.force_https {
            Protocol::TlsRedirect {
                from: config.http_port,
                to: config.https_port,
            }
        } else {
            Protocol::Http {
                port: config.http_port,
            }
        },
        http_request_timeout: config.http_request_timeout,
        websocket_timeout: config.tcp_connection_timeout,
        disable_http_logs: config.disable_http_logs,
        _phantom_data: PhantomData,
    });
    tokio::spawn(async move {
        loop {
            let proxy_data = Arc::clone(&http_proxy_data);
            let (stream, address) = http_listener.accept().await.unwrap();
            let service = service_fn(move |req: Request<Incoming>| {
                proxy_handler(req, address, Arc::clone(&proxy_data))
            });
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let conn = http1::Builder::new()
                    .serve_connection(io, service)
                    .with_upgrades();
                let _ = conn.await;
            });
        }
    });

    // HTTPS handler (with optional SSH handling)
    let https_listener = TcpListener::bind((listen_address, config.https_port))
        .await
        .with_context(|| "Error listening to HTTPS port")?;
    info!(
        "Listening for HTTPS connections on port {}",
        config.https_port
    );
    let certificates_clone = Arc::clone(&certificates);
    let tls_server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(certificates),
    );
    let https_proxy_data = Arc::new(ProxyData {
        conn_manager: http_connections,
        telemetry: Arc::clone(&telemetry),
        domain_redirect: Arc::clone(&domain_redirect),
        protocol: Protocol::Https {
            port: config.https_port,
        },
        http_request_timeout: config.http_request_timeout,
        websocket_timeout: config.tcp_connection_timeout,
        disable_http_logs: config.disable_http_logs,
        _phantom_data: PhantomData,
    });
    let mut sandhole_clone = Arc::clone(&sandhole);
    let ssh_config_clone = Arc::clone(&ssh_config);
    tokio::spawn(async move {
        loop {
            let (stream, address) = https_listener.accept().await.unwrap();
            if config.connect_ssh_on_https_port {
                let mut buf = [0u8; 8];
                if let Ok(n) = stream.peek(&mut buf).await {
                    if buf[..n].starts_with(b"SSH-2.0-") {
                        handle_ssh_connection(
                            stream,
                            address,
                            &ssh_config_clone,
                            &mut sandhole_clone,
                        )
                        .await;
                        continue;
                    }
                }
            }
            let proxy_data = Arc::clone(&https_proxy_data);
            let server_config = Arc::clone(&tls_server_config);
            let service = service_fn(move |req: Request<Incoming>| {
                proxy_handler(req, address, Arc::clone(&proxy_data))
            });
            match LazyConfigAcceptor::new(Default::default(), stream).await {
                Ok(handshake) => {
                    if is_tls_alpn_challenge(&handshake.client_hello()) {
                        if let Some(challenge_config) = certificates_clone.challenge_rustls_config()
                        {
                            tokio::spawn(async move {
                                let mut tls =
                                    handshake.into_stream(challenge_config).await.unwrap();
                                tls.shutdown().await.unwrap();
                            });
                        }
                    } else {
                        tokio::spawn(async move {
                            match handshake.into_stream(server_config).await {
                                Ok(stream) => {
                                    let conn = http1::Builder::new()
                                        .serve_connection(TokioIo::new(stream), service)
                                        .with_upgrades();
                                    let _ = conn.await;
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
                }
                Err(err) => {
                    warn!(
                        "Failed to establish TLS handshake with {}: {}",
                        address, err
                    );
                    continue;
                }
            }
        }
    });

    // Start Sandhole on SSH port
    let ssh_listener = TcpListener::bind((listen_address, config.ssh_port))
        .await
        .with_context(|| "Error listening to SSH port")?;
    info!("Listening for SSH connections on port {}", config.ssh_port);
    info!("sandhole is now running.");
    loop {
        let (stream, address) = match ssh_listener.accept().await {
            Ok((stream, address)) => (stream, address),
            Err(_) => break,
        };
        handle_ssh_connection(stream, address, &ssh_config, &mut sandhole).await;
    }
    Ok(())
}

async fn handle_ssh_connection(
    stream: TcpStream,
    address: SocketAddr,
    config: &Arc<Config>,
    server: &mut Arc<SandholeServer>,
) {
    let config = Arc::clone(config);
    let (tx, mut rx) = oneshot::channel::<()>();
    let handler = server.new_client(Some(address), tx);
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
            Ok(_) = &mut rx => {
                let _ = session.handle().disconnect(russh::Disconnect::ByApplication, "".into(), "English".into()).await;
            },
        }
    });
}
