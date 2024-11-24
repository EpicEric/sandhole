use std::{
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Duration,
};

use anyhow::Context;
use http::DomainRedirect;
use hyper::{body::Incoming, server::conn::http1, service::service_fn, Request};
use hyper_util::rt::TokioIo;
use log::{info, warn};
use login::ApiLogin;
use rand::rngs::OsRng;
use russh::server::Config;
use russh_keys::decode_secret_key;
use rustls::ServerConfig;
use rustls_acme::is_tls_alpn_challenge;
use tcp::TcpHandler;
use tcp_alias::TcpAlias;
use tokio::{fs, io::AsyncWriteExt, net::TcpListener, sync::oneshot, time::sleep};
use tokio_rustls::LazyConfigAcceptor;

use crate::{
    acme::AcmeResolver,
    addressing::{AddressDelegator, DnsResolver},
    certificates::{AlpnChallengeResolver, CertificateResolver, DummyAlpnChallengeResolver},
    config::ApplicationConfig,
    connections::ConnectionMap,
    error::ServerError,
    fingerprints::FingerprintsValidator,
    http::{proxy_handler, Protocol},
    ssh::{Server, SshTunnelHandler},
};

mod acme;
mod addressing;
mod admin;
mod certificates;
pub mod config;
mod connections;
mod directory;
mod error;
mod fingerprints;
mod handler;
mod http;
mod login;
mod ssh;
mod tcp;
mod tcp_alias;

type DataTable<T> = RwLock<Vec<(T, Vec<SocketAddr>)>>;

#[derive(Clone)]
pub(crate) struct SandholeServer {
    pub(crate) http: Arc<ConnectionMap<String, Arc<SshTunnelHandler>, Arc<CertificateResolver>>>,
    pub(crate) ssh: Arc<ConnectionMap<String, Arc<SshTunnelHandler>>>,
    pub(crate) tcp: Arc<ConnectionMap<TcpAlias, Arc<SshTunnelHandler>, Arc<TcpHandler>>>,
    pub(crate) http_data: Arc<DataTable<String>>,
    pub(crate) ssh_data: Arc<DataTable<String>>,
    pub(crate) tcp_data: Arc<DataTable<TcpAlias>>,
    pub(crate) fingerprints_validator: Arc<FingerprintsValidator>,
    pub(crate) api_login: Arc<Option<ApiLogin>>,
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

    // Initialize modules
    if !config.disable_directory_creation {
        fs::create_dir_all(config.user_keys_directory.as_path())
            .await
            .with_context(|| "Error creating user keys directory")?;
        fs::create_dir_all(config.admin_keys_directory.as_path())
            .await
            .with_context(|| "Error creating admin keys directory")?;
    }
    let fingerprints = Arc::new(
        FingerprintsValidator::watch(
            config.user_keys_directory.clone(),
            config.admin_keys_directory.clone(),
        )
        .await
        .with_context(|| "Error setting up public keys watcher")?,
    );
    let api_login = Arc::new(config.password_authentication_url.map(ApiLogin::new));
    let alpn_resolver: Box<dyn AlpnChallengeResolver> = match config.acme_contact_email {
        Some(contact) => {
            if config.https_port == 443 {
                Box::new(AcmeResolver::new(
                    config.acme_cache_directory,
                    contact,
                    config.acme_use_staging,
                ))
            } else {
                warn!(
                    "ACME challenges are only supported on HTTPS port 443 (currently {}). Disabling.",
                    config.https_port
                );
                Box::new(DummyAlpnChallengeResolver)
            }
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
    let http_connections = Arc::new(ConnectionMap::new(Some(Arc::clone(&certificates))));
    let ssh_connections = Arc::new(ConnectionMap::new(None));
    let tcp_connections = Arc::new(ConnectionMap::new(None));
    let tcp_handler: Arc<TcpHandler> = Arc::new(TcpHandler::new(
        config.listen_address.clone(),
        Arc::clone(&tcp_connections),
    ));
    tcp_connections.update_reactor(Some(Arc::clone(&tcp_handler)));
    let addressing = Arc::new(AddressDelegator::new(
        DnsResolver::new(),
        config.txt_record_prefix.trim_matches('.').to_string(),
        config.domain.trim_matches('.').to_string(),
        config.bind_hostnames,
        !config.allow_provided_subdomains,
        config.random_subdomain_seed,
    ));
    let domain_redirect = Arc::new(DomainRedirect {
        from: config.domain.clone(),
        to: config.domain_redirect,
    });

    // HTTP handlers
    let http_listener = TcpListener::bind((config.listen_address.clone(), config.http_port))
        .await
        .with_context(|| "Error listening to HTTP port and address")?;
    let http_map = Arc::clone(&http_connections);
    let redirect = Arc::clone(&domain_redirect);
    tokio::spawn(async move {
        loop {
            let http_map = Arc::clone(&http_map);
            let domain_redirect = Arc::clone(&redirect);
            let (stream, address) = http_listener.accept().await.unwrap();
            let service = service_fn(move |req: Request<Incoming>| {
                proxy_handler(
                    req,
                    address,
                    Arc::clone(&http_map),
                    Arc::clone(&domain_redirect),
                    if config.force_https {
                        Protocol::TlsRedirect {
                            from: config.http_port,
                            to: config.https_port,
                        }
                    } else {
                        Protocol::Http {
                            port: config.http_port,
                        }
                    },
                    config.request_timeout,
                )
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

    // HTTPS handlers
    let https_listener = TcpListener::bind((config.listen_address.clone(), config.https_port))
        .await
        .with_context(|| "Error listening to HTTP port and address")?;
    let certificates_clone = Arc::clone(&certificates);
    let tls_server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(certificates),
    );
    let http_map = Arc::clone(&http_connections);
    tokio::spawn(async move {
        loop {
            let http_map = Arc::clone(&http_map);
            let domain_redirect = Arc::clone(&domain_redirect);
            let server_config = Arc::clone(&tls_server_config);
            let (stream, address) = https_listener.accept().await.unwrap();
            let service = service_fn(move |req: Request<Incoming>| {
                proxy_handler(
                    req,
                    address,
                    Arc::clone(&http_map),
                    Arc::clone(&domain_redirect),
                    Protocol::Https {
                        port: config.https_port,
                    },
                    config.request_timeout,
                )
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
                                    warn!("Error establishing TLS connection: {}", err);
                                }
                            }
                        });
                    }
                }
                Err(err) => {
                    warn!("Failed to establish TLS handshake: {}", err);
                    continue;
                }
            }
        }
    });

    // Telemetry
    let http_data = Arc::new(RwLock::new(vec![]));
    let data_clone = Arc::clone(&http_data);
    let connections_clone = Arc::clone(&http_connections);
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_millis(3_000)).await;
            let mut data = connections_clone.data();
            data.sort();
            data.iter_mut().for_each(|(_, v)| v.sort());
            *data_clone.write().unwrap() = data;
        }
    });
    let ssh_data = Arc::new(RwLock::new(vec![]));
    let data_clone = Arc::clone(&ssh_data);
    let connections_clone = Arc::clone(&ssh_connections);
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_millis(3_000)).await;
            let mut data = connections_clone.data();
            data.sort();
            data.iter_mut().for_each(|(_, v)| v.sort());
            *data_clone.write().unwrap() = data;
        }
    });
    let tcp_data = Arc::new(RwLock::new(vec![]));
    let data_clone = Arc::clone(&tcp_data);
    let connections_clone = Arc::clone(&tcp_connections);
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_millis(3_000)).await;
            let mut data = connections_clone.data();
            data.sort();
            data.iter_mut().for_each(|(_, v)| v.sort());
            *data_clone.write().unwrap() = data;
        }
    });

    // Start Sandhole
    let ssh_config = Arc::new(Config {
        inactivity_timeout: Some(Duration::from_secs(3_600)),
        auth_rejection_time: Duration::from_secs(2),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        keys: vec![key],
        ..Default::default()
    });
    let mut sandhole = Arc::new(SandholeServer {
        http: http_connections,
        ssh: ssh_connections,
        tcp: tcp_connections,
        http_data,
        ssh_data,
        tcp_data,
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
    let ssh_listener = TcpListener::bind((config.listen_address.clone(), config.ssh_port))
        .await
        .with_context(|| "Error listening to SSH port and address")?;
    info!("sandhole is now running.");
    loop {
        let (stream, address) = match ssh_listener.accept().await {
            Ok((stream, address)) => (stream, address),
            Err(_) => break,
        };
        debug_assert_eq!(stream.peer_addr().ok(), Some(address));
        let config = Arc::clone(&ssh_config);
        let (tx, rx) = oneshot::channel::<()>();
        let handler = sandhole.new_client(Some(address), tx);
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
                        warn!("Connection closed with error: {}", err);
                    }
                }
                _ = rx => {
                    let _ = session.handle().disconnect(russh::Disconnect::ByApplication, "".into(), "English".into()).await;
                },
            }
        });
    }
    Ok(())
}
