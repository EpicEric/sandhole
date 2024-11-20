use std::sync::{Arc, RwLock};

use anyhow::Context;
use hyper::{body::Incoming, server::conn::http1, service::service_fn, Request};
use hyper_util::rt::TokioIo;
use rand::rngs::OsRng;
use russh::server::Config;
use russh_keys::decode_secret_key;
use rustls::ServerConfig;
use rustls_acme::is_tls_alpn_challenge;
use tokio::{fs, io::AsyncWriteExt, net::TcpListener};
use tokio_rustls::LazyConfigAcceptor;

use crate::{
    acme::AcmeResolver,
    addressing::{AddressDelegator, DnsResolver},
    certificates::{AlpnChallengeResolver, CertificateResolver, DummyAlpnChallengeResolver},
    config::ApplicationConfig,
    connections::{ConnectionMap, DummyConnectionMapReactor},
    error::ServerError,
    fingerprints::FingerprintsValidator,
    http::{proxy_handler, Protocol},
    ssh::{Server, SshTunnelHandler},
};

mod acme;
mod addressing;
mod certificates;
pub mod config;
mod connections;
mod directory;
mod error;
mod fingerprints;
mod http;
mod ssh;
mod tcp;

#[derive(Clone)]
pub(crate) struct SandholeServer {
    pub(crate) http: Arc<ConnectionMap<String, Arc<SshTunnelHandler>, Arc<CertificateResolver>>>,
    pub(crate) ssh: Arc<ConnectionMap<String, Arc<SshTunnelHandler>, DummyConnectionMapReactor>>,
    pub(crate) tcp: Arc<ConnectionMap<u16, Arc<SshTunnelHandler>, DummyConnectionMapReactor>>,
    pub(crate) fingerprints_validator: Arc<FingerprintsValidator>,
    pub(crate) address_delegator: Arc<AddressDelegator<DnsResolver>>,
    pub(crate) http_port: u16,
    pub(crate) https_port: u16,
    pub(crate) ssh_port: u16,
}

pub async fn entrypoint(config: ApplicationConfig) -> anyhow::Result<()> {
    let key = match fs::read_to_string(config.private_key_file.as_path()).await {
        Ok(key) => decode_secret_key(&key, None).with_context(|| "Error decoding secret key")?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            println!("Key file not found. Creating...");
            let key = ssh_key::PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519)
                .with_context(|| "Error creating secret key")?;
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
            let key_string = key.to_openssh(ssh_key::LineEnding::LF)?;
            let key = decode_secret_key(&key_string, None)
                .with_context(|| "Error decoding secret key")?;
            fs::write(config.private_key_file.as_path(), key_string).await?;
            key
        }
        Err(err) => return Err(err).with_context(|| "Error reading secret key"),
    };

    let fingerprints = Arc::new(
        FingerprintsValidator::watch(config.public_keys_directory.clone())
            .await
            .with_context(|| "Error setting up public keys watcher")?,
    );
    let alpn_resolver: Box<dyn AlpnChallengeResolver> = match config.acme_contact_email {
        Some(contact) => {
            if config.https_port == 443 {
                Box::new(AcmeResolver::new(
                    config.acme_cache_directory,
                    contact,
                    config.acme_use_staging,
                ))
            } else {
                eprintln!(
                    "WARNING: ACME challenges are only supported on HTTPS port 443 (currently {}). Disabling.",
                    config.https_port
                );
                Box::new(DummyAlpnChallengeResolver)
            }
        }
        None => Box::new(DummyAlpnChallengeResolver),
    };
    let certificates = Arc::new(
        CertificateResolver::watch(
            config.certificates_directory.clone(),
            Arc::new(RwLock::new(alpn_resolver)),
        )
        .await
        .with_context(|| "Error setting up certificates watcher")?,
    );
    let http_connections = Arc::new(ConnectionMap::new(Some(Arc::clone(&certificates))));
    let ssh_connections = Arc::new(ConnectionMap::new(None));
    let tcp_connections = Arc::new(ConnectionMap::new(None));
    let addressing = Arc::new(AddressDelegator::new(
        DnsResolver::new(),
        config.txt_record_prefix.trim_matches('.').to_string(),
        config.domain.trim_matches('.').to_string(),
        config.bind_hostnames,
        !config.allow_provided_subdomains,
        !config.allow_requested_ports,
        config.random_subdomain_seed,
    ));
    let domain_redirect = Arc::new((config.domain, config.domain_redirect));

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

    let https_listener = TcpListener::bind((config.listen_address.clone(), config.https_port))
        .await
        .with_context(|| "Error listening to HTTP port and address")?;
    let certificates_clone = Arc::clone(&certificates);
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(certificates),
    );
    let http_map = Arc::clone(&http_connections);
    tokio::spawn(async move {
        loop {
            let http_map = Arc::clone(&http_map);
            let domain_redirect = Arc::clone(&domain_redirect);
            let server_config = Arc::clone(&server_config);
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
                                    eprintln!("Error establishing TLS connection: {:?}", err);
                                }
                            }
                        });
                    }
                }
                Err(err) => {
                    eprintln!("Failed to establish TLS handshake: {:?}", err);
                    continue;
                }
            }
        }
    });

    let ssh_config = Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(3_600)),
        auth_rejection_time: std::time::Duration::from_secs(1),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![key],
        ..Default::default()
    };
    let ssh_config = Arc::new(ssh_config);
    let mut sandhole = Arc::new(SandholeServer {
        http: http_connections,
        ssh: ssh_connections,
        tcp: tcp_connections,
        fingerprints_validator: fingerprints,
        address_delegator: addressing,
        http_port: config.http_port,
        https_port: config.https_port,
        ssh_port: config.ssh_port,
    });
    let ssh_listener = TcpListener::bind((config.listen_address.clone(), config.ssh_port))
        .await
        .with_context(|| "Error listening to SSH port and address")?;
    println!("sandhole is now running.");
    loop {
        let (stream, address) = match ssh_listener.accept().await {
            Ok((stream, address)) => (stream, address),
            Err(_) => break,
        };
        debug_assert_eq!(stream.peer_addr().ok(), Some(address));
        let config = Arc::clone(&ssh_config);
        let handler = sandhole.new_client(Some(address));
        tokio::spawn(async move {
            let session = match russh::server::run_stream(config, stream, handler).await {
                Ok(session) => session,
                Err(_) => {
                    // Connection setup failed
                    return;
                }
            };
            match session.await {
                Ok(_) => (),
                Err(_) => {
                    // Connection closed with error
                    return;
                }
            }
        });
    }
    Ok(())
}
