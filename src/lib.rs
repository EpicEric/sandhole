use std::sync::{Arc, RwLock};

use acme::AcmeResolver;
use anyhow::Context;
use certificates::{AlpnChallengeResolver, CertificateResolver, DummyAlpnChallengeResolver};
use config::ApplicationConfig;
use http::proxy_handler;
use hyper::{body::Incoming, server::conn::http1, service::service_fn, Request};
use hyper_util::rt::TokioIo;
use russh::server::{Config, Server as _};
use russh_keys::decode_secret_key;
use rustls::ServerConfig;
use rustls_acme::is_tls_alpn_challenge;
use ssh::SshTunnelHandler;
use tokio::{fs, io::AsyncWriteExt, net::TcpListener};
use tokio_rustls::LazyConfigAcceptor;

use crate::{
    addressing::{AddressDelegator, DnsResolver},
    connections::ConnectionMap,
    fingerprints::FingerprintsValidator,
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

#[derive(Clone)]
pub(crate) struct SandholeServer {
    pub(crate) http: Arc<ConnectionMap<Arc<SshTunnelHandler>, Arc<CertificateResolver>>>,
    pub(crate) fingerprints_validator: Arc<FingerprintsValidator>,
    pub(crate) address_delegator: Arc<AddressDelegator<DnsResolver>>,
    pub(crate) http_port: u16,
    pub(crate) https_port: u16,
}

pub async fn entrypoint(config: ApplicationConfig) -> anyhow::Result<()> {
    let key = match fs::read_to_string(config.private_key_file.as_path()).await {
        Ok(key) => decode_secret_key(&key, config.private_key_password.as_deref())
            .with_context(|| "Error decoding secret key")?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(err).with_context(|| "Error reading secret key");
            // TO-DO: Allow generating key file on startup
            // println!("Key file not found. Creating...");
            // let key = russh_keys::key::KeyPair::generate_ed25519();
            // fs::create_dir_all(
            //     config
            //         .private_key_file
            //         .as_path()
            //         .parent()
            //         .ok_or(ServerError::InvalidFilePath)
            //         .with_context(|| "Error parsing secret key path")?,
            // )
            // .await
            // .with_context(|| "Error creating secret key directory")?;
            // fs::write(
            //     config
            //         .private_key_file
            //         .as_path(),
            //         ...
            // )
        }
        Err(err) => return Err(err).with_context(|| "Error reading secret key"),
    };

    let fingerprints = Arc::new(
        FingerprintsValidator::watch(config.public_keys_directory.clone())
            .await
            .with_context(|| "Error setting up public keys watcher")?,
    );
    let alpn_resolver: Box<dyn AlpnChallengeResolver> = match config.acme_contact_email {
        Some(contact) => Box::new(AcmeResolver::new(
            config.acme_cache_directory,
            contact,
            config.acme_use_production,
        )),
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
    let addressing = Arc::new(AddressDelegator::new(
        DnsResolver::new(),
        config.txt_record_prefix.trim_matches('.').to_string(),
        config.domain.trim_matches('.').to_string(),
        config.bind_hostnames,
        config.force_random_subdomains,
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
                        Some(config.https_port)
                    } else {
                        None
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
                    None,
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
                            let io =
                                TokioIo::new(handshake.into_stream(server_config).await.unwrap());
                            let conn = http1::Builder::new()
                                .serve_connection(io, service)
                                .with_upgrades();
                            let _ = conn.await;
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
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_secs(1),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![key],
        ..Default::default()
    };
    let ssh_config = Arc::new(ssh_config);
    let mut sandhole = SandholeServer {
        http: http_connections,
        fingerprints_validator: fingerprints,
        address_delegator: addressing,
        http_port: config.http_port,
        https_port: config.https_port,
    };
    println!("sandhole is now running.");
    sandhole
        .run_on_address(ssh_config, (config.listen_address.clone(), config.ssh_port))
        .await
        .with_context(|| "Error listening to SSH port and address")?;
    Ok(())
}
