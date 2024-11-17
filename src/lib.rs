use std::sync::Arc;

use anyhow::Context;
use certificates::CertificateResolver;
use config::CONFIG;
use http::proxy_handler;
use hyper::{body::Incoming, server::conn::http1, service::service_fn, Request};
use hyper_util::rt::TokioIo;
use russh::server::{Config, Server as _};
use russh_keys::decode_secret_key;
use rustls::ServerConfig;
use tokio::{fs, net::TcpListener, sync::mpsc};
use tokio_rustls::TlsAcceptor;

use crate::{
    addressing::{AddressDelegator, DnsResolver},
    fingerprints::FingerprintsValidator,
    http::ConnectionMap,
};

mod addressing;
mod certificates;
pub mod config;
mod error;
mod fingerprints;
mod http;
mod ssh;

#[derive(Clone)]
pub(crate) struct HttpHandler {
    pub(crate) handle: russh::server::Handle,
    pub(crate) address: String,
    pub(crate) port: u16,
    pub(crate) tx: mpsc::Sender<Vec<u8>>,
}

#[derive(Clone)]
pub(crate) struct Server {
    pub(crate) http: Arc<ConnectionMap<HttpHandler>>,
    pub(crate) fingerprints_validator: Arc<FingerprintsValidator>,
    pub(crate) address_delegator: Arc<AddressDelegator<DnsResolver>>,
    pub(crate) http_port: u16,
    pub(crate) https_port: u16,
}

pub async fn entrypoint() -> anyhow::Result<()> {
    let config = CONFIG.get().unwrap();
    let key = fs::read_to_string(config.private_key_file.as_path())
        .await
        .with_context(|| "Error reading secret key")?;
    let key = decode_secret_key(&key, config.private_key_password.as_deref())
        .with_context(|| "Error decoding secret key")?;

    let http_connections = Arc::new(ConnectionMap::new());
    let fingerprints = Arc::new(
        FingerprintsValidator::watch(config.public_keys_directory.clone())
            .await
            .with_context(|| "Error setting up public keys watcher")?,
    );
    let certificates = Arc::new(
        CertificateResolver::watch(config.certificates_directory.clone())
            .await
            .with_context(|| "Error setting up certificates watcher")?,
    );

    let http_listener = TcpListener::bind((config.listen_address.clone(), config.http_port))
        .await
        .with_context(|| "Error listening to HTTP port and address")?;
    let http_map = Arc::clone(&http_connections);
    tokio::spawn(async move {
        loop {
            let map_clone = http_map.clone();
            let (stream, address) = http_listener.accept().await.unwrap();
            let service = service_fn(move |req: Request<Incoming>| {
                proxy_handler(req, address, map_clone.clone())
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
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(certificates);
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let http_map = Arc::clone(&http_connections);
    tokio::spawn(async move {
        loop {
            let map_clone = http_map.clone();
            let acceptor = acceptor.clone();
            let (stream, address) = https_listener.accept().await.unwrap();
            let service = service_fn(move |req: Request<Incoming>| {
                proxy_handler(req, address, map_clone.clone())
            });
            let io = match acceptor.accept(stream).await {
                Ok(stream) => TokioIo::new(stream),
                Err(err) => {
                    eprintln!("Failed to establish TLS handshake: {:?}", err);
                    continue;
                }
            };
            tokio::spawn(async move {
                let conn = http1::Builder::new()
                    .serve_connection(io, service)
                    .with_upgrades();
                let _ = conn.await;
            });
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
    let mut sh = Server {
        http: http_connections,
        fingerprints_validator: fingerprints,
        http_port: config.http_port,
        https_port: config.https_port,
        address_delegator: Arc::new(AddressDelegator::new(
            DnsResolver::new(),
            config.txt_record_prefix.trim_matches('.').to_string(),
            config.domain.trim_matches('.').to_string(),
            config.bind_any_host,
            config.force_random_subdomains,
            config.random_subdomain_seed,
        )),
    };
    sh.run_on_address(ssh_config, (config.listen_address.clone(), config.ssh_port))
        .await
        .with_context(|| "Error listening to SSH port and address")?;
    Ok(())
}
