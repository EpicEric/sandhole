use std::sync::Arc;

use anyhow::Context;
use config::CONFIG;
use dashmap::DashSet;
use http::proxy_handler;
use hyper::{body::Incoming, server::conn::http1, service::service_fn, Request};
use hyper_util::rt::TokioIo;
use russh::server::{Config, Server as _};
use russh_keys::decode_secret_key;
use tokio::{fs, net::TcpListener};

use crate::{fingerprints::watch_public_keys_directory, http::ConnectionMap};

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
}

#[derive(Clone)]
pub(crate) struct Server {
    pub(crate) http: Arc<ConnectionMap>,
    pub(crate) allowed_key_fingerprints: Arc<DashSet<String>>,
}

pub async fn entrypoint() -> anyhow::Result<()> {
    let config = CONFIG.get().unwrap();
    let key = fs::read_to_string(config.private_key_file.clone())
        .await
        .with_context(|| "Error reading secret key")?;
    let key = decode_secret_key(&key, config.private_key_password.as_deref())
        .with_context(|| "Error decoding secret key")?;
    let ssh_config = Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_secs(1),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![key],
        ..Default::default()
    };
    let ssh_config = Arc::new(ssh_config);
    let mut sh = Server {
        http: Arc::new(ConnectionMap::new()),
        allowed_key_fingerprints: Arc::new(DashSet::new()),
    };

    let http_listener = TcpListener::bind((config.listen_address.clone(), config.http_port))
        .await
        .with_context(|| "Error listening to HTTP port and address")?;
    let http_map = Arc::clone(&sh.http);
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
    let http_map = Arc::clone(&sh.http);
    tokio::spawn(async move {
        loop {
            let map_clone = http_map.clone();
            let (stream, address) = https_listener.accept().await.unwrap();
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

    watch_public_keys_directory(
        config.public_keys_directory.clone(),
        Arc::clone(&sh.allowed_key_fingerprints),
    )?;

    sh.run_on_address(ssh_config, (config.listen_address.clone(), config.ssh_port))
        .await
        .with_context(|| "Error listening to SSH port and address")?;
    Ok(())
}
