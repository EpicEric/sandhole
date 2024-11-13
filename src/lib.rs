use std::{net::SocketAddr, sync::Arc};

use anyhow::Context;
use config::CONFIG;
use dashmap::{DashMap, DashSet};
use http::proxy_handler;
use hyper::{body::Incoming, server::conn::http1, service::service_fn, Request};
use hyper_util::rt::TokioIo;
use russh::server::{Config, Server as _};
use russh_keys::decode_secret_key;
use tokio::{fs, net::TcpListener};

use crate::files::watch_public_keys_directory;

pub mod config;
mod error;
mod files;
mod http;
mod ssh;

#[derive(Clone)]
pub struct HttpHandler {
    pub handle: russh::server::Handle,
    pub address: String,
    pub port: u16,
}

#[derive(Clone)]
pub struct Server {
    pub http: Arc<DashMap<String, (SocketAddr, HttpHandler)>>,
    pub allowed_key_fingerprints: Arc<DashSet<String>>,
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
        http: Arc::new(DashMap::new()),
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

    watch_public_keys_directory(
        config.public_keys_directory.clone(),
        Arc::clone(&sh.allowed_key_fingerprints),
    )?;

    sh.run_on_address(ssh_config, (config.listen_address.clone(), config.ssh_port))
        .await
        .with_context(|| "Error listening to SSH port and address")?;
    Ok(())
}
