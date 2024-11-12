use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{command, Parser};
use dashmap::DashMap;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Request;
use hyper_util::rt::TokioIo;
use russh::server::{Config, Server as _};
use russh_keys::decode_secret_key;
use sandhole::{http::proxy_handler, Server};
use tokio::fs;
use tokio::net::TcpListener;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    private_key_file: Option<PathBuf>,

    #[arg(long)]
    private_key_password: Option<String>,

    #[arg(long)]
    address: Option<String>,

    #[arg(long, default_value_t = 2222)]
    ssh_port: u16,

    #[arg(long, default_value_t = 80)]
    http_port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let address = args.address.unwrap_or_else(|| "0.0.0.0".into());
    let private_key_location = args
        .private_key_file
        .unwrap_or_else(|| PathBuf::from("./deploy/keys/ssh_key"));
    let key = fs::read_to_string(private_key_location)
        .await
        .with_context(|| "Error reading secret key")?;
    let key = decode_secret_key(&key, args.private_key_password.as_deref())
        .with_context(|| "Error decoding secret key")?;
    let config = Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_secs(3),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![key],
        ..Default::default()
    };
    let config = Arc::new(config);
    let mut sh = Server {
        http: Arc::new(DashMap::new()),
        peers: Arc::new(DashMap::new()),
    };
    let http_address = address.clone();
    let http_listener = TcpListener::bind((http_address, args.http_port))
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
    sh.run_on_address(config, (address, args.ssh_port))
        .await
        .with_context(|| "Error listening to SSH port and address")?;
    Ok(())
}
