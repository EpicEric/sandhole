use std::{net::SocketAddr, sync::Arc};

use dashmap::DashMap;
use tokio::sync::mpsc;

pub mod error;
pub mod http;
pub mod ssh;

pub struct ServerHandler {
    pub peer: SocketAddr,
    pub tx: mpsc::Sender<Vec<u8>>,
    pub rx: Option<mpsc::Receiver<Vec<u8>>>,
    pub server: Server,
}

#[derive(Clone)]
pub struct HttpHandler {
    pub handle: russh::server::Handle,
    pub address: String,
    pub port: u16,
}

#[derive(Clone)]
pub struct Server {
    pub http: Arc<DashMap<String, HttpHandler>>,
    pub peers: Arc<DashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>,
}
