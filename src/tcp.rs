use std::{collections::HashSet, sync::Arc};

use crate::{
    connections::{ConnectionMap, ConnectionMapReactor},
    http::HttpHandler,
    ssh::SshTunnelHandler,
};
use async_trait::async_trait;
use dashmap::DashMap;
use log::error;
use tokio::{io::copy_bidirectional, net::TcpListener, task::JoinHandle};

pub(crate) struct TcpHandler {
    listen_address: String,
    sockets: DashMap<u16, DroppableHandle<()>>,
    conn_manager: Arc<ConnectionMap<u16, Arc<SshTunnelHandler>, Arc<Self>>>,
}

struct DroppableHandle<T>(JoinHandle<T>);

impl<T> Drop for DroppableHandle<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl TcpHandler {
    pub(crate) fn new(
        listen_address: String,
        conn_manager: Arc<ConnectionMap<u16, Arc<SshTunnelHandler>, Arc<Self>>>,
    ) -> Self {
        TcpHandler {
            listen_address,
            conn_manager,
            sockets: DashMap::new(),
        }
    }
}

#[async_trait]
pub(crate) trait PortHandler {
    async fn create_port_listener(&self, port: u16) -> u16;
    async fn get_free_port(&self) -> u16;
}

#[async_trait]
impl PortHandler for Arc<TcpHandler> {
    async fn create_port_listener(&self, port: u16) -> u16 {
        let listener = match TcpListener::bind((self.listen_address.as_ref(), port)).await {
            Ok(listener) => listener,
            Err(err) => panic!("Error listening to TCP port {}: {}", port, err),
        };
        let port = listener.local_addr().unwrap().port();
        let clone = Arc::clone(self);
        let jh = DroppableHandle(tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut stream, address)) => {
                        if let Some(handler) = clone.conn_manager.get(&port) {
                            if let Ok(mut channel) = handler
                                .tunneling_channel(&address.ip().to_string(), address.port())
                                .await
                            {
                                let _ = copy_bidirectional(&mut stream, channel.inner_mut()).await;
                            }
                        }
                    }
                    Err(err) => error!("Error listening on port {}: {}", port, err),
                }
            }
        }));
        self.sockets.insert(port, jh);
        port
    }

    async fn get_free_port(&self) -> u16 {
        self.create_port_listener(0).await
    }
}

impl ConnectionMapReactor<u16> for Arc<TcpHandler> {
    fn call(&self, ports: Vec<u16>) {
        let mut ports: HashSet<u16> = ports.into_iter().collect();
        self.sockets.retain(|port, _| ports.contains(port));
        ports.retain(|port| !self.sockets.contains_key(port));
        if !ports.is_empty() {
            let clone = Arc::clone(self);
            tokio::spawn(async move {
                for port in ports.into_iter() {
                    clone.create_port_listener(port).await;
                }
            });
        }
    }
}
