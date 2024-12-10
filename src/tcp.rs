use std::{collections::HashSet, sync::Arc, time::Duration};

use crate::{
    connections::{ConnectionMap, ConnectionMapReactor},
    droppable_handle::DroppableHandle,
    handler::ConnectionHandler,
    ssh::SshTunnelHandler,
    tcp_alias::{BorrowedTcpAlias, TcpAlias, TcpAliasKey},
};
use async_trait::async_trait;
use dashmap::DashMap;
use log::error;
use tokio::{io::copy_bidirectional, net::TcpListener, time::timeout};

pub(crate) static NO_ALIAS_HOST: &str = "localhost";

pub(crate) fn is_alias(address: &str) -> bool {
    address != "localhost" && !address.is_empty() && address != "*"
}

pub(crate) struct TcpHandler {
    listen_address: String,
    sockets: DashMap<u16, DroppableHandle<()>>,
    conn_manager: Arc<ConnectionMap<TcpAlias, Arc<SshTunnelHandler>, Arc<Self>>>,
    tcp_connection_timeout: Option<Duration>,
    disable_tcp_logs: bool,
}

impl TcpHandler {
    pub(crate) fn new(
        listen_address: String,
        conn_manager: Arc<ConnectionMap<TcpAlias, Arc<SshTunnelHandler>, Arc<Self>>>,
        tcp_connection_timeout: Option<Duration>,
        disable_tcp_logs: bool,
    ) -> Self {
        TcpHandler {
            listen_address,
            sockets: DashMap::new(),
            conn_manager,
            tcp_connection_timeout,
            disable_tcp_logs,
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
        let tcp_connection_timeout = self.tcp_connection_timeout;
        let disable_tcp_logs = self.disable_tcp_logs;
        let join_handle = DroppableHandle(tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut stream, address)) => {
                        let key: &dyn TcpAliasKey = &BorrowedTcpAlias(NO_ALIAS_HOST, &port);
                        if let Some(handler) = clone.conn_manager.get(key) {
                            if let Ok(mut channel) = handler
                                .tunneling_channel(
                                    &address.ip().to_canonical().to_string(),
                                    address.port(),
                                )
                                .await
                            {
                                if !disable_tcp_logs {
                                    let _ = handler.log_channel().send(
                                        format!(
                                            "New connection from {}:{} to TCP port {}",
                                            address.ip().to_canonical(),
                                            address.port(),
                                            port
                                        )
                                        .into_bytes(),
                                    );
                                }
                                match tcp_connection_timeout {
                                    Some(duration) => {
                                        let _ = timeout(duration, async {
                                            copy_bidirectional(&mut stream, &mut channel).await
                                        })
                                        .await;
                                    }
                                    None => {
                                        let _ = copy_bidirectional(&mut stream, &mut channel).await;
                                    }
                                }
                            }
                        }
                    }
                    Err(err) => error!("Error listening on port {}: {}", port, err),
                }
            }
        }));
        self.sockets.insert(port, join_handle);
        port
    }

    async fn get_free_port(&self) -> u16 {
        self.create_port_listener(0).await
    }
}

impl ConnectionMapReactor<TcpAlias> for Arc<TcpHandler> {
    fn call(&self, ports: Vec<TcpAlias>) {
        let mut ports: HashSet<u16> = ports
            .into_iter()
            .filter_map(|TcpAlias(address, port)| {
                if address == NO_ALIAS_HOST {
                    Some(port)
                } else {
                    None
                }
            })
            .collect();
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
