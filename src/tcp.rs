use std::{collections::HashSet, sync::Arc, time::Duration};

use crate::{
    connection_handler::ConnectionHandler,
    connections::{ConnectionMap, ConnectionMapReactor},
    droppable_handle::DroppableHandle,
    ssh::SshTunnelHandler,
};
use anyhow::Context;
use async_trait::async_trait;
use dashmap::DashMap;
use log::error;
use tokio::{io::copy_bidirectional, net::TcpListener, time::timeout};

// Service that handles creating TCP sockets for reverse forwarding connections.
pub(crate) struct TcpHandler {
    // Address to listen to when creating sockets.
    listen_address: String,
    // Map containing spawned tasks of connections for each socket.
    sockets: DashMap<u16, DroppableHandle<()>>,
    // Connection map to assign a tunneling service for each incoming connection.
    conn_manager: Arc<ConnectionMap<u16, Arc<SshTunnelHandler>, Arc<Self>>>,
    // Optional duration to time out TCP connections.
    tcp_connection_timeout: Option<Duration>,
    // Whether to send TCP logs to the SSH handles behind the forwarded connections.
    disable_tcp_logs: bool,
}

impl TcpHandler {
    pub(crate) fn new(
        listen_address: String,
        conn_manager: Arc<ConnectionMap<u16, Arc<SshTunnelHandler>, Arc<Self>>>,
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
    async fn create_port_listener(&self, port: u16) -> anyhow::Result<u16>;
    async fn get_free_port(&self) -> anyhow::Result<u16>;
}

#[async_trait]
impl PortHandler for Arc<TcpHandler> {
    // Create a TCP listener on the given port.
    async fn create_port_listener(&self, port: u16) -> anyhow::Result<u16> {
        // Check if we're able to bind to the given address and port.
        let listener = match TcpListener::bind((self.listen_address.as_ref(), port)).await {
            Ok(listener) => listener,
            Err(err) => return Err(err.into()),
        };
        let port = listener
            .local_addr()
            .with_context(|| "Missing local address when binding port")?
            .port();
        let clone = Arc::clone(self);
        let tcp_connection_timeout = self.tcp_connection_timeout;
        let disable_tcp_logs = self.disable_tcp_logs;
        // Start task that will listen to incoming connections.
        let join_handle = DroppableHandle(tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut stream, address)) => {
                        // Get the handler for this port
                        if let Some(handler) = clone.conn_manager.get(&port) {
                            if let Ok(mut channel) = handler
                                .tunneling_channel(
                                    &address.ip().to_canonical().to_string(),
                                    address.port(),
                                )
                                .await
                            {
                                // Log new connection to SSH handler
                                if !disable_tcp_logs {
                                    handler.log_channel().inspect(|tx| {
                                        let _ = tx.send(
                                            format!(
                                                "New connection from {}:{} to TCP port {}",
                                                address.ip().to_canonical(),
                                                address.port(),
                                                port
                                            )
                                            .into_bytes(),
                                        );
                                    });
                                }
                                // Copy data between the TCP stream and the reverse forwarding channel, with optional timeout
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
        Ok(port)
    }

    // Create a TCP listener on a random open port, returning the port number.
    async fn get_free_port(&self) -> anyhow::Result<u16> {
        // By passing 0 to create_port_listener, the OS will choose a port for us.
        self.create_port_listener(0).await
    }
}

impl ConnectionMapReactor<u16> for Arc<TcpHandler> {
    // Handle changes to the proxy ports, creating/deleting listeners as needed.
    fn call(&self, ports: Vec<u16>) {
        // Find the ports listening to the localhost address
        let mut ports: HashSet<u16> = ports.into_iter().collect();
        // Remove any socket tasks not in the list of localhost port
        self.sockets.retain(|port, _| ports.contains(port));
        // Find the list of new ports
        ports.retain(|port| !self.sockets.contains_key(port));
        if !ports.is_empty() {
            let clone = Arc::clone(self);
            // Create port listeners for the new ports
            tokio::spawn(async move {
                for port in ports.into_iter() {
                    let _ = clone.create_port_listener(port).await;
                }
            });
        }
    }
}
