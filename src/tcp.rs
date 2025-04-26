use std::{collections::HashSet, net::IpAddr, sync::Arc, time::Duration};

use crate::{
    connection_handler::ConnectionHandler, connections::ConnectionMap,
    droppable_handle::DroppableHandle, ip::IpFilter, reactor::TcpReactor, ssh::SshTunnelHandler,
    telemetry::Telemetry,
};
use anyhow::Context;
use dashmap::DashMap;
use log::{error, info, warn};
use tokio::{io::copy_bidirectional_with_sizes, net::TcpListener, time::timeout};

// Service that handles creating TCP sockets for reverse forwarding connections.
pub(crate) struct TcpHandlerConfig {
    // Address to listen to when creating sockets.
    pub(crate) listen_address: IpAddr,
    // Connection map to assign a tunneling service for each incoming connection.
    pub(crate) conn_manager: Arc<ConnectionMap<u16, Arc<SshTunnelHandler>, TcpReactor>>,
    // Telemetry server to keep track of the total connections.
    pub(crate) telemetry: Arc<Telemetry>,
    // Service that identifies whether to allow or block a given IP address.
    pub(crate) ip_filter: Arc<IpFilter>,
    // Buffer size for bidirectional copying.
    pub(crate) buffer_size: usize,
    // Optional duration to time out TCP connections.
    pub(crate) tcp_connection_timeout: Option<Duration>,
    // Whether to send TCP logs to the SSH handles behind the forwarded connections.
    pub(crate) disable_tcp_logs: bool,
}

// Service that handles creating TCP sockets for reverse forwarding connections.
pub(crate) struct TcpHandler {
    // Address to listen to when creating sockets.
    listen_address: IpAddr,
    // Map containing spawned tasks of connections for each socket.
    sockets: DashMap<u16, DroppableHandle<()>>,
    // Connection map to assign a tunneling service for each incoming connection.
    conn_manager: Arc<ConnectionMap<u16, Arc<SshTunnelHandler>, TcpReactor>>,
    // Telemetry server to keep track of the total connections.
    telemetry: Arc<Telemetry>,
    // Service that identifies whether to allow or block a given IP address.
    ip_filter: Arc<IpFilter>,
    // Buffer size for bidirectional copying.
    buffer_size: usize,
    // Optional duration to time out TCP connections.
    tcp_connection_timeout: Option<Duration>,
    // Whether to send TCP logs to the SSH handles behind the forwarded connections.
    disable_tcp_logs: bool,
}

impl TcpHandler {
    pub(crate) fn new(
        TcpHandlerConfig {
            listen_address,
            conn_manager,
            telemetry,
            ip_filter,
            buffer_size,
            tcp_connection_timeout,
            disable_tcp_logs,
        }: TcpHandlerConfig,
    ) -> Self {
        TcpHandler {
            listen_address,
            sockets: DashMap::new(),
            conn_manager,
            telemetry,
            ip_filter,
            buffer_size,
            tcp_connection_timeout,
            disable_tcp_logs,
        }
    }
}

pub(crate) trait PortHandler {
    async fn create_port_listener(&self, port: u16) -> anyhow::Result<u16>;
    async fn get_free_port(&self) -> anyhow::Result<u16>;
    fn update_ports(&self, ports: Vec<u16>);
}

impl PortHandler for Arc<TcpHandler> {
    // Create a TCP listener on the given port.
    async fn create_port_listener(&self, port: u16) -> anyhow::Result<u16> {
        // Check if we're able to bind to the given address and port.
        let listener = match TcpListener::bind((self.listen_address, port)).await {
            Ok(listener) => listener,
            Err(err) => return Err(err.into()),
        };
        let port = listener
            .local_addr()
            .with_context(|| "Missing local address when binding port")?
            .port();
        let clone = Arc::clone(self);
        // Start task that will listen to incoming connections.
        let join_handle = DroppableHandle(tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut stream, address)) => {
                        let ip = address.ip();
                        if !clone.ip_filter.is_allowed(ip) {
                            info!("Rejecting TCP connection for {}: not allowed", ip);
                            continue;
                        }
                        if let Err(err) = stream.set_nodelay(true) {
                            warn!("Error setting nodelay for {}: {}", address, err);
                        }
                        // Get the handler for this port
                        if let Some(handler) = clone.conn_manager.get(&port) {
                            if let Ok(mut channel) = handler
                                .tunneling_channel(address.ip(), address.port())
                                .await
                            {
                                clone.telemetry.add_tcp_connection(port);
                                // Log new connection to SSH handler
                                if !clone.disable_tcp_logs {
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
                                // Copy data between the TCP stream and the reverse forwarding channel, with optional timeout
                                match clone.tcp_connection_timeout {
                                    Some(duration) => {
                                        let _ = timeout(duration, async {
                                            copy_bidirectional_with_sizes(
                                                &mut stream,
                                                &mut channel,
                                                clone.buffer_size,
                                                clone.buffer_size,
                                            )
                                            .await
                                        })
                                        .await;
                                    }
                                    None => {
                                        let _ = copy_bidirectional_with_sizes(
                                            &mut stream,
                                            &mut channel,
                                            clone.buffer_size,
                                            clone.buffer_size,
                                        )
                                        .await;
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

    // Handle changes to the proxy ports, creating/deleting listeners as needed.
    fn update_ports(&self, ports: Vec<u16>) {
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
                    if let Err(err) = clone.create_port_listener(port).await {
                        error!("Failed to create listener for port {}: {}", port, err);
                    }
                }
            });
        }
    }
}
