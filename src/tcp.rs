use std::{collections::HashSet, net::IpAddr, sync::Arc, time::Duration};

use crate::{
    connection_handler::ConnectionHandler,
    connections::ConnectionMap,
    droppable_handle::DroppableHandle,
    ip::IpFilter,
    reactor::TcpReactor,
    ssh::connection_handler::SshTunnelHandler,
    telemetry::{TELEMETRY_COUNTER_TCP_CONNECTIONS_TOTAL, TELEMETRY_KEY_PORT},
};
use ahash::RandomState;
use bon::Builder;
use color_eyre::eyre::Context;
use dashmap::DashMap;
use metrics::counter;
use tokio::{io::copy_bidirectional_with_sizes, net::TcpListener, time::timeout};
#[cfg(not(coverage_nightly))]
use tracing::{error, info, warn};

// Service that handles creating TCP sockets for reverse forwarding connections.
#[derive(Builder)]
pub(crate) struct TcpHandler {
    // Address to listen to when creating sockets.
    listen_address: IpAddr,
    // Map containing spawned tasks of connections for each socket.
    #[builder(skip = DashMap::default())]
    sockets: DashMap<u16, DroppableHandle<()>, RandomState>,
    // Connection map to assign a tunneling service for each incoming connection.
    conn_manager: Arc<ConnectionMap<u16, Arc<SshTunnelHandler>, TcpReactor>>,
    // Service that identifies whether to allow or block a given IP address.
    ip_filter: Arc<IpFilter>,
    // Buffer size for bidirectional copying.
    buffer_size: usize,
    // Optional duration to time out TCP connections.
    tcp_connection_timeout: Option<Duration>,
    // Whether to send TCP logs to the SSH handles behind the forwarded connections.
    disable_tcp_logs: bool,
}

pub(crate) trait PortHandler {
    async fn create_port_listener(&self, port: u16) -> color_eyre::Result<u16>;
    async fn get_free_port(&self) -> color_eyre::Result<u16>;
    fn update_ports(&self, ports: Vec<u16>);
}

impl PortHandler for Arc<TcpHandler> {
    // Create a TCP listener on the given port.
    async fn create_port_listener(&self, port: u16) -> color_eyre::Result<u16> {
        if self.sockets.contains_key(&port) {
            return Ok(port);
        }
        // Check if we're able to bind to the given address and port.
        let listener = TcpListener::bind((self.listen_address, port)).await?;
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
                            #[cfg(not(coverage_nightly))]
                            info!(%address, "Rejecting TCP connection: IP not allowed.");
                            continue;
                        }
                        if let Err(error) = stream.set_nodelay(true) {
                            #[cfg(not(coverage_nightly))]
                            warn!(%address, %error, "Error setting nodelay.");
                        }
                        // Get the handler for this port
                        let ip = address.ip().to_canonical();
                        if let Some(handler) = clone.conn_manager.get(&port, ip) {
                            if let Ok(mut channel) =
                                handler.tunneling_channel(ip, address.port()).await
                            {
                                counter!(TELEMETRY_COUNTER_TCP_CONNECTIONS_TOTAL, TELEMETRY_KEY_PORT => port.to_string())
                                    .increment(1);
                                // Log new connection to SSH handler
                                if !clone.disable_tcp_logs {
                                    let _ = handler.log_channel().send(
                                        format!(
                                            "New connection from {}:{} to TCP port {}\r\n",
                                            address.ip().to_canonical(),
                                            address.port(),
                                            port
                                        )
                                        .into_bytes(),
                                    );
                                }
                                // Copy data between the TCP stream and the reverse forwarding channel, with optional timeout
                                let buffer_size = clone.buffer_size;
                                match clone.tcp_connection_timeout {
                                    Some(duration) => {
                                        tokio::spawn(async move {
                                            let _ = timeout(duration, async {
                                                copy_bidirectional_with_sizes(
                                                    &mut stream,
                                                    &mut channel,
                                                    buffer_size,
                                                    buffer_size,
                                                )
                                                .await
                                            })
                                            .await;
                                        });
                                    }
                                    None => {
                                        tokio::spawn(async move {
                                            let _ = copy_bidirectional_with_sizes(
                                                &mut stream,
                                                &mut channel,
                                                buffer_size,
                                                buffer_size,
                                            )
                                            .await;
                                        });
                                    }
                                }
                            }
                        }
                    }
                    Err(error) => {
                        #[cfg(not(coverage_nightly))]
                        error!(%port, %error, "Error listening on TCP port.")
                    }
                }
            }
        }));
        self.sockets.insert(port, join_handle);
        Ok(port)
    }

    // Create a TCP listener on a random open port, returning the port number.
    async fn get_free_port(&self) -> color_eyre::Result<u16> {
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
                    if let Err(error) = clone.create_port_listener(port).await {
                        #[cfg(not(coverage_nightly))]
                        error!(%port, %error, "Failed to create listener for TCP port.");
                    }
                }
            });
        }
    }
}
