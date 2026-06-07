use std::{collections::HashSet, mem::size_of, net::IpAddr, sync::Arc};

use crate::{
    connection_handler::ConnectionHandler,
    connections::ConnectionMap,
    droppable_handle::DroppableHandle,
    ip::IpFilter,
    reactor::UdpReactor,
    ssh::connection_handler::SshTunnelHandler,
    telemetry::{TELEMETRY_COUNTER_UDP_CONNECTIONS, TELEMETRY_KEY_PORT},
    udp_listener::get_udp_socket,
};
use ahash::RandomState;
use bon::Builder;
use color_eyre::eyre::Context;
use dashmap::DashMap;
use futures_util::pin_mut;
use metrics::counter;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    select,
};

pub const MAX_PACKET_SIZE: usize = size_of::<u16>() + u16::MAX as usize;

// Creates and returns a buffer on the heap with enough space to contain any possible
// UDP datagram.
//
// This is put on the heap and in a separate function to avoid the 64k buffer from ending
// up on the stack and blowing up the size of the futures using it.
#[inline]
fn datagram_buffer() -> Box<[u8; MAX_PACKET_SIZE]> {
    Box::new([0u8; MAX_PACKET_SIZE])
}

// Service that handles creating UDP sockets for reverse forwarding connections.
#[derive(Builder)]
pub(crate) struct UdpHandler {
    // Address to listen to when creating sockets.
    listen_address: IpAddr,
    // Map containing spawned tasks of connections for each socket.
    #[builder(skip = DashMap::default())]
    sockets: DashMap<u16, DroppableHandle<()>, RandomState>,
    // Connection map to assign a tunneling service for each incoming connection.
    conn_manager: Arc<ConnectionMap<u16, Arc<SshTunnelHandler>, UdpReactor>>,
    // Service that identifies whether to allow or block a given IP address.
    ip_filter: Arc<IpFilter>,
    // Whether to send UDP logs to the SSH handles behind the forwarded connections.
    disable_udp_logs: bool,
}

pub(crate) trait UdpPortHandler {
    async fn create_port_socket(&self, port: u16) -> color_eyre::Result<u16>;
    async fn get_free_port(&self) -> color_eyre::Result<u16>;
    fn update_ports(&self, ports: Vec<u16>);
}

impl UdpPortHandler for Arc<UdpHandler> {
    // Create a UDP listener on the given port.
    async fn create_port_socket(&self, port: u16) -> color_eyre::Result<u16> {
        if self.sockets.contains_key(&port) {
            return Ok(port);
        }
        // Check if we're able to bind to the given address and port.
        let socket = get_udp_socket((self.listen_address, port))?;
        let port = socket
            .local_addr()
            .with_context(|| "Missing local address when binding port")?
            .port();
        let clone = Arc::clone(self);
        let listen_address = self.listen_address;
        // Start task that will listen to incoming connections.
        let join_handle = DroppableHandle(tokio::spawn(async move {
            let mut socket = socket;
            loop {
                let mut buf = datagram_buffer();
                match socket.recv_from(buf.as_mut()).await {
                    Ok((len, address)) => {
                        let ip = address.ip().to_canonical();
                        if !clone.ip_filter.is_allowed(ip) {
                            #[cfg(not(coverage_nightly))]
                            tracing::info!(%address, "Rejecting UDP connection: IP not allowed.");
                            continue;
                        }
                        // Get the handler for this port
                        if let Some(handler) = clone.conn_manager.get(&port, ip)
                            && let Ok(channel) = handler.tunneling_channel(ip, address.port()).await
                        {
                            counter!(TELEMETRY_COUNTER_UDP_CONNECTIONS, TELEMETRY_KEY_PORT => port.to_string())
                            .increment(1);
                            // Log new connection to SSH handler
                            if !clone.disable_udp_logs {
                                let _ = handler.log_channel().send(
                                    format!(
                                        "New connection from {}:{} to UDP port {}\r\n",
                                        ip,
                                        address.port(),
                                        port
                                    )
                                    .into_bytes(),
                                );
                            }
                            let socket = std::mem::replace(
                                &mut socket,
                                get_udp_socket((listen_address, port))
                                    .expect("should re-create UDP socket"),
                            );
                            if let Err(error) = socket.connect(address).await {
                                #[cfg(not(coverage_nightly))]
                                tracing::error!(%port, %error, "Error connecting UDP socket.");
                                continue;
                            }
                            let mut read_buf = datagram_buffer();

                            // Prepare already consumed data to be sent to SSH channel
                            *read_buf[..size_of::<u16>()]
                                .as_mut_array()
                                .expect("length checked") = (len as u16).to_be_bytes();
                            read_buf[size_of::<u16>()..size_of::<u16>() + len]
                                .copy_from_slice(&buf[..len]);

                            tokio::spawn(async move {
                                let udp_read = Arc::new(socket);
                                let udp_write = udp_read.clone();
                                let (mut ssh_read, mut ssh_write) = tokio::io::split(channel);

                                let udp2ssh = async move {
                                    let mut buf = read_buf;
                                    if let Err(error) =
                                        ssh_write.write_all(&buf[..size_of::<u16>() + len]).await
                                    {
                                        #[cfg(not(coverage_nightly))]
                                        tracing::warn!(%port, %error, "Error writing to SSH channel for UDP.");
                                        return;
                                    }
                                    loop {
                                        match udp_read
                                            .recv(&mut buf.as_mut()[size_of::<u16>()..])
                                            .await
                                        {
                                            Ok(len) => {
                                                *buf[..size_of::<u16>()]
                                                    .as_mut_array()
                                                    .expect("length checked") =
                                                    (len as u16).to_be_bytes();
                                                if let Err(error) = ssh_write
                                                    .write_all(&buf[..size_of::<u16>() + len])
                                                    .await
                                                {
                                                    #[cfg(not(coverage_nightly))]
                                                    tracing::warn!(%port, %error, "Error writing to SSH channel for UDP.");
                                                    break;
                                                };
                                            }
                                            Err(error) => {
                                                #[cfg(not(coverage_nightly))]
                                                tracing::warn!(%port, %error, "Error reading from UDP socket.");
                                                break;
                                            }
                                        }
                                    }
                                };
                                let ssh2udp = async move {
                                    let mut buf = datagram_buffer();
                                    loop {
                                        match ssh_read.read_u16().await {
                                            Ok(len) => {
                                                if let Err(error) = ssh_read
                                                    .read_exact(&mut buf[..len as usize])
                                                    .await
                                                {
                                                    #[cfg(not(coverage_nightly))]
                                                    tracing::warn!(%port, %error, "Error reading UDP datagram from SSH channel.");
                                                    break;
                                                } else if let Err(error) =
                                                    udp_write.send(&mut buf[..len as usize]).await
                                                {
                                                    #[cfg(not(coverage_nightly))]
                                                    tracing::warn!(%port, %error, "Error reading from SSH channel for UDP.");
                                                    break;
                                                }
                                            }
                                            Err(error) => {
                                                #[cfg(not(coverage_nightly))]
                                                tracing::warn!(%port, %error, "Error reading UDP datagram size from SSH channel.");
                                                break;
                                            }
                                        }
                                    }
                                };

                                pin_mut!(udp2ssh);
                                pin_mut!(ssh2udp);

                                select! {
                                    _ = udp2ssh => {}
                                    _ = ssh2udp => {}
                                }
                            });
                        }
                    }
                    Err(error) => {
                        #[cfg(not(coverage_nightly))]
                        tracing::warn!(%port, %error, "Error getting remote connection on UDP port.")
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
        self.create_port_socket(0).await
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
                    if let Err(error) = clone.create_port_socket(port).await {
                        #[cfg(not(coverage_nightly))]
                        tracing::error!(%port, %error, "Failed to create listener for TCP port.");
                    }
                }
            });
        }
    }
}
