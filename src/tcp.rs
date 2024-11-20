use std::{collections::HashSet, sync::Arc};

use crate::{
    connections::{ConnectionMap, ConnectionMapReactor},
    http::HttpHandler,
    ssh::SshTunnelHandler,
};
use dashmap::DashMap;
use rand::{thread_rng, Rng};
use tokio::{io::copy_bidirectional, net::TcpListener, task::JoinHandle};

pub(crate) struct TcpHandler {
    listen_address: String,
    sockets: DashMap<u16, DroppableHandle<()>>,
    conn_manager: Arc<ConnectionMap<u16, Arc<SshTunnelHandler>, Arc<Self>>>,
    force_random_ports: bool,
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
        force_random_ports: bool,
    ) -> Self {
        TcpHandler {
            listen_address,
            conn_manager,
            sockets: DashMap::new(),
            force_random_ports,
        }
    }

    pub(crate) fn get_free_port(&self) -> u16 {
        let mut rng = thread_rng();
        loop {
            let port = rng.gen_range(1025..=u16::MAX);
            if !self.sockets.contains_key(&port) {
                return port;
            }
        }
    }

    pub(crate) fn force_random_ports(&self) -> bool {
        self.force_random_ports
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
                    let listener =
                        match TcpListener::bind((clone.listen_address.as_ref(), port)).await {
                            Ok(listener) => listener,
                            Err(err) => panic!("Error listening to TCP port {}: {}", port, err),
                        };
                    let other_clone = Arc::clone(&clone);
                    let jh = DroppableHandle(tokio::spawn(async move {
                        loop {
                            match listener.accept().await {
                                Ok((mut stream, address)) => {
                                    if let Some(handler) = other_clone.conn_manager.get(&port) {
                                        if let Ok(mut channel) = handler
                                            .tunneling_channel(
                                                &address.ip().to_string(),
                                                address.port(),
                                            )
                                            .await
                                        {
                                            let _ = copy_bidirectional(
                                                &mut stream,
                                                channel.inner_mut(),
                                            )
                                            .await;
                                        }
                                    }
                                }
                                Err(err) => eprintln!("Error listening on port {}: {}", port, err),
                            }
                        }
                    }));
                    clone.sockets.insert(port, jh);
                }
            });
        }
    }
}
