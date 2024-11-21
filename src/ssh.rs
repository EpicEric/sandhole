use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
};

use crate::{
    addressing::{AddressDelegator, DnsResolver},
    http::HttpHandler,
    SandholeServer,
};

use async_trait::async_trait;
use hyper_util::rt::TokioIo;
use russh::{
    server::{Auth, Handler, Msg, Session},
    Channel, ChannelId, ChannelStream, MethodSet,
};
use russh_keys::key::PublicKey;
use tokio::{
    io::{copy_bidirectional, AsyncWriteExt},
    sync::{mpsc, oneshot, Mutex},
    time::sleep,
};

#[derive(Clone)]
pub(crate) struct SshTunnelHandler {
    handle: russh::server::Handle,
    tx: mpsc::Sender<Vec<u8>>,
    peer: SocketAddr,
    address: String,
    port: u32,
}

impl SshTunnelHandler {
    pub(crate) fn new(
        handle: russh::server::Handle,
        tx: mpsc::Sender<Vec<u8>>,
        peer: SocketAddr,
        address: String,
        port: u32,
    ) -> Self {
        SshTunnelHandler {
            handle,
            address,
            peer,
            port,
            tx,
        }
    }
}

#[async_trait]
impl HttpHandler<ChannelStream<Msg>> for SshTunnelHandler {
    fn log_channel(&self) -> mpsc::Sender<Vec<u8>> {
        self.tx.clone()
    }
    async fn tunneling_channel(
        &self,
        ip: &str,
        port: u16,
    ) -> anyhow::Result<TokioIo<ChannelStream<Msg>>> {
        let channel = self
            .handle
            .channel_open_forwarded_tcpip(self.address.clone(), self.port, ip, port.into())
            .await?
            .into_stream();
        Ok(TokioIo::new(channel))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Authentication {
    /// Not authenticated.
    None,
    /// Authenticated as a proxy/tunneling user.
    Proxy,
    /// Authenticated as a valid user.
    User,
    /// Authenticated as an admin.
    Admin,
}

// TO-DO: Optimize memory usage
pub(crate) struct ServerHandler {
    cancellation_tx: Option<oneshot::Sender<()>>,
    peer: SocketAddr,
    user: Option<String>,
    key_fingerprint: Option<String>,
    authentication: Arc<Mutex<Authentication>>,
    tx: mpsc::Sender<Vec<u8>>,
    rx: Option<mpsc::Receiver<Vec<u8>>>,
    ssh_hosts: HashSet<String>,
    http_hosts: HashSet<String>,
    tcp_ports: HashSet<u16>,
    host_addressing: HashMap<(String, u32), String>,
    port_addressing: HashMap<(String, u32), u16>,
    address_delegator: Arc<AddressDelegator<DnsResolver>>,
    server: Arc<SandholeServer>,
}

pub(crate) trait Server {
    fn new_client(
        &mut self,
        peer_address: Option<SocketAddr>,
        cancellation_tx: oneshot::Sender<()>,
    ) -> ServerHandler;
}

impl Server for Arc<SandholeServer> {
    fn new_client(
        &mut self,
        peer_address: Option<SocketAddr>,
        cancellation_tx: oneshot::Sender<()>,
    ) -> ServerHandler {
        let (tx, rx) = mpsc::channel(64);
        let peer_address = peer_address.unwrap();
        ServerHandler {
            cancellation_tx: Some(cancellation_tx),
            peer: peer_address,
            user: None,
            key_fingerprint: None,
            authentication: Arc::new(Mutex::new(Authentication::None)),
            tx,
            rx: Some(rx),
            ssh_hosts: HashSet::new(),
            http_hosts: HashSet::new(),
            tcp_ports: HashSet::new(),
            host_addressing: HashMap::new(),
            port_addressing: HashMap::new(),
            address_delegator: Arc::clone(&self.address_delegator),
            server: Arc::clone(self),
        }
    }
}

#[async_trait]
impl Handler for ServerHandler {
    type Error = russh::Error;

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let Some(mut rx) = self.rx.take() else {
            return Err(russh::Error::Disconnect);
        };
        if *self.authentication.lock().await == Authentication::None {
            return Err(russh::Error::Disconnect);
        }
        let mut stream = channel.into_stream();
        tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                if stream.write_all(&message).await.is_err() {
                    break;
                }
            }
        });
        Ok(true)
    }

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::PUBLICKEY),
        })
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        let fingerprint = public_key.fingerprint();
        self.user = Some(user.to_string());
        self.key_fingerprint = Some(fingerprint);
        let authentication = self
            .server
            .fingerprints_validator
            .authenticate_fingerprint(self.key_fingerprint.as_ref().unwrap());
        let mut authentication_guard = self.authentication.lock().await;
        *authentication_guard = authentication;
        drop(authentication_guard);
        match authentication {
            Authentication::None => {
                // Start timer for user to do local port forwarding.
                // Otherwise, the connection will be canceled upon expiration
                let authentication = Arc::clone(&self.authentication);
                let Some(cancellation_tx) = self.cancellation_tx.take() else {
                    return Err(russh::Error::Disconnect);
                };
                let timeout = self.server.idle_connection_timeout;
                tokio::spawn(async move {
                    sleep(timeout).await;
                    if *authentication.lock().await == Authentication::None {
                        let _ = cancellation_tx.send(());
                    }
                });
                Ok(Auth::Accept)
            }
            Authentication::Proxy => unreachable!(),
            Authentication::User | Authentication::Admin => Ok(Auth::Accept),
        }
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        match *self.authentication.lock().await {
            Authentication::None => return Err(russh::Error::Disconnect),
            Authentication::Proxy | Authentication::User | Authentication::Admin => (),
        }
        // Sending Ctrl+C ends the session and disconnects the client
        if data == [3] {
            return Err(russh::Error::Disconnect);
        }
        Ok(())
    }

    // TO-DO: Admin interface
    async fn pty_request(
        &mut self,
        _channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if *self.authentication.lock().await != Authentication::Admin {
            return Ok(());
        }
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // Only allow remote forwarding for authorized keys
        match *self.authentication.lock().await {
            Authentication::None | Authentication::Proxy => return Err(russh::Error::Disconnect),
            Authentication::User | Authentication::Admin => (),
        }
        let address = address.to_string();
        let handle = session.handle();
        match *port {
            22 => {
                // Assign SSH host through config
                let assigned_host = self
                    .address_delegator
                    .get_address(&address, &self.user, &self.key_fingerprint, &self.peer)
                    .await;
                self.ssh_hosts.insert(assigned_host.clone());
                self.host_addressing
                    .insert((address.clone(), *port), assigned_host.clone());
                println!("Serving SSH for {} ({})", &assigned_host, self.peer);
                let _ = self
                    .tx
                    .send(
                        format!(
                            "Serving SSH on {}:{}\r\n\x1b[2mhint: connect with ssh -J {}{} {}{}\x1b[0m\r\n",
                            &assigned_host,
                            self.server.ssh_port,
                            self.server.domain,
                            if self.server.ssh_port == 22 {
                                "".into()
                            } else {
                                format!(":{}", self.server.ssh_port)
                            },
                            &assigned_host,
                            if self.server.ssh_port == 22 {
                                "".into()
                            } else {
                                format!(" -p {}", self.server.ssh_port)
                            },
                        )
                        .into_bytes(),
                    )
                    .await;
                self.server.ssh.insert(
                    assigned_host.clone(),
                    self.peer,
                    Arc::new(SshTunnelHandler::new(
                        handle,
                        self.tx.clone(),
                        self.peer,
                        address,
                        *port,
                    )),
                );
                Ok(true)
            }
            80 | 443 => {
                // Assign HTTP host through config
                let assigned_host = self
                    .address_delegator
                    .get_address(&address, &self.user, &self.key_fingerprint, &self.peer)
                    .await;
                self.http_hosts.insert(assigned_host.clone());
                self.host_addressing
                    .insert((address.clone(), *port), assigned_host.clone());
                println!("Serving HTTP for {} ({})", &assigned_host, self.peer);
                let _ = self
                    .tx
                    .send(
                        format!(
                            "Serving HTTP on http://{}{}\r\n",
                            &assigned_host,
                            match self.server.http_port {
                                80 => "".into(),
                                port => format!(":{}", port),
                            }
                        )
                        .into_bytes(),
                    )
                    .await;
                let _ = self
                    .tx
                    .send(
                        format!(
                            "Serving HTTPS on https://{}{}\r\n",
                            &assigned_host,
                            match self.server.https_port {
                                443 => "".into(),
                                port => format!(":{}", port),
                            }
                        )
                        .into_bytes(),
                    )
                    .await;
                self.server.http.insert(
                    assigned_host.clone(),
                    self.peer,
                    Arc::new(SshTunnelHandler::new(
                        handle,
                        self.tx.clone(),
                        self.peer,
                        address,
                        *port,
                    )),
                );
                Ok(true)
            }
            // Handle TCP
            1..=1024 => Ok(false),
            _ => {
                let assigned_port = if *port == 0 {
                    let assigned_port = self.server.tcp_handler.get_free_port();
                    *port = assigned_port.into();
                    assigned_port
                } else if self.server.tcp_handler.force_random_ports() {
                    self.server.tcp_handler.get_free_port()
                } else {
                    *port as u16
                };
                self.tcp_ports.insert(assigned_port);
                self.port_addressing
                    .insert((address.clone(), *port), assigned_port);
                println!(
                    "Serving TCP port {} for {} ({})",
                    &assigned_port, &address, self.peer
                );
                let _ = self
                    .tx
                    .send(
                        format!(
                            "Serving TCP port on {}:{}\r\n",
                            self.server.domain, &assigned_port,
                        )
                        .into_bytes(),
                    )
                    .await;
                self.server.tcp.insert(
                    assigned_port,
                    self.peer,
                    Arc::new(SshTunnelHandler::new(
                        handle,
                        self.tx.clone(),
                        self.peer,
                        address,
                        *port,
                    )),
                );
                Ok(true)
            }
        }
    }

    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        match port {
            22 => {
                if let Some(assigned_host) =
                    self.host_addressing.remove(&(address.to_string(), port))
                {
                    self.server.ssh.remove(&assigned_host, self.peer);
                    self.ssh_hosts.remove(&assigned_host);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            80 | 443 => {
                if let Some(assigned_host) =
                    self.host_addressing.remove(&(address.to_string(), port))
                {
                    self.server.http.remove(&assigned_host, self.peer);
                    self.http_hosts.remove(&assigned_host);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => {
                if let Some(assigned_port) =
                    self.port_addressing.remove(&(address.to_string(), port))
                {
                    self.server.tcp.remove(&assigned_port, self.peer);
                    self.tcp_ports.remove(&assigned_port);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }

    // TO-DO: Add user-defined authentication mechanism for forwarding (tunneling)
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let port_to_connect = port_to_connect as u16;
        if port_to_connect == self.server.http_port || port_to_connect == self.server.https_port {
            if let Some(handler) = self.server.http.get(host_to_connect) {
                if let Ok(mut io) = handler
                    .tunneling_channel(originator_address, originator_port as u16)
                    .await
                {
                    let mut authentication = self.authentication.lock().await;
                    if *authentication == Authentication::None {
                        *authentication = Authentication::Proxy;
                    };
                    drop(authentication);
                    tokio::spawn(async move {
                        let mut stream = channel.into_stream();
                        let _ = copy_bidirectional(&mut stream, io.inner_mut()).await;
                    });
                    println!(
                        "Accepted connection from {} => {} ({})",
                        self.peer, host_to_connect, handler.peer,
                    );
                    let _ = self
                        .tx
                        .send(format!("Forwarding HTTP from {}\r\n", host_to_connect).into_bytes())
                        .await;
                    return Ok(true);
                }
            }
        } else if port_to_connect == self.server.ssh_port {
            if let Some(handler) = self.server.ssh.get(host_to_connect) {
                if let Ok(mut io) = handler
                    .tunneling_channel(originator_address, originator_port as u16)
                    .await
                {
                    let mut authentication = self.authentication.lock().await;
                    if *authentication == Authentication::None {
                        *authentication = Authentication::Proxy;
                    };
                    drop(authentication);
                    tokio::spawn(async move {
                        let mut stream = channel.into_stream();
                        let _ = copy_bidirectional(&mut stream, io.inner_mut()).await;
                    });
                    println!(
                        "Accepted connection from {} => {} ({})",
                        self.peer, host_to_connect, handler.peer,
                    );
                    let _ = self
                        .tx
                        .send(format!("Forwarding SSH from {}\r\n", host_to_connect).into_bytes())
                        .await;
                    return Ok(true);
                }
            }
        } else if let Some(handler) = self.server.tcp.get(&port_to_connect) {
            if let Ok(mut io) = handler
                .tunneling_channel(originator_address, originator_port as u16)
                .await
            {
                let mut authentication = self.authentication.lock().await;
                if *authentication == Authentication::None {
                    *authentication = Authentication::Proxy;
                };
                drop(authentication);
                tokio::spawn(async move {
                    let mut stream = channel.into_stream();
                    let _ = copy_bidirectional(&mut stream, io.inner_mut()).await;
                });
                println!(
                    "Accepted connection from {} => {} ({})",
                    self.peer, host_to_connect, handler.peer,
                );
                let _ = self
                    .tx
                    .send(format!("Forwarding TCP from {}\r\n", host_to_connect).into_bytes())
                    .await;
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl Drop for ServerHandler {
    fn drop(&mut self) {
        for host in self.ssh_hosts.iter() {
            self.server.ssh.remove(host, self.peer);
        }
        for host in self.http_hosts.iter() {
            self.server.http.remove(host, self.peer);
        }
        for port in self.tcp_ports.iter() {
            self.server.tcp.remove(port, self.peer);
        }
    }
}
