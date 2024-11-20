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
    sync::mpsc,
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
        // TO-DO: Fix fields
        let channel = self
            .handle
            .channel_open_forwarded_tcpip(self.address.clone(), self.port, ip, port.into())
            .await?
            .into_stream();
        Ok(TokioIo::new(channel))
    }
}

// TO-DO: Optimize memory usage
pub(crate) struct ServerHandler {
    pub(crate) peer: SocketAddr,
    pub(crate) user: Option<String>,
    pub(crate) key_fingerprint: Option<String>,
    pub(crate) tx: mpsc::Sender<Vec<u8>>,
    pub(crate) rx: Option<mpsc::Receiver<Vec<u8>>>,
    pub(crate) ssh_hosts: HashSet<String>,
    pub(crate) http_hosts: HashSet<String>,
    pub(crate) tcp_ports: HashSet<u16>,
    pub(crate) host_addressing: HashMap<(String, u32), String>,
    pub(crate) port_addressing: HashMap<(String, u32), u16>,
    pub(crate) address_delegator: Arc<AddressDelegator<DnsResolver>>,
    pub(crate) server: Arc<SandholeServer>,
}

pub(crate) trait Server {
    fn new_client(&mut self, peer_address: Option<SocketAddr>) -> ServerHandler;
}

impl Server for Arc<SandholeServer> {
    fn new_client(&mut self, peer_address: Option<SocketAddr>) -> ServerHandler {
        let (tx, rx) = mpsc::channel(32);
        let peer_address = peer_address.unwrap();
        ServerHandler {
            peer: peer_address,
            user: None,
            key_fingerprint: None,
            tx,
            rx: Some(rx),
            ssh_hosts: HashSet::new(),
            http_hosts: HashSet::new(),
            tcp_ports: HashSet::new(),
            host_addressing: HashMap::new(),
            port_addressing: HashMap::new(),
            address_delegator: Arc::clone(&self.address_delegator),
            server: Arc::clone(&self),
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
        if self
            .server
            .fingerprints_validator
            .is_key_allowed(public_key)
        {
            self.key_fingerprint = Some(public_key.fingerprint());
            self.user = Some(user.to_string());
            Ok(Auth::Accept)
        } else {
            Ok(Auth::Reject {
                proceed_with_methods: None,
            })
        }
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Sending Ctrl+C ends the session and disconnects the client
        if data == [3] {
            return Err(russh::Error::Disconnect);
        }
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
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
                            "Serving SSH on http://{}{}\r\n",
                            &assigned_host,
                            match self.server.http_port {
                                80 => "".into(),
                                port => format!(":{}", port),
                            }
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
            80 => {
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
            // TO-DO: Handle TCP (special cases: 0, 443)
            _ => Err(russh::Error::RequestDenied),
        }
    }

    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // TO-DO: Handle more than HTTP
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
            80 => {
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
            // TO-DO: Handle TCP (special cases: 0, 443)
            _ => Err(russh::Error::RequestDenied),
        }
    }

    // TO-DO: Add proper authentication for forwarding
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
                    .tunneling_channel(&originator_address, originator_port as u16)
                    .await
                {
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
                    .tunneling_channel(&originator_address, originator_port as u16)
                    .await
                {
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
                .tunneling_channel(&originator_address, originator_port as u16)
                .await
            {
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
    }
}
