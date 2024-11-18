use std::{collections::HashMap, net::SocketAddr, sync::Arc};

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
use tokio::{io::AsyncWriteExt, sync::mpsc};

#[derive(Clone)]
pub(crate) struct SshTunnelHandler {
    handle: russh::server::Handle,
    tx: mpsc::Sender<Vec<u8>>,
    address: String,
    port: u32,
}

impl SshTunnelHandler {
    pub(crate) fn new(
        handle: russh::server::Handle,
        tx: mpsc::Sender<Vec<u8>>,
        address: String,
        port: u32,
    ) -> Self {
        SshTunnelHandler {
            handle,
            address,
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
    async fn tunneling_channel(&self) -> anyhow::Result<TokioIo<ChannelStream<Msg>>> {
        let channel = self
            .handle
            .channel_open_forwarded_tcpip(self.address.clone(), self.port, "1.2.3.4", 1234)
            .await?
            .into_stream();
        Ok(TokioIo::new(channel))
    }
}

pub(crate) struct ServerHandler {
    pub(crate) peer: SocketAddr,
    pub(crate) user: Option<String>,
    pub(crate) key_fingerprint: Option<String>,
    pub(crate) tx: mpsc::Sender<Vec<u8>>,
    pub(crate) rx: Option<mpsc::Receiver<Vec<u8>>>,
    pub(crate) hosts: Vec<String>,
    pub(crate) addressing: HashMap<(String, u32), String>,
    pub(crate) address_delegator: Arc<AddressDelegator<DnsResolver>>,
    pub(crate) server: SandholeServer,
}

impl russh::server::Server for SandholeServer {
    type Handler = ServerHandler;

    fn new_client(&mut self, peer_address: Option<SocketAddr>) -> ServerHandler {
        let (tx, rx) = mpsc::channel(32);
        let peer_address = peer_address.unwrap();
        ServerHandler {
            peer: peer_address,
            user: None,
            key_fingerprint: None,
            tx,
            rx: Some(rx),
            hosts: Vec::new(),
            addressing: HashMap::new(),
            address_delegator: Arc::clone(&self.address_delegator),
            server: self.clone(),
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
        let fingerprint = public_key.fingerprint();
        if self
            .server
            .fingerprints_validator
            .is_key_allowed(&fingerprint)
        {
            self.key_fingerprint = Some(fingerprint);
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
        // TO-DO: Handle more than plain HTTP
        if *port == 0 {
            *port = 80;
        } else if *port != 80 {
            return Err(russh::Error::RequestDenied);
        }
        let address = address.to_string();
        let handle = session.handle();
        // Assign HTTP host through config
        let assigned_host = self
            .address_delegator
            .get_address(&address, &self.user, &self.key_fingerprint, &self.peer)
            .await;
        self.hosts.push(assigned_host.clone());
        self.addressing
            .insert((address, *port), assigned_host.clone());
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
                assigned_host,
                *port,
            )),
        );
        // Send connection info through data channel
        Ok(true)
    }

    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // TO-DO: Handle more than plain HTTP
        if port != 80 {
            return Err(russh::Error::RequestDenied);
        }
        if let Some(assigned_host) = self.addressing.remove(&(address.to_string(), port)) {
            // Remove handler from self.server.http
            self.server.http.remove(&assigned_host, self.peer);
            // Remove key from self.hosts
            self.hosts.retain(|host| host != &assigned_host);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl Drop for ServerHandler {
    fn drop(&mut self) {
        for host in self.hosts.iter() {
            self.server.http.remove(host, self.peer);
        }
    }
}
