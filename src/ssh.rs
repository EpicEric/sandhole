use std::net::SocketAddr;

use crate::{HttpHandler, Server, CONFIG};

use async_trait::async_trait;
use russh::{
    server::{Auth, Handler, Msg, Session},
    Channel, ChannelId, MethodSet,
};
use russh_keys::key::PublicKey;
use tokio::{io::AsyncWriteExt, sync::mpsc};

impl russh::server::Server for Server {
    type Handler = ServerHandler;

    fn new_client(&mut self, peer_address: Option<SocketAddr>) -> ServerHandler {
        let (tx, rx) = mpsc::channel(10);
        let peer_address = peer_address.unwrap();
        ServerHandler {
            peer: peer_address,
            tx,
            rx: Some(rx),
            server: self.clone(),
            hosts: Vec::new(),
        }
    }
}

// TODO: impl Drop to handle disconnection
pub struct ServerHandler {
    pub peer: SocketAddr,
    pub tx: mpsc::Sender<Vec<u8>>,
    pub rx: Option<mpsc::Receiver<Vec<u8>>>,
    pub hosts: Vec<String>,
    pub server: Server,
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
        _user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        if self
            .server
            .allowed_key_fingerprints
            .contains(&public_key.fingerprint())
        {
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
        // TO-DO: Assign HTTP host through config
        let key = address.clone();
        self.hosts.push(key.clone());
        let _ = self
            .tx
            .send(
                format!(
                    "Serving HTTP on http://{}:{}\n",
                    &key,
                    CONFIG.get().unwrap().http_port
                )
                .into_bytes(),
            )
            .await;
        self.server.http.insert(
            key,
            self.peer,
            HttpHandler {
                handle,
                address,
                port: *port as u16,
            },
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
        // Remove handler from self.server.http
        let key = address;
        self.server.http.remove(key, self.peer);
        // Remove key from self.hosts
        self.hosts.retain(|host| host != key);
        Ok(true)
    }
}

impl Drop for ServerHandler {
    fn drop(&mut self) {
        for host in self.hosts.iter() {
            self.server.http.remove(host, self.peer);
        }
    }
}
