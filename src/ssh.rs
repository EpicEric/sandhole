use std::net::SocketAddr;

use crate::{HttpHandler, Server, ServerHandler};

use async_trait::async_trait;
use russh::{
    server::{Auth, Handler, Msg, Session},
    Channel, ChannelId,
};
use russh_keys::key::PublicKey;
use tokio::{io::AsyncWriteExt, sync::mpsc};

impl russh::server::Server for Server {
    type Handler = ServerHandler;

    fn new_client(&mut self, peer_address: Option<SocketAddr>) -> ServerHandler {
        let (tx, rx) = mpsc::channel(10);
        let peer_address = peer_address.unwrap();
        self.peers.insert(peer_address.clone(), tx.clone());
        ServerHandler {
            peer: peer_address,
            tx,
            rx: Some(rx),
            server: self.clone(),
        }
    }

    fn handle_session_error(&mut self, _error: <Self::Handler as russh::server::Handler>::Error) {
        eprintln!("Session error: {:#?}", _error);
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
            return Err(russh::Error::RequestDenied);
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

    async fn auth_publickey(&mut self, _: &str, _key: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
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
        println!("{} {}", address, port);
        let address = address.to_string();
        let port = *port as u16;
        let handle = session.handle();
        // TO-DO: Handle more than plain HTTP
        if port != 80 {
            return Err(russh::Error::RequestDenied);
        }
        let _ = self
            .tx
            .send(format!("Serving HTTP on {}\n", &address).into_bytes())
            .await;
        self.server.http.insert(
            // TO-DO: Assign HTTP host
            address.clone(),
            HttpHandler {
                handle,
                address,
                port,
            },
        );
        // Send connection info through data channel
        Ok(true)
    }
}
