use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::IntoResponse;
use clap::{command, Parser};
use dashmap::DashMap;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming, Response};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use russh::{
    server::{Auth, Config, Handler, Msg, Server as _, Session},
    Channel, ChannelId,
};
use russh_keys::key::{KeyPair, PublicKey};
use tokio::{io::AsyncWriteExt, net::TcpListener, sync::mpsc};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    address: Option<String>,

    #[arg(long, default_value_t = 2222)]
    ssh_port: u16,

    #[arg(long, default_value_t = 80)]
    http_port: u16,
}

fn get_handler(
    req: &Request<Incoming>,
    map: Arc<DashMap<String, HttpHandler>>,
) -> Result<HttpHandler, Response<Body>> {
    let Some(host) = req.headers().get("host").map(|host| {
        host.to_str()
            .expect("Invalid host header")
            .split(':')
            .next()
            .unwrap()
            .to_owned()
    }) else {
        return Err((StatusCode::BAD_REQUEST, "").into_response());
    };
    let Some(handler) = map.get(&host).map(|details| details.value().clone()) else {
        return Err((StatusCode::NOT_FOUND, "").into_response());
    };
    Ok(handler)
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let config = Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_secs(3),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![KeyPair::generate_ed25519()],
        ..Default::default()
    };
    let config = Arc::new(config);
    let mut sh = Server {
        http: Arc::new(DashMap::new()),
        peers: Arc::new(DashMap::new()),
    };
    let address = args.address.unwrap_or_else(|| "0.0.0.0".into());
    let http_address = address.clone();
    let http_listener = TcpListener::bind((http_address, args.http_port))
        .await
        .expect("Not enough permissions to listen on HTTP port");
    let http_map = Arc::clone(&sh.http);
    tokio::spawn(async move {
        loop {
            let map_clone = http_map.clone();
            let (stream, tcp_address) = http_listener.accept().await.unwrap();
            let service = service_fn(move |mut req: Request<Incoming>| {
                let handler = get_handler(&req, Arc::clone(&map_clone));
                async move {
                    let HttpHandler {
                        handle,
                        address,
                        port,
                    } = match handler {
                        Ok(handler) => handler,
                        Err(response) => {
                            return Ok(response);
                        }
                    };

                    req.headers_mut().insert(
                        "X-Forwarded-For",
                        tcp_address.ip().to_string().parse().unwrap(),
                    );
                    let channel = handle
                        .channel_open_forwarded_tcpip(address, port as u32, "1.2.3.4", 1234)
                        .await
                        .unwrap()
                        .into_stream();
                    let io = TokioIo::new(channel);
                    let (mut sender, conn) =
                        hyper::client::conn::http1::handshake(io).await.unwrap();
                    tokio::spawn(async move {
                        if let Err(err) = conn.await {
                            println!("Connection failed: {:?}", err);
                        }
                    });
                    sender
                        .send_request(req)
                        .await
                        .map(|response| response.into_response())
                }
            });
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let conn = http1::Builder::new()
                    .serve_connection(io, service)
                    .with_upgrades();
                let _ = conn.await;
            });
        }
    });
    sh.run_on_address(config, (address, args.ssh_port))
        .await
        .expect("Not enough permissions to listen on SSH port");
}

#[derive(Clone)]
struct Server {
    http: Arc<DashMap<String, HttpHandler>>,
    peers: Arc<DashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>,
}

#[derive(Clone)]
struct HttpHandler {
    handle: russh::server::Handle,
    address: String,
    port: u16,
}

struct ServerHandler {
    peer: SocketAddr,
    tx: mpsc::Sender<Vec<u8>>,
    rx: Option<mpsc::Receiver<Vec<u8>>>,
    server: Server,
}

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
