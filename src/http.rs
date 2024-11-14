use std::{net::SocketAddr, sync::Arc};

use super::{error::ServerError, HttpHandler};
use axum::body::Body;
use axum::response::IntoResponse;
use dashmap::DashMap;
use hyper::header::{HOST, UPGRADE};
use hyper::{body::Incoming, Response};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use rand::seq::SliceRandom;
use tokio::io::copy_bidirectional;

const X_FORWARDED_FOR: &str = "X-Forwarded-For";

pub struct ConnectionMap(DashMap<String, Vec<(SocketAddr, HttpHandler)>>);

impl ConnectionMap {
    pub fn new() -> Self {
        ConnectionMap(DashMap::new())
    }

    pub fn insert(&self, host: String, addr: SocketAddr, handler: HttpHandler) {
        self.0.entry(host).or_default().push((addr, handler));
    }

    pub fn get(&self, host: &str) -> Option<HttpHandler> {
        let mut rng = rand::thread_rng();
        self.0.get(host).and_then(|handler| {
            handler
                .value()
                .as_slice()
                .choose(&mut rng)
                .map(|(_, handler)| handler.clone())
        })
    }

    pub fn remove(&self, host: &str, addr: SocketAddr) {
        self.0.remove_if_mut(host, |_, value| {
            value.retain(|(address, _)| *address != addr);
            value.is_empty()
        });
    }
}

pub async fn proxy_handler(
    mut request: Request<Incoming>,
    tcp_address: SocketAddr,
    conn_manager: Arc<ConnectionMap>,
) -> anyhow::Result<Response<Body>> {
    let host = request
        .headers()
        .get(HOST)
        .ok_or(ServerError::MissingHostHeader)?
        .to_str()?
        .split(':')
        .next()
        .ok_or(ServerError::InvalidHostHeader)?
        .to_owned();
    let Some(HttpHandler {
        handle,
        address,
        port,
    }) = conn_manager.get(&host)
    else {
        return Ok((StatusCode::NOT_FOUND, "").into_response());
    };
    request.headers_mut().insert(
        X_FORWARDED_FOR,
        tcp_address.ip().to_string().parse().unwrap(),
    );

    let channel = handle
        .channel_open_forwarded_tcpip(address, port as u32, "1.2.3.4", 1234)
        .await?
        .into_stream();
    let io = TokioIo::new(channel);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;

    match request.headers().get(UPGRADE) {
        None => {
            tokio::spawn(async move {
                if let Err(err) = conn.await {
                    println!("Connection failed: {:?}", err);
                }
            });
            let method = request.method().to_string();
            let uri = request.uri().to_string();
            let response = sender.send_request(request).await?;
            println!("{} {} {}", response.status().as_u16(), method, uri);
            Ok(response.into_response())
        }

        Some(request_upgrade) => {
            tokio::spawn(async move {
                if let Err(err) = conn.with_upgrades().await {
                    println!("Connection failed: {:?}", err);
                }
            });
            let request_type = request_upgrade.to_str()?.to_string();
            let method = request.method().to_string();
            let uri = request.uri().to_string();
            let upgraded_request = hyper::upgrade::on(&mut request);
            let mut response = sender.send_request(request).await?;
            println!("{} {} {}", response.status().as_u16(), method, uri);
            match response.status() {
                StatusCode::SWITCHING_PROTOCOLS => {
                    if request_type
                        == response
                            .headers()
                            .get(UPGRADE)
                            .ok_or(ServerError::MissingUpgradeHeader)?
                            .to_str()?
                    {
                        let upgraded_response = hyper::upgrade::on(&mut response).await?;
                        tokio::spawn(async move {
                            let mut upgraded_request =
                                TokioIo::new(upgraded_request.await.unwrap());
                            let mut upgraded_response = TokioIo::new(upgraded_response);
                            let _ =
                                copy_bidirectional(&mut upgraded_response, &mut upgraded_request)
                                    .await;
                        });
                    }
                    Ok(response.into_response())
                }
                _ => Ok(response.into_response()),
            }
        }
    }
}
