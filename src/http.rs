use std::time::{Duration, Instant};
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
use tokio::sync::mpsc;

const X_FORWARDED_FOR: &str = "X-Forwarded-For";

pub(crate) struct ConnectionMap<H>(DashMap<String, Vec<(SocketAddr, H)>>);

impl<H: Clone> ConnectionMap<H> {
    pub(crate) fn new() -> Self {
        ConnectionMap(DashMap::new())
    }

    pub(crate) fn insert(&self, host: String, addr: SocketAddr, handler: H) {
        self.0.entry(host).or_default().push((addr, handler));
    }

    pub(crate) fn get(&self, host: &str) -> Option<H> {
        let mut rng = rand::thread_rng();
        self.0.get(host).and_then(|handler| {
            handler
                .value()
                .as_slice()
                .choose(&mut rng)
                .map(|(_, handler)| handler.clone())
        })
    }

    pub(crate) fn remove(&self, host: &str, addr: SocketAddr) {
        self.0.remove_if_mut(host, |_, value| {
            value.retain(|(address, _)| *address != addr);
            value.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::ConnectionMap;

    #[test]
    fn connection_map_inserts_and_removes_one_handler() {
        let map = ConnectionMap::<usize>::new();
        map.insert("host".into(), "127.0.0.1:1".parse().unwrap(), 1);
        assert_eq!(map.get("host"), Some(1));
        map.remove("host".into(), "127.0.0.1:1".parse().unwrap());
        assert_eq!(map.get("host"), None);
    }

    #[test]
    fn connection_map_returns_none_for_missing_host() {
        let map = ConnectionMap::<usize>::new();
        map.insert("host".into(), "127.0.0.1:1".parse().unwrap(), 1);
        map.insert("other".into(), "127.0.0.1:2".parse().unwrap(), 2);
        assert_eq!(map.get("unknown"), None);
    }

    #[test]
    fn connection_map_returns_one_of_several_handlers() {
        let map = ConnectionMap::<usize>::new();
        map.insert("host".into(), "127.0.0.1:1".parse().unwrap(), 1);
        map.insert("host".into(), "127.0.0.1:2".parse().unwrap(), 2);
        for _ in 0..100 {
            assert!(matches!(map.get("host"), Some(1) | Some(2)));
        }
    }
}

fn http_log(
    status: u16,
    method: String,
    uri: String,
    elapsed_time: Duration,
    tx: mpsc::Sender<Vec<u8>>,
) {
    let status_escape_color = match status {
        100..=199 => "\x1b[37m",
        200..=299 => "\x1b[34m",
        300..=399 => "\x1b[32m",
        400..=499 => "\x1b[33m",
        500..=599 => "\x1b[31m",
        _ => unreachable!(),
    };
    let line = format!(
        "\x1b[2m{:19}\x1b[22m {}[{:3}] \x1b[0;1;44m{:^7}\x1b[0m {} \x1b[2m{}\x1b[0m\r\n",
        chrono::Local::now().format("%Y-%m-%dT%H:%M:%S"),
        status_escape_color,
        status,
        method,
        uri,
        pretty_duration::pretty_duration(&elapsed_time, None)
    );
    print!("{}", line);
    let _ = tx.try_send(line.into_bytes());
}

pub async fn proxy_handler(
    mut request: Request<Incoming>,
    tcp_address: SocketAddr,
    conn_manager: Arc<ConnectionMap<HttpHandler>>,
) -> anyhow::Result<Response<Body>> {
    let timer = Instant::now();
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
        tx,
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

    let method = request.method().to_string();
    let uri = request.uri().to_string();
    match request.headers().get(UPGRADE) {
        None => {
            tokio::spawn(async move {
                if let Err(err) = conn.await {
                    println!("Connection failed: {:?}", err);
                }
            });
            let response = sender.send_request(request).await?;
            let elapsed = timer.elapsed();
            http_log(response.status().as_u16(), method, uri, elapsed, tx);
            Ok(response.into_response())
        }

        Some(request_upgrade) => {
            tokio::spawn(async move {
                if let Err(err) = conn.with_upgrades().await {
                    println!("Connection failed: {:?}", err);
                }
            });
            let request_type = request_upgrade.to_str()?.to_string();
            let upgraded_request = hyper::upgrade::on(&mut request);
            let mut response = sender.send_request(request).await?;
            let elapsed = timer.elapsed();
            http_log(response.status().as_u16(), method, uri, elapsed, tx);
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
