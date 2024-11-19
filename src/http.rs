use std::error::Error;
use std::time::{Duration, Instant};
use std::{net::SocketAddr, sync::Arc};

use super::error::ServerError;
use async_trait::async_trait;
use axum::{
    body::Body as AxumBody,
    response::{IntoResponse, Redirect},
};
use dashmap::DashMap;
use hyper::{
    body::Body,
    header::{HOST, UPGRADE},
    Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
#[cfg(test)]
use mockall::automock;
use rand::seq::SliceRandom;
use tokio::{
    io::{copy_bidirectional, AsyncRead, AsyncWrite},
    sync::mpsc,
    time::timeout,
};

const X_FORWARDED_FOR: &str = "X-Forwarded-For";
const X_FORWARDED_HOST: &str = "X-Forwarded-Host";

#[cfg_attr(test, automock)]
#[async_trait]
pub(crate) trait HttpHandler<T: Sync> {
    fn log_channel(&self) -> mpsc::Sender<Vec<u8>>;
    async fn tunneling_channel(&self) -> anyhow::Result<TokioIo<T>>;
}

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
mod connection_map_tests {
    use super::ConnectionMap;

    #[test]
    fn inserts_and_removes_one_handler() {
        let map = ConnectionMap::<usize>::new();
        map.insert("host".into(), "127.0.0.1:1".parse().unwrap(), 1);
        assert_eq!(map.get("host"), Some(1));
        map.remove("host".into(), "127.0.0.1:1".parse().unwrap());
        assert_eq!(map.get("host"), None);
    }

    #[test]
    fn returns_none_for_missing_host() {
        let map = ConnectionMap::<usize>::new();
        map.insert("host".into(), "127.0.0.1:1".parse().unwrap(), 1);
        map.insert("other".into(), "127.0.0.1:2".parse().unwrap(), 2);
        assert_eq!(map.get("unknown"), None);
    }

    #[test]
    fn returns_one_of_several_handlers() {
        let map = ConnectionMap::<usize>::new();
        map.insert("host".into(), "127.0.0.1:1".parse().unwrap(), 1);
        map.insert("host".into(), "127.0.0.1:2".parse().unwrap(), 2);
        map.insert("host".into(), "127.0.0.1:3".parse().unwrap(), 3);
        let mut results: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
        for _ in 0..10_000 {
            let map_item = map.get("host");
            match map_item {
                Some(key @ 1) | Some(key @ 2) | Some(key @ 3) => {
                    *results.entry(key).or_default() += 1;
                }
                unknown => panic!("Unexpected {:?}", unknown),
            }
        }
        assert_eq!(results.len(), 3);
        assert_eq!(
            results.into_iter().fold(0usize, |acc, (_, i)| acc + i),
            10_000
        );
    }
}

fn http_log(
    status: u16,
    method: &str,
    uri: &str,
    elapsed_time: Duration,
    tx: Option<mpsc::Sender<Vec<u8>>>,
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
    // TO-DO: Check from config if we should log back to client
    let _ = tx.map(|tx| tx.try_send(line.into_bytes()));
}

pub(crate) async fn proxy_handler<B, H, T>(
    mut request: Request<B>,
    tcp_address: SocketAddr,
    conn_manager: Arc<ConnectionMap<Arc<H>>>,
    domain_redirect: Arc<(String, String)>,
    redirect_to_https: Option<u16>,
    request_timeout: Duration,
) -> anyhow::Result<Response<AxumBody>>
where
    H: HttpHandler<T>,
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    B: Body + Send + 'static,
    <B as Body>::Data: Send + Sync + 'static,
    <B as Body>::Error: Error + Send + Sync + 'static,
{
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
    let Some(handler) = conn_manager.get(&host) else {
        if &domain_redirect.0 == &host {
            return Ok(Redirect::to(&domain_redirect.1).into_response());
        }
        return Ok((StatusCode::NOT_FOUND, "").into_response());
    };
    if let Some(port) = redirect_to_https {
        let elapsed = timer.elapsed();
        let response = Redirect::permanent(
            format!(
                "https://{}{}{}",
                host,
                if port == 443 {
                    "".into()
                } else {
                    format!(":{port}")
                },
                request
                    .uri()
                    .path_and_query()
                    .map(|path| path.as_str())
                    .unwrap_or("/"),
            )
            .as_str(),
        )
        .into_response();
        http_log(
            response.status().as_u16(),
            request.method().as_str(),
            &request.uri().to_string(),
            elapsed,
            None,
        );
        return Ok(response);
    }
    request.headers_mut().insert(
        X_FORWARDED_FOR,
        tcp_address.ip().to_string().parse().unwrap(),
    );
    request
        .headers_mut()
        .insert(X_FORWARDED_HOST, host.parse().unwrap());

    let io = handler.tunneling_channel().await?;
    let tx = handler.log_channel();
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
            let response = timeout(request_timeout, sender.send_request(request))
                .await
                .map_err(|_| ServerError::RequestTimeout)??;
            let elapsed = timer.elapsed();
            http_log(response.status().as_u16(), &method, &uri, elapsed, Some(tx));
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
            let mut response = timeout(request_timeout, sender.send_request(request))
                .await
                .map_err(|_| ServerError::RequestTimeout)??;
            let elapsed = timer.elapsed();
            http_log(response.status().as_u16(), &method, &uri, elapsed, Some(tx));
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

#[cfg(test)]
mod proxy_handler_tests {
    use bytes::Bytes;
    use futures_util::StreamExt;
    use http_body_util::Empty;
    use hyper::{body::Incoming, service::service_fn, HeaderMap, Request, StatusCode};
    use hyper_util::rt::TokioIo;
    use std::{sync::Arc, time::Duration};
    use tokio::{io::DuplexStream, sync::mpsc};
    use tokio_tungstenite::client_async;
    use tower::Service;

    use super::{proxy_handler, ConnectionMap, MockHttpHandler};

    #[tokio::test]
    async fn errors_on_missing_host_header() {
        let conn_manager: Arc<ConnectionMap<Arc<MockHttpHandler<DuplexStream>>>> =
            Arc::new(ConnectionMap::new());
        let request = Request::builder()
            .method("GET")
            .uri("/index.html")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = proxy_handler(
            request,
            "127.0.0.1:12345".parse().unwrap(),
            Arc::clone(&conn_manager),
            Arc::new(("main.domain".into(), "https://example.com".into())),
            None,
            Duration::from_secs(5),
        )
        .await;
        assert!(response.is_err());
    }

    #[tokio::test]
    async fn returns_not_found_on_missing_handler() {
        let conn_manager: Arc<ConnectionMap<Arc<MockHttpHandler<DuplexStream>>>> =
            Arc::new(ConnectionMap::new());
        let request = Request::builder()
            .method("GET")
            .uri("/index.html")
            .header("host", "no.handler")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = proxy_handler(
            request,
            "127.0.0.1:12345".parse().unwrap(),
            Arc::clone(&conn_manager),
            Arc::new(("main.domain".into(), "https://example.com".into())),
            None,
            Duration::from_secs(5),
        )
        .await;
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.status(), hyper::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn returns_redirect_for_root_domain_and_missing_handler() {
        let conn_manager: Arc<ConnectionMap<Arc<MockHttpHandler<DuplexStream>>>> =
            Arc::new(ConnectionMap::new());
        let request = Request::builder()
            .method("GET")
            .uri("/index.html")
            .header("host", "main.domain")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = proxy_handler(
            request,
            "127.0.0.1:12345".parse().unwrap(),
            Arc::clone(&conn_manager),
            Arc::new(("main.domain".into(), "https://example.com".into())),
            None,
            Duration::from_secs(5),
        )
        .await;
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.status(), hyper::StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get("location").unwrap(),
            "https://example.com"
        );
    }

    #[tokio::test]
    async fn returns_redirect_to_https() {
        let conn_manager: Arc<ConnectionMap<Arc<MockHttpHandler<DuplexStream>>>> =
            Arc::new(ConnectionMap::new());
        let mut mock = MockHttpHandler::new();
        mock.expect_log_channel().never();
        mock.expect_tunneling_channel().never();
        conn_manager.insert(
            "with.handler".into(),
            "127.0.0.1:12345".parse().unwrap(),
            Arc::new(mock),
        );
        let request = Request::builder()
            .method("POST")
            .uri("/api/endpoint")
            .header("host", "with.handler")
            .body(String::from("Hello world"))
            .unwrap();
        let response = proxy_handler(
            request,
            "127.0.0.1:12345".parse().unwrap(),
            Arc::clone(&conn_manager),
            Arc::new(("main.domain".into(), "https://example.com".into())),
            Some(443),
            Duration::from_secs(5),
        )
        .await;
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.status(), hyper::StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            response.headers().get("location").unwrap(),
            "https://with.handler/api/endpoint"
        );
    }

    #[tokio::test]
    async fn returns_redirect_to_non_standard_https_port() {
        let conn_manager: Arc<ConnectionMap<Arc<MockHttpHandler<DuplexStream>>>> =
            Arc::new(ConnectionMap::new());
        let mut mock = MockHttpHandler::new();
        mock.expect_log_channel().never();
        mock.expect_tunneling_channel().never();
        conn_manager.insert(
            "non.standard".into(),
            "127.0.0.1:12345".parse().unwrap(),
            Arc::new(mock),
        );
        let request = Request::builder()
            .method("POST")
            .uri("/test")
            .header("host", "non.standard")
            .body(String::from("Hello world"))
            .unwrap();
        let response = proxy_handler(
            request,
            "127.0.0.1:12345".parse().unwrap(),
            Arc::clone(&conn_manager),
            Arc::new(("main.domain".into(), "https://example.com".into())),
            Some(8443),
            Duration::from_secs(5),
        )
        .await;
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.status(), hyper::StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            response.headers().get("location").unwrap(),
            "https://non.standard:8443/test"
        );
    }

    #[tokio::test]
    async fn returns_response_for_existing_handler() {
        let conn_manager: Arc<ConnectionMap<Arc<MockHttpHandler<DuplexStream>>>> =
            Arc::new(ConnectionMap::new());
        let (server, handler) = tokio::io::duplex(1024);
        let (logging_tx, logging_rx) = mpsc::channel::<Vec<u8>>(1);
        let mut mock = MockHttpHandler::new();
        mock.expect_log_channel()
            .once()
            .return_once(move || logging_tx);
        mock.expect_tunneling_channel()
            .once()
            .return_once(move || Ok(TokioIo::new(handler)));
        conn_manager.insert(
            "with.handler".into(),
            "127.0.0.1:12345".parse().unwrap(),
            Arc::new(mock),
        );
        let request = Request::builder()
            .method("POST")
            .uri("/api/endpoint")
            .header("host", "with.handler")
            .body(String::from("Hello world"))
            .unwrap();
        let router = axum::Router::new()
            .route(
                "/api/endpoint",
                axum::routing::post(|headers: HeaderMap, body: String| async move {
                    if headers.get("X-Forwarded-For").unwrap() == "127.0.0.1"
                        && headers.get("X-Forwarded-Host").unwrap() == "with.handler"
                        && body == "Hello world"
                    {
                        "Success."
                    } else {
                        "Failure."
                    }
                }),
            )
            .into_service();
        let router_service = service_fn(move |req: Request<Incoming>| router.clone().call(req));
        let jh = tokio::spawn(async move {
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(TokioIo::new(server), router_service)
                .await
                .expect("Invalid request");
        });
        assert!(logging_rx.is_empty());
        let response = proxy_handler(
            request,
            "127.0.0.1:12345".parse().unwrap(),
            Arc::clone(&conn_manager),
            Arc::new(("main.domain".into(), "https://example.com".into())),
            None,
            Duration::from_secs(5),
        )
        .await;
        assert!(!logging_rx.is_empty());
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.status(), hyper::StatusCode::OK);
        let body = response.into_body();
        let body = axum::body::to_bytes(body, 32).await.unwrap();
        assert_eq!(body, bytes::Bytes::from("Success."));
        jh.abort();
    }

    #[tokio::test]
    async fn returns_response_for_handler_of_root_domain() {
        let conn_manager: Arc<ConnectionMap<Arc<MockHttpHandler<DuplexStream>>>> =
            Arc::new(ConnectionMap::new());
        let (server, handler) = tokio::io::duplex(1024);
        let (logging_tx, logging_rx) = mpsc::channel::<Vec<u8>>(1);
        let mut mock = MockHttpHandler::new();
        mock.expect_log_channel()
            .once()
            .return_once(move || logging_tx);
        mock.expect_tunneling_channel()
            .once()
            .return_once(move || Ok(TokioIo::new(handler)));
        conn_manager.insert(
            "root.domain".into(),
            "127.0.0.1:12345".parse().unwrap(),
            Arc::new(mock),
        );
        let request = Request::builder()
            .method("POST")
            .uri("/test")
            .header("host", "root.domain")
            .body(String::from("My body"))
            .unwrap();
        let router = axum::Router::new()
            .route(
                "/test",
                axum::routing::post(|headers: HeaderMap, body: String| async move {
                    if headers.get("X-Forwarded-For").unwrap() == "192.168.0.1"
                        && headers.get("X-Forwarded-Host").unwrap() == "root.domain"
                        && body == "My body"
                    {
                        "Success."
                    } else {
                        "Failure."
                    }
                }),
            )
            .into_service();
        let router_service = service_fn(move |req: Request<Incoming>| router.clone().call(req));
        let jh = tokio::spawn(async move {
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(TokioIo::new(server), router_service)
                .await
                .expect("Invalid request");
        });
        assert!(logging_rx.is_empty());
        let response = proxy_handler(
            request,
            "192.168.0.1:12345".parse().unwrap(),
            Arc::clone(&conn_manager),
            Arc::new(("root.domain".into(), "https://this.is.ignored".into())),
            None,
            Duration::from_secs(5),
        )
        .await;
        assert!(!logging_rx.is_empty());
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.status(), hyper::StatusCode::OK);
        let body = response.into_body();
        let body = axum::body::to_bytes(body, 32).await.unwrap();
        assert_eq!(body, bytes::Bytes::from("Success."));
        jh.abort();
    }

    #[tokio::test]
    async fn returns_websocket_upgrade_for_existing_handler() {
        let conn_manager: Arc<ConnectionMap<Arc<MockHttpHandler<DuplexStream>>>> =
            Arc::new(ConnectionMap::new());
        let (server, handler) = tokio::io::duplex(1024);
        let (logging_tx, logging_rx) = mpsc::channel::<Vec<u8>>(1);
        let mut mock = MockHttpHandler::new();
        mock.expect_log_channel()
            .once()
            .return_once(move || logging_tx);
        mock.expect_tunneling_channel()
            .once()
            .return_once(move || Ok(TokioIo::new(handler)));
        conn_manager.insert(
            "with.websocket".into(),
            "127.0.0.1:12345".parse().unwrap(),
            Arc::new(mock),
        );
        let (socket, stream) = tokio::io::duplex(1024);
        let router = axum::Router::new()
            .route(
                "/ws",
                axum::routing::any(|ws: axum::extract::WebSocketUpgrade| async move {
                    ws.on_upgrade(|mut socket| async move {
                        let _ = socket
                            .send(axum::extract::ws::Message::Text("Success.".into()))
                            .await;
                        let _ = socket.close().await;
                    })
                }),
            )
            .into_service();
        let router_service = service_fn(move |req: Request<Incoming>| router.clone().call(req));
        let jh = tokio::spawn(async move {
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(server), router_service)
                .await
                .expect("Invalid request");
        });
        assert!(logging_rx.is_empty());
        let proxy_service = service_fn(move |request| {
            proxy_handler(
                request,
                "127.0.0.1:12345".parse().unwrap(),
                Arc::clone(&conn_manager),
                Arc::new(("main.domain".into(), "https://example.com".into())),
                None,
                Duration::from_secs(5),
            )
        });
        let jh2 = tokio::spawn(async move {
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(socket), proxy_service)
                .await
                .expect("Invalid request");
        });
        let (mut websocket, response) = client_async("ws://with.websocket/ws", stream)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(
            websocket
                .next()
                .await
                .unwrap()
                .unwrap()
                .into_text()
                .unwrap(),
            "Success."
        );
        jh.abort();
        jh2.abort();
    }
}
