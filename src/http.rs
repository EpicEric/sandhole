use std::error::Error;
use std::marker::PhantomData;
use std::time::{Duration, Instant};
use std::{net::SocketAddr, sync::Arc};

use crate::connection_handler::ConnectionHandler;
use crate::connections::ConnectionGetByHttpHost;
use crate::tcp_alias::TcpAlias;
use crate::telemetry::Telemetry;

use super::error::ServerError;
use axum::{
    body::Body as AxumBody,
    response::{IntoResponse, Redirect},
};
use hyper::{
    body::Body,
    header::{HOST, UPGRADE},
    Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use log::warn;
use ssh_key::Fingerprint;
use tokio::{
    io::{copy_bidirectional, AsyncRead, AsyncWrite},
    sync::mpsc,
    time::timeout,
};

const X_FORWARDED_FOR: &str = "X-Forwarded-For";
const X_FORWARDED_HOST: &str = "X-Forwarded-Host";
const X_FORWARDED_PROTO: &str = "X-Forwarded-Proto";
const X_FORWARDED_PORT: &str = "X-Forwarded-Port";

struct HttpLog<'a> {
    ip: &'a str,
    status: u16,
    method: &'a str,
    host: &'a str,
    uri: &'a str,
    elapsed_time: Duration,
}

fn http_log(data: HttpLog, tx: Option<mpsc::UnboundedSender<Vec<u8>>>, disable_http_logs: bool) {
    let HttpLog {
        ip,
        status,
        method,
        host,
        uri,
        elapsed_time,
    } = data;
    let status_escape_color = match status {
        100..=199 => "37",
        200..=299 => "34",
        300..=399 => "32",
        400..=499 => "33",
        500..=599 => "31",
        _ => unreachable!(),
    };
    let method_escape_color = match method {
        "POST" => "42",
        "PUT" => "43",
        "DELETE" => "41",
        "HEAD" => "46",
        "OPTIONS" => "45",
        "CONNECT" => "45",
        "PATCH" => "43",
        "TRACE" => "45",
        // GET or other
        _ => "44",
    };
    let line = format!(
        " \x1b[2m{:19}\x1b[22m \x1b[{}m[{:3}] \x1b[0;1;30;{}m{:^7}\x1b[0m {} => {} \x1b[2m({}) {}\x1b[0m\r\n",
        chrono::Local::now().format("%Y-%m-%dT%H:%M:%S"),
        status_escape_color,
        status,
        method_escape_color,
        method,
        host,
        uri,
        ip,
        pretty_duration::pretty_duration(&elapsed_time, None)
    );
    print!("{}", line);
    if !disable_http_logs {
        let _ = tx.map(|tx| tx.send(line.into_bytes()));
    }
}

pub(crate) enum Protocol {
    Http { port: u16 },
    TlsRedirect { from: u16, to: u16 },
    Https { port: u16 },
}

pub(crate) struct DomainRedirect {
    pub(crate) from: String,
    pub(crate) to: String,
}

pub(crate) enum ProxyType {
    Tunneling,
    Aliasing,
}

// Data commonly reused between HTTP proxy requests.
pub(crate) struct ProxyData<M, H, T>
where
    M: ConnectionGetByHttpHost<Arc<H>>,
    H: ConnectionHandler<T>,
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    // An HTTP connection manager (usually ConnectionMap) that returns a tunneling/aliasing handler.
    pub(crate) conn_manager: M,
    // Telemetry service, where HTTP requests are tracked.
    pub(crate) telemetry: Arc<Telemetry>,
    // Tuple containing where to redirect requests from the main domain to.
    pub(crate) domain_redirect: Arc<DomainRedirect>,
    // The HTTP protocol for the current connection.
    pub(crate) protocol: Protocol,
    // Configuration on which type of channel to retrieve from the handler.
    pub(crate) proxy_type: ProxyType,
    // Duration until an outgoing request is canceled.
    pub(crate) http_request_timeout: Duration,
    // Optional duration until an established Websocket connection is canceled.
    pub(crate) websocket_timeout: Option<Duration>,
    // If set, disables sending HTTP logs to the handler.
    pub(crate) disable_http_logs: bool,
    pub(crate) _phantom_data: PhantomData<(H, T)>,
}

// Receive an HTTP request and appropriately proxy it, with a possible upgrade to WebSocket.
pub(crate) async fn proxy_handler<B, M, H, T>(
    mut request: Request<B>,
    tcp_address: SocketAddr,
    fingerprint: Option<Fingerprint>,
    proxy_data: Arc<ProxyData<M, H, T>>,
) -> anyhow::Result<Response<AxumBody>>
where
    M: ConnectionGetByHttpHost<Arc<H>>,
    H: ConnectionHandler<T>,
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    B: Body + Send + 'static,
    <B as Body>::Data: Send + Sync + 'static,
    <B as Body>::Error: Error + Send + Sync + 'static,
{
    let conn_manager = &proxy_data.conn_manager;
    let telemetry = &proxy_data.telemetry;
    let domain_redirect = &proxy_data.domain_redirect;
    let protocol = &proxy_data.protocol;
    let disable_http_logs = proxy_data.disable_http_logs;
    let timer = Instant::now();
    // Retrieve host from the headers
    let host = request
        .headers()
        .get(HOST)
        .ok_or(ServerError::MissingHostHeader)?
        .to_str()?
        .split(':')
        .next()
        .ok_or(ServerError::InvalidHostHeader)?
        .to_owned();
    let ip = tcp_address.ip().to_canonical().to_string();
    // Find the HTTP handler for the given host
    let Some(handler) = conn_manager.get_by_http_host(&host) else {
        // If no handler was found, check if this is a request to the root domain
        if domain_redirect.from == host {
            // If so, redirect to the configured URL
            let elapsed_time = timer.elapsed();
            let response = Redirect::to(&domain_redirect.to).into_response();
            http_log(
                HttpLog {
                    ip: &ip,
                    status: response.status().as_u16(),
                    method: request.method().as_str(),
                    host: &host,
                    uri: request.uri().path(),
                    elapsed_time,
                },
                None,
                disable_http_logs,
            );
            return Ok(response);
        }
        // No handler was found, return 404
        return Ok((StatusCode::NOT_FOUND, "").into_response());
    };
    let http_data = handler.http_data().await;
    let redirect_http_to_https_port = http_data
        .as_ref()
        .and_then(|data| data.redirect_http_to_https_port);
    // Read protocol information for X-Forwarded headers
    let (proto, port) = match (
        protocol,
        redirect_http_to_https_port.as_ref(),
        &proxy_data.proxy_type,
    ) {
        // If force-https is true, redirect this HTTP request to HTTPS
        (Protocol::Http { .. }, Some(to_port), ProxyType::Tunneling)
        | (Protocol::TlsRedirect { to: to_port, .. }, _, ProxyType::Tunneling) => {
            let elapsed_time = timer.elapsed();
            let response = Redirect::permanent(
                format!(
                    "https://{}:{}{}",
                    host,
                    to_port,
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
                HttpLog {
                    ip: &ip,
                    status: response.status().as_u16(),
                    method: request.method().as_str(),
                    host: &host,
                    uri: request.uri().path(),
                    elapsed_time,
                },
                None,
                disable_http_logs,
            );
            return Ok(response);
        }
        (Protocol::Http { port }, _, _)
        | (Protocol::TlsRedirect { from: port, .. }, _, ProxyType::Aliasing) => ("http", *port),
        (Protocol::Https { port }, _, _) => ("https", *port),
    };
    // Add proxied info to the proper headers
    request
        .headers_mut()
        .insert(X_FORWARDED_FOR, ip.parse().unwrap());
    request
        .headers_mut()
        .insert(X_FORWARDED_HOST, host.parse().unwrap());
    request
        .headers_mut()
        .insert(X_FORWARDED_PROTO, proto.parse().unwrap());
    request
        .headers_mut()
        .insert(X_FORWARDED_PORT, port.to_string().parse().unwrap());
    // Add this request to the telemetry for the host
    if http_data.as_ref().is_some_and(|data| data.is_aliasing) {
        telemetry.add_alias_connection(TcpAlias(host.clone(), port));
    } else {
        telemetry.add_http_request(host.clone());
    }

    // Find the appropriate handler for this proxy type
    let Ok(io) = (match proxy_data.proxy_type {
        ProxyType::Tunneling => {
            handler
                .tunneling_channel(tcp_address.ip(), tcp_address.port())
                .await
        }
        ProxyType::Aliasing => {
            handler
                .aliasing_channel(tcp_address.ip(), tcp_address.port(), fingerprint.as_ref())
                .await
        }
    }) else {
        // If getting the handler failed, return 404 (they may have an allowlist for fingerprints/IP networks)
        return Ok((StatusCode::NOT_FOUND, "").into_response());
    };
    let tx = handler.log_channel();
    // Create an HTTP handshake over the selected channel
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;

    let method = request.method().to_string();
    let uri = request.uri().path().to_string();
    // Check for an Upgrade header
    match request.headers().get(UPGRADE) {
        // If not present, handle the request as usual
        None => {
            tokio::spawn(async move {
                if let Err(err) = conn.await {
                    warn!("Connection failed: {:?}", err);
                }
            });
            // Await for a response under the given duration.
            let response = timeout(
                proxy_data.http_request_timeout,
                sender.send_request(request),
            )
            .await
            .map_err(|_| ServerError::RequestTimeout)??;
            let elapsed_time = timer.elapsed();
            http_log(
                HttpLog {
                    ip: &ip,
                    status: response.status().as_u16(),
                    method: &method,
                    host: &host,
                    uri: &uri,
                    elapsed_time,
                },
                tx,
                disable_http_logs,
            );
            // Return the received response to the client
            Ok(response.into_response())
        }

        // If there is an Upgrade header, make sure that it's a valid Websocket upgrade.
        Some(request_upgrade) => {
            tokio::spawn(async move {
                if let Err(err) = conn.with_upgrades().await {
                    warn!("Connection failed: {:?}", err);
                }
            });
            let request_type = request_upgrade.to_str()?.to_string();
            // Retrieve the OnUpgrade from the incoming request
            let upgraded_request = hyper::upgrade::on(&mut request);
            // Await for a response under the given duration.
            let mut response = timeout(
                proxy_data.http_request_timeout,
                sender.send_request(request),
            )
            .await
            .map_err(|_| ServerError::RequestTimeout)??;
            let elapsed_time = timer.elapsed();
            http_log(
                HttpLog {
                    ip: &ip,
                    status: response.status().as_u16(),
                    method: &method,
                    host: &host,
                    uri: &uri,
                    elapsed_time,
                },
                tx,
                disable_http_logs,
            );
            // Check if the underlying server accepts the Upgrade request
            match response.status() {
                StatusCode::SWITCHING_PROTOCOLS => {
                    if request_type
                        == response
                            .headers()
                            .get(UPGRADE)
                            .ok_or(ServerError::MissingUpgradeHeader)?
                            .to_str()?
                    {
                        // Retrieve the upgraded connection from the response
                        let upgraded_response = hyper::upgrade::on(&mut response).await?;
                        let websocket_timeout = proxy_data.websocket_timeout;
                        // Start a task to copy data between the two Upgraded parts
                        tokio::spawn(async move {
                            let mut upgraded_request =
                                TokioIo::new(upgraded_request.await.unwrap());
                            let mut upgraded_response = TokioIo::new(upgraded_response);
                            match websocket_timeout {
                                // If there is a Websocket timeout, copy until the deadline is reached.
                                Some(duration) => {
                                    let _ = timeout(duration, async {
                                        copy_bidirectional(
                                            &mut upgraded_response,
                                            &mut upgraded_request,
                                        )
                                        .await
                                    })
                                    .await;
                                }
                                // If there isn't a Websocket timeout, copy data between both sides unconditionally.
                                None => {
                                    let _ = copy_bidirectional(
                                        &mut upgraded_response,
                                        &mut upgraded_request,
                                    )
                                    .await;
                                }
                            }
                        });
                    }
                    // Return the response to the client
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
    use std::{marker::PhantomData, sync::Arc, time::Duration};
    use tokio::{io::DuplexStream, sync::mpsc};
    use tokio_tungstenite::client_async;
    use tower::Service;

    use crate::{
        config::LoadBalancing,
        connection_handler::{ConnectionHttpData, MockConnectionHandler},
        connections::ConnectionMap,
        quota::{DummyQuotaHandler, TokenHolder, UserIdentification},
        reactor::MockConnectionMapReactor,
        telemetry::Telemetry,
    };

    use super::{proxy_handler, DomainRedirect, Protocol, ProxyData, ProxyType};

    #[tokio::test]
    async fn errors_on_missing_host_header() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(ConnectionMap::new(
            LoadBalancing::Allow,
            Arc::new(Box::new(DummyQuotaHandler)),
            None,
        ));
        let request = Request::builder()
            .method("GET")
            .uri("/index.html")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = proxy_handler(
            request,
            "127.0.0.1:12345".parse().unwrap(),
            None,
            Arc::new(ProxyData {
                conn_manager: Arc::clone(&conn_manager),
                telemetry: Arc::new(Telemetry::new()),
                domain_redirect: Arc::new(DomainRedirect {
                    from: "main.domain".into(),
                    to: "https://example.com".into(),
                }),
                protocol: Protocol::Http { port: 80 },
                proxy_type: ProxyType::Tunneling,
                http_request_timeout: Duration::from_secs(5),
                websocket_timeout: None,
                disable_http_logs: false,
                _phantom_data: PhantomData,
            }),
        )
        .await;
        assert!(response.is_err(), "should error on missing host header");
    }

    #[tokio::test]
    async fn returns_not_found_on_missing_handler() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(ConnectionMap::new(
            LoadBalancing::Allow,
            Arc::new(Box::new(DummyQuotaHandler)),
            None,
        ));
        let request = Request::builder()
            .method("GET")
            .uri("/index.html")
            .header("host", "no.handler")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = proxy_handler(
            request,
            "127.0.0.1:12345".parse().unwrap(),
            None,
            Arc::new(ProxyData {
                conn_manager: Arc::clone(&conn_manager),
                telemetry: Arc::new(Telemetry::new()),
                domain_redirect: Arc::new(DomainRedirect {
                    from: "main.domain".into(),
                    to: "https://example.com".into(),
                }),
                protocol: Protocol::Http { port: 80 },
                proxy_type: ProxyType::Tunneling,
                http_request_timeout: Duration::from_secs(5),
                websocket_timeout: None,
                disable_http_logs: false,
                _phantom_data: PhantomData,
            }),
        )
        .await;
        assert!(response.is_ok(), "should return response when not found");
        let response = response.unwrap();
        assert_eq!(response.status(), hyper::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn returns_redirect_for_root_domain_and_missing_handler() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(ConnectionMap::new(
            LoadBalancing::Allow,
            Arc::new(Box::new(DummyQuotaHandler)),
            None,
        ));
        let request = Request::builder()
            .method("GET")
            .uri("/index.html")
            .header("host", "main.domain")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = proxy_handler(
            request,
            "127.0.0.1:12345".parse().unwrap(),
            None,
            Arc::new(ProxyData {
                conn_manager: Arc::clone(&conn_manager),
                telemetry: Arc::new(Telemetry::new()),
                domain_redirect: Arc::new(DomainRedirect {
                    from: "main.domain".into(),
                    to: "https://example.com".into(),
                }),
                protocol: Protocol::Http { port: 80 },
                proxy_type: ProxyType::Tunneling,
                http_request_timeout: Duration::from_secs(5),
                websocket_timeout: None,
                disable_http_logs: false,
                _phantom_data: PhantomData,
            }),
        )
        .await;
        assert!(response.is_ok(), "should return response when redirect");
        let response = response.unwrap();
        assert_eq!(response.status(), hyper::StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get("location").unwrap(),
            "https://example.com"
        );
    }

    #[tokio::test]
    async fn returns_redirect_to_https_from_global_config() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(ConnectionMap::new(
            LoadBalancing::Allow,
            Arc::new(Box::new(DummyQuotaHandler)),
            None,
        ));
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel().never();
        mock.expect_tunneling_channel().never();
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
            })
        });
        conn_manager
            .insert(
                "with.handler".into(),
                "127.0.0.1:12345".parse().unwrap(),
                TokenHolder::User(UserIdentification::Username("a".into())),
                Arc::new(mock),
            )
            .unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/endpoint")
            .header("host", "with.handler")
            .body(String::from("Hello world"))
            .unwrap();
        let response = proxy_handler(
            request,
            "127.0.0.1:12345".parse().unwrap(),
            None,
            Arc::new(ProxyData {
                conn_manager: Arc::clone(&conn_manager),
                telemetry: Arc::new(Telemetry::new()),
                domain_redirect: Arc::new(DomainRedirect {
                    from: "main.domain".into(),
                    to: "https://example.com".into(),
                }),
                protocol: Protocol::TlsRedirect { from: 80, to: 443 },
                proxy_type: ProxyType::Tunneling,
                http_request_timeout: Duration::from_secs(5),
                websocket_timeout: None,
                disable_http_logs: false,
                _phantom_data: PhantomData,
            }),
        )
        .await;
        assert!(
            response.is_ok(),
            "should return response when HTTPS redirect"
        );
        let response = response.unwrap();
        assert_eq!(response.status(), hyper::StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            response.headers().get("location").unwrap(),
            "https://with.handler:443/api/endpoint"
        );
    }

    #[tokio::test]
    async fn returns_redirect_to_non_standard_https_port_from_global_config() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(ConnectionMap::new(
            LoadBalancing::Allow,
            Arc::new(Box::new(DummyQuotaHandler)),
            None,
        ));
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel().never();
        mock.expect_tunneling_channel().never();
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
            })
        });
        conn_manager
            .insert(
                "non.standard".into(),
                "127.0.0.1:12345".parse().unwrap(),
                TokenHolder::User(UserIdentification::Username("a".into())),
                Arc::new(mock),
            )
            .unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/test")
            .header("host", "non.standard")
            .body(String::from("Hello world"))
            .unwrap();
        let response = proxy_handler(
            request,
            "127.0.0.1:12345".parse().unwrap(),
            None,
            Arc::new(ProxyData {
                conn_manager: Arc::clone(&conn_manager),
                telemetry: Arc::new(Telemetry::new()),
                domain_redirect: Arc::new(DomainRedirect {
                    from: "main.domain".into(),
                    to: "https://example.com".into(),
                }),
                protocol: Protocol::TlsRedirect { from: 80, to: 8443 },
                proxy_type: ProxyType::Tunneling,
                http_request_timeout: Duration::from_secs(5),
                websocket_timeout: None,
                disable_http_logs: false,
                _phantom_data: PhantomData,
            }),
        )
        .await;
        assert!(
            response.is_ok(),
            "should return response whyen HTTPS redirect to non-standard port"
        );
        let response = response.unwrap();
        assert_eq!(response.status(), hyper::StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            response.headers().get("location").unwrap(),
            "https://non.standard:8443/test"
        );
    }

    #[tokio::test]
    async fn returns_redirect_to_https_from_connection_data() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(ConnectionMap::new(
            LoadBalancing::Allow,
            Arc::new(Box::new(DummyQuotaHandler)),
            None,
        ));
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel().never();
        mock.expect_tunneling_channel().never();
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: Some(443),
                is_aliasing: false,
            })
        });
        conn_manager
            .insert(
                "with.handler".into(),
                "127.0.0.1:12345".parse().unwrap(),
                TokenHolder::User(UserIdentification::Username("a".into())),
                Arc::new(mock),
            )
            .unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/endpoint")
            .header("host", "with.handler")
            .body(String::from("Hello world"))
            .unwrap();
        let response = proxy_handler(
            request,
            "127.0.0.1:12345".parse().unwrap(),
            None,
            Arc::new(ProxyData {
                conn_manager: Arc::clone(&conn_manager),
                telemetry: Arc::new(Telemetry::new()),
                domain_redirect: Arc::new(DomainRedirect {
                    from: "main.domain".into(),
                    to: "https://example.com".into(),
                }),
                protocol: Protocol::Http { port: 80 },
                proxy_type: ProxyType::Tunneling,
                http_request_timeout: Duration::from_secs(5),
                websocket_timeout: None,
                disable_http_logs: false,
                _phantom_data: PhantomData,
            }),
        )
        .await;
        assert!(
            response.is_ok(),
            "should return response when HTTPS redirect"
        );
        let response = response.unwrap();
        assert_eq!(response.status(), hyper::StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            response.headers().get("location").unwrap(),
            "https://with.handler:443/api/endpoint"
        );
    }

    #[tokio::test]
    async fn returns_redirect_to_non_standard_https_port_from_connection_data() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(ConnectionMap::new(
            LoadBalancing::Allow,
            Arc::new(Box::new(DummyQuotaHandler)),
            None,
        ));
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel().never();
        mock.expect_tunneling_channel().never();
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: Some(8443),
                is_aliasing: false,
            })
        });
        conn_manager
            .insert(
                "non.standard".into(),
                "127.0.0.1:12345".parse().unwrap(),
                TokenHolder::User(UserIdentification::Username("a".into())),
                Arc::new(mock),
            )
            .unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/test")
            .header("host", "non.standard")
            .body(String::from("Hello world"))
            .unwrap();
        let response = proxy_handler(
            request,
            "127.0.0.1:12345".parse().unwrap(),
            None,
            Arc::new(ProxyData {
                conn_manager: Arc::clone(&conn_manager),
                telemetry: Arc::new(Telemetry::new()),
                domain_redirect: Arc::new(DomainRedirect {
                    from: "main.domain".into(),
                    to: "https://example.com".into(),
                }),
                protocol: Protocol::Http { port: 80 },
                proxy_type: ProxyType::Tunneling,
                http_request_timeout: Duration::from_secs(5),
                websocket_timeout: None,
                disable_http_logs: false,
                _phantom_data: PhantomData,
            }),
        )
        .await;
        assert!(
            response.is_ok(),
            "should return response whyen HTTPS redirect to non-standard port"
        );
        let response = response.unwrap();
        assert_eq!(response.status(), hyper::StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            response.headers().get("location").unwrap(),
            "https://non.standard:8443/test"
        );
    }

    #[tokio::test]
    async fn returns_response_for_existing_handler() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(ConnectionMap::new(
            LoadBalancing::Allow,
            Arc::new(Box::new(DummyQuotaHandler)),
            None,
        ));
        let (server, handler) = tokio::io::duplex(1024);
        let (logging_tx, logging_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel()
            .once()
            .return_once(move || Some(logging_tx));
        mock.expect_tunneling_channel()
            .once()
            .return_once(move |_, _| Ok(handler));
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
            })
        });
        conn_manager
            .insert(
                "with.handler".into(),
                "127.0.0.1:12345".parse().unwrap(),
                TokenHolder::User(UserIdentification::Username("a".into())),
                Arc::new(mock),
            )
            .unwrap();
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
        assert!(
            logging_rx.is_empty(),
            "shouldn't log before handling request"
        );
        let response = proxy_handler(
            request,
            "127.0.0.1:12345".parse().unwrap(),
            None,
            Arc::new(ProxyData {
                conn_manager: Arc::clone(&conn_manager),
                telemetry: Arc::new(Telemetry::new()),
                domain_redirect: Arc::new(DomainRedirect {
                    from: "main.domain".into(),
                    to: "https://example.com".into(),
                }),
                protocol: Protocol::Https { port: 443 },
                proxy_type: ProxyType::Tunneling,
                http_request_timeout: Duration::from_secs(5),
                websocket_timeout: None,
                disable_http_logs: false,
                _phantom_data: PhantomData,
            }),
        )
        .await;
        assert!(!logging_rx.is_empty(), "should log after proxying request");
        assert!(response.is_ok(), "should return response after proxy");
        let response = response.unwrap();
        assert_eq!(response.status(), hyper::StatusCode::OK);
        let body = response.into_body();
        let body = axum::body::to_bytes(body, 32).await.unwrap();
        assert_eq!(body, bytes::Bytes::from("Success."));
        jh.abort();
    }

    #[tokio::test]
    async fn returns_response_for_aliasing_handler() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(ConnectionMap::new(
            LoadBalancing::Allow,
            Arc::new(Box::new(DummyQuotaHandler)),
            None,
        ));
        let (server, handler) = tokio::io::duplex(1024);
        let (logging_tx, logging_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel()
            .once()
            .return_once(move || Some(logging_tx));
        mock.expect_aliasing_channel()
            .once()
            .return_once(move |_, _, _| Ok(handler));
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: Some(443),
                is_aliasing: false,
            })
        });
        conn_manager
            .insert(
                "with.handler".into(),
                "127.0.0.1:12345".parse().unwrap(),
                TokenHolder::User(UserIdentification::Username("a".into())),
                Arc::new(mock),
            )
            .unwrap();
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
        assert!(
            logging_rx.is_empty(),
            "shouldn't log before handling request"
        );
        let response = proxy_handler(
            request,
            "127.0.0.1:12345".parse().unwrap(),
            None,
            Arc::new(ProxyData {
                conn_manager: Arc::clone(&conn_manager),
                telemetry: Arc::new(Telemetry::new()),
                domain_redirect: Arc::new(DomainRedirect {
                    from: "main.domain".into(),
                    to: "https://example.com".into(),
                }),
                protocol: Protocol::Http { port: 80 },
                proxy_type: ProxyType::Aliasing,
                http_request_timeout: Duration::from_secs(5),
                websocket_timeout: None,
                disable_http_logs: false,
                _phantom_data: PhantomData,
            }),
        )
        .await;
        assert!(!logging_rx.is_empty(), "should log after proxying request");
        assert!(response.is_ok(), "should return response after proxy");
        let response = response.unwrap();
        assert_eq!(response.status(), hyper::StatusCode::OK);
        let body = response.into_body();
        let body = axum::body::to_bytes(body, 32).await.unwrap();
        assert_eq!(body, bytes::Bytes::from("Success."));
        jh.abort();
    }

    #[tokio::test]
    async fn returns_response_for_handler_of_root_domain() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(ConnectionMap::new(
            LoadBalancing::Allow,
            Arc::new(Box::new(DummyQuotaHandler)),
            None,
        ));
        let (server, handler) = tokio::io::duplex(1024);
        let (logging_tx, logging_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel()
            .once()
            .return_once(move || Some(logging_tx));
        mock.expect_tunneling_channel()
            .once()
            .return_once(move |_, _| Ok(handler));
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
            })
        });
        conn_manager
            .insert(
                "root.domain".into(),
                "127.0.0.1:12345".parse().unwrap(),
                TokenHolder::User(UserIdentification::Username("a".into())),
                Arc::new(mock),
            )
            .unwrap();
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
        assert!(
            logging_rx.is_empty(),
            "shouldn't log before handling request"
        );
        let response = proxy_handler(
            request,
            "192.168.0.1:12345".parse().unwrap(),
            None,
            Arc::new(ProxyData {
                conn_manager: Arc::clone(&conn_manager),
                telemetry: Arc::new(Telemetry::new()),
                domain_redirect: Arc::new(DomainRedirect {
                    from: "root.domain".into(),
                    to: "https://this.is.ignored".into(),
                }),
                protocol: Protocol::Https { port: 443 },
                proxy_type: ProxyType::Tunneling,
                http_request_timeout: Duration::from_secs(5),
                websocket_timeout: None,
                disable_http_logs: false,
                _phantom_data: PhantomData,
            }),
        )
        .await;
        assert!(!logging_rx.is_empty(), "should log after proxying request");
        assert!(
            response.is_ok(),
            "should return response after proxying request"
        );
        let response = response.unwrap();
        assert_eq!(response.status(), hyper::StatusCode::OK);
        let body = response.into_body();
        let body = axum::body::to_bytes(body, 32).await.unwrap();
        assert_eq!(body, bytes::Bytes::from("Success."));
        jh.abort();
    }

    #[tokio::test]
    async fn returns_websocket_upgrade_for_existing_handler() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(ConnectionMap::new(
            LoadBalancing::Allow,
            Arc::new(Box::new(DummyQuotaHandler)),
            None,
        ));
        let (server, handler) = tokio::io::duplex(1024);
        let (logging_tx, logging_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel()
            .once()
            .return_once(move || Some(logging_tx));
        mock.expect_tunneling_channel()
            .once()
            .return_once(move |_, _| Ok(handler));
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
            })
        });
        conn_manager
            .insert(
                "with.websocket".into(),
                "127.0.0.1:12345".parse().unwrap(),
                TokenHolder::User(UserIdentification::Username("a".into())),
                Arc::new(mock),
            )
            .unwrap();
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
        assert!(logging_rx.is_empty(), "shouldn't log before request");
        let proxy_service = service_fn(move |request| {
            proxy_handler(
                request,
                "127.0.0.1:12345".parse().unwrap(),
                None,
                Arc::new(ProxyData {
                    conn_manager: Arc::clone(&conn_manager),
                    telemetry: Arc::new(Telemetry::new()),
                    domain_redirect: Arc::new(DomainRedirect {
                        from: "main.domain".into(),
                        to: "https://example.com".into(),
                    }),
                    protocol: Protocol::Https { port: 443 },
                    proxy_type: ProxyType::Tunneling,
                    http_request_timeout: Duration::from_secs(5),
                    websocket_timeout: None,
                    disable_http_logs: false,
                    _phantom_data: PhantomData,
                }),
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
        assert!(
            !logging_rx.is_empty(),
            "should log after upgrade proxying request"
        );
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(
            websocket.next().await.unwrap().unwrap().to_text().unwrap(),
            "Success."
        );
        jh.abort();
        jh2.abort();
    }
}
