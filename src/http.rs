use std::error::Error;
use std::marker::PhantomData;
use std::str::FromStr;
use std::time::{Duration, Instant};
use std::{net::SocketAddr, sync::Arc};

use crate::connection_handler::ConnectionHandler;
use crate::connections::ConnectionGetByHttpHost;
use crate::ssh::ServerHandlerSender;
use crate::tcp_alias::TcpAlias;
use crate::telemetry::Telemetry;

use axum::{
    body::Body as AxumBody,
    response::{IntoResponse, Redirect},
};
use bon::Builder;
use http::header::COOKIE;
use http::{Uri, Version};
use hyper::{
    Request, Response, StatusCode,
    body::Body,
    header::{HOST, UPGRADE},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use log::{debug, warn};
use russh::keys::ssh_key::Fingerprint;
use tokio::{
    io::{AsyncRead, AsyncWrite, copy_bidirectional_with_sizes},
    time::timeout,
};

const X_FORWARDED_FOR: &str = "X-Forwarded-For";
const X_FORWARDED_HOST: &str = "X-Forwarded-Host";
const X_FORWARDED_PROTO: &str = "X-Forwarded-Proto";
const X_FORWARDED_PORT: &str = "X-Forwarded-Port";

#[derive(Builder)]
struct HttpLog<'a> {
    ip: &'a str,
    status: u16,
    method: &'a str,
    host: &'a str,
    uri: &'a str,
    elapsed_time: Duration,
}

fn http_log(data: HttpLog, tx: Option<ServerHandlerSender>, disable_http_logs: bool) {
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
        " \x1b[2m{}\x1b[22m \x1b[{}m[{}] \x1b[0;1;30;{}m {} \x1b[0m {} => {} \x1b[2m({}) {}\x1b[0m\r\n",
        chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%:z"),
        status_escape_color,
        status,
        method_escape_color,
        method,
        host,
        uri,
        ip,
        pretty_duration::pretty_duration(&elapsed_time, None)
    );
    print!("{line}");
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

#[derive(thiserror::Error, Debug)]
pub(crate) enum HttpError {
    #[error("Hyper error: {0}")]
    HyperError(#[from] hyper::Error),
    #[error("Handler not found")]
    HandlerNotFound,
    #[error("Header to string error: {0}")]
    HeaderToStrError(#[from] http::header::ToStrError),
    #[error("Missing URI host")]
    MissingUriHost,
    #[error("Missing Host header")]
    MissingHostHeader,
    #[error("Invalid Host header")]
    InvalidHostHeader,
    #[error("Invalid HTTP version {0:?}")]
    InvalidHttpVersion(Version),
    #[error("Missing Upgrade header")]
    MissingUpgradeHeader,
    #[error("Request timeout")]
    RequestTimeout,
}

impl IntoResponse for HttpError {
    fn into_response(self) -> axum::response::Response {
        debug!("HTTP proxy error: {:?}", &self);
        match self {
            HttpError::HeaderToStrError(_)
            | HttpError::MissingUriHost
            | HttpError::MissingHostHeader
            | HttpError::InvalidHostHeader
            | HttpError::InvalidHttpVersion(_)
            | HttpError::MissingUpgradeHeader => StatusCode::BAD_REQUEST,
            HttpError::RequestTimeout => StatusCode::REQUEST_TIMEOUT,
            HttpError::HandlerNotFound => StatusCode::NOT_FOUND,
            HttpError::HyperError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
        .into_response()
    }
}

// Data commonly reused between HTTP proxy requests.
#[derive(Builder)]
pub(crate) struct ProxyData<M, H, T>
where
    M: ConnectionGetByHttpHost<Arc<H>>,
    H: ConnectionHandler<T>,
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    // An HTTP connection manager (usually ConnectionMap) that returns a tunneling/aliasing handler.
    conn_manager: M,
    // Telemetry service, where HTTP requests are tracked.
    telemetry: Arc<Telemetry>,
    // Tuple containing where to redirect requests from the main domain to.
    domain_redirect: Arc<DomainRedirect>,
    // The HTTP protocol for the current connection.
    protocol: Protocol,
    // Configuration on which type of channel to retrieve from the handler.
    proxy_type: ProxyType,
    // Buffer size for bidirectional copying.
    buffer_size: usize,
    // Optional duration until an outgoing request is canceled.
    http_request_timeout: Option<Duration>,
    // Optional duration until an established Websocket connection is canceled.
    websocket_timeout: Option<Duration>,
    // If set, disables sending HTTP logs to the handler.
    disable_http_logs: bool,
    #[builder(skip)]
    _phantom_data: PhantomData<(H, T)>,
}

impl<M, H, T> ProxyData<M, H, T>
where
    M: ConnectionGetByHttpHost<Arc<H>>,
    H: ConnectionHandler<T>,
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    pub(crate) fn conn_manager(&self) -> &M {
        &self.conn_manager
    }
}

// Receive an HTTP request and appropriately proxy it, with a possible upgrade to WebSocket.
pub(crate) async fn proxy_handler<B, M, H, T>(
    request: Request<B>,
    tcp_address: SocketAddr,
    fingerprint: Option<Fingerprint>,
    proxy_data: Arc<ProxyData<M, H, T>>,
) -> anyhow::Result<Response<AxumBody>>
where
    M: ConnectionGetByHttpHost<Arc<H>>,
    H: ConnectionHandler<T>,
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    B: Body + Send + Unpin + 'static,
    <B as Body>::Data: Send + Sync + 'static,
    <B as Body>::Error: Error + Send + Sync + 'static,
{
    match proxy_handler_inner(request, tcp_address, fingerprint, proxy_data).await {
        Ok(response) => Ok(response),
        Err(error) => Ok(error.into_response()),
    }
}

async fn proxy_handler_inner<B, M, H, T>(
    mut request: Request<B>,
    tcp_address: SocketAddr,
    fingerprint: Option<Fingerprint>,
    proxy_data: Arc<ProxyData<M, H, T>>,
) -> Result<Response<AxumBody>, HttpError>
where
    M: ConnectionGetByHttpHost<Arc<H>>,
    H: ConnectionHandler<T>,
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    B: Body + Send + Unpin + 'static,
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
    let host = match request.version() {
        Version::HTTP_2 => request.uri().host().ok_or(HttpError::MissingUriHost)?,
        Version::HTTP_11 => match request.headers().get(HOST) {
            Some(header_value) => match header_value.to_str() {
                Ok(header) => header
                    .split(':')
                    .next()
                    .ok_or(HttpError::InvalidHostHeader)?,
                Err(_) => return Err(HttpError::InvalidHostHeader),
            },
            None => return Err(HttpError::MissingHostHeader),
        },
        version => return Err(HttpError::InvalidHttpVersion(version)),
    };
    let host = host.to_owned();
    let ip = tcp_address.ip().to_canonical().to_string();
    let method = request.method().to_owned();
    let uri = request.uri().to_owned();
    let http_log_builder = HttpLog::builder()
        .ip(&ip)
        .host(&host)
        .uri(uri.path())
        .method(method.as_str());
    // Find the HTTP handler for the given host
    let Some(handler) = conn_manager.get_by_http_host(&host) else {
        // If no handler was found, check if this is a request to the root domain
        if domain_redirect.from == host {
            // If so, redirect to the configured URL
            let elapsed_time = timer.elapsed();
            let response = Redirect::to(&domain_redirect.to).into_response();
            http_log(
                http_log_builder
                    .status(response.status().as_u16())
                    .elapsed_time(elapsed_time)
                    .build(),
                None,
                disable_http_logs,
            );
            return Ok(response);
        }
        // No handler was found, return 404
        return Err(HttpError::HandlerNotFound);
    };
    let http_data = handler.http_data().await;
    let redirect_http_to_https_port =
        http_data
            .as_ref()
            .and_then(|data: &crate::connection_handler::ConnectionHttpData| {
                data.redirect_http_to_https_port
            });
    // Read protocol information for X-Forwarded headers
    let (proto, port) = match (
        protocol,
        redirect_http_to_https_port.as_ref(),
        &proxy_data.proxy_type,
    ) {
        // If force-https is true, redirect this HTTP request to HTTPS
        (Protocol::Http { .. }, Some(port), ProxyType::Tunneling)
        | (Protocol::TlsRedirect { to: port, .. }, _, ProxyType::Tunneling) => {
            let elapsed_time = timer.elapsed();
            let response = Redirect::permanent(
                format!(
                    "https://{}:{}{}",
                    host,
                    port,
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
                http_log_builder
                    .status(response.status().as_u16())
                    .elapsed_time(elapsed_time)
                    .build(),
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
        return Err(HttpError::HandlerNotFound);
    };
    let tx = handler.log_channel();
    let is_http2 = http_data.as_ref().map(|data| data.http2).unwrap_or(false);
    match request.version() {
        Version::HTTP_2 if is_http2 => {
            // Create an HTTP/2 handshake over the selected channel
            let (mut sender, conn) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io))
                    .await?;
            tokio::spawn(Box::pin(async move {
                if let Err(err) = conn.await {
                    warn!("HTTP/2 connection failed: {err:?}");
                }
            }));
            let response = match proxy_data.http_request_timeout {
                // Await for a response under the given duration.
                Some(duration) => {
                    if let Ok(response) = timeout(duration, sender.send_request(request)).await {
                        response?.into_response()
                    } else {
                        let elapsed_time = timer.elapsed();
                        http_log(
                            http_log_builder
                                .status(StatusCode::REQUEST_TIMEOUT.as_u16())
                                .elapsed_time(elapsed_time)
                                .build(),
                            Some(tx),
                            disable_http_logs,
                        );
                        return Err(HttpError::RequestTimeout);
                    }
                }
                None => sender.send_request(request).await?.into_response(),
            };
            let elapsed_time = timer.elapsed();
            http_log(
                http_log_builder
                    .status(response.status().as_u16())
                    .elapsed_time(elapsed_time)
                    .build(),
                Some(tx),
                disable_http_logs,
            );
            Ok(response)
        }
        Version::HTTP_11 | Version::HTTP_2 => {
            // Ensure best-effort compatibility of proxy request with HTTP/1.1 format
            // -> Add host header if missing
            request
                .headers_mut()
                .entry(HOST)
                .or_insert_with(|| host.clone().try_into().unwrap());
            // -> Change URI to only include path and query
            *request.uri_mut() = request
                .uri()
                .path_and_query()
                .map(|path| Uri::from_str(path.as_str()).unwrap())
                .unwrap_or_default();
            // -> Decompress cookies: https://www.rfc-editor.org/rfc/rfc7540#section-8.1.2.5
            if let http::header::Entry::Occupied(occupied_entry) =
                request.headers_mut().entry(COOKIE)
            {
                let (header, values) = occupied_entry.remove_entry_mult();
                let mut value = vec![];
                for header_value in values {
                    if !value.is_empty() {
                        value.extend_from_slice(b"; ");
                    }
                    value.extend_from_slice(header_value.as_bytes());
                }
                request
                    .headers_mut()
                    .insert(header, value.try_into().unwrap());
            }

            // Create an HTTP/1.1 handshake over the selected channel
            let (mut sender, conn) =
                hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;

            // Check for an Upgrade header
            if let Some(request_upgrade) = request.headers().get(UPGRADE) {
                // If there is an Upgrade header, make sure that it's a valid Websocket upgrade.
                tokio::spawn(async move {
                    if let Err(err) = conn.with_upgrades().await {
                        warn!("HTTP/1.1 connection with upgrades failed: {err:?}");
                    }
                });
                let request_type = request_upgrade.to_str()?.to_string();
                // Retrieve the OnUpgrade from the incoming request
                let upgraded_request = hyper::upgrade::on(&mut request);
                let mut response = match proxy_data.http_request_timeout {
                    // Await for a response under the given duration.
                    Some(duration) => {
                        if let Ok(response) = timeout(duration, sender.send_request(request)).await
                        {
                            response?.into_response()
                        } else {
                            let elapsed_time = timer.elapsed();
                            http_log(
                                http_log_builder
                                    .status(StatusCode::REQUEST_TIMEOUT.as_u16())
                                    .elapsed_time(elapsed_time)
                                    .build(),
                                Some(tx),
                                disable_http_logs,
                            );
                            return Err(HttpError::RequestTimeout);
                        }
                    }
                    None => sender.send_request(request).await?.into_response(),
                };
                let elapsed_time = timer.elapsed();
                http_log(
                    http_log_builder
                        .status(response.status().as_u16())
                        .elapsed_time(elapsed_time)
                        .build(),
                    Some(tx),
                    disable_http_logs,
                );
                // Check if the underlying server accepts the Upgrade request
                match response.status() {
                    StatusCode::SWITCHING_PROTOCOLS => {
                        if request_type
                            == response
                                .headers()
                                .get(UPGRADE)
                                .ok_or(HttpError::MissingUpgradeHeader)?
                                .to_str()?
                        {
                            // Retrieve the upgraded connection from the response
                            let upgraded_response = hyper::upgrade::on(&mut response).await?;
                            let websocket_timeout = proxy_data.websocket_timeout;
                            let buffer_size = proxy_data.buffer_size;
                            // Start a task to copy data between the two Upgraded parts
                            tokio::spawn(async move {
                                let mut upgraded_request =
                                    TokioIo::new(upgraded_request.await.unwrap());
                                let mut upgraded_response = TokioIo::new(upgraded_response);
                                match websocket_timeout {
                                    // If there is a Websocket timeout, copy until the deadline is reached.
                                    Some(duration) => {
                                        let _ = timeout(duration, async {
                                            copy_bidirectional_with_sizes(
                                                &mut upgraded_response,
                                                &mut upgraded_request,
                                                buffer_size,
                                                buffer_size,
                                            )
                                            .await
                                        })
                                        .await;
                                    }
                                    // If there isn't a Websocket timeout, copy data between both sides unconditionally.
                                    None => {
                                        let _ = copy_bidirectional_with_sizes(
                                            &mut upgraded_response,
                                            &mut upgraded_request,
                                            buffer_size,
                                            buffer_size,
                                        )
                                        .await;
                                    }
                                }
                            });
                        }
                        // Return the response to the client
                        Ok(response)
                    }
                    _ => Ok(response),
                }
            } else {
                // If Upgrade header is not present, simply handle the request
                tokio::spawn(async move {
                    if let Err(err) = conn.await {
                        warn!("HTTP/1.1 connection failed: {err:?}");
                    }
                });
                let response = match proxy_data.http_request_timeout {
                    // Await for a response under the given duration.
                    Some(duration) => {
                        if let Ok(response) = timeout(duration, sender.send_request(request)).await
                        {
                            response?.into_response()
                        } else {
                            let elapsed_time = timer.elapsed();
                            http_log(
                                http_log_builder
                                    .status(StatusCode::REQUEST_TIMEOUT.as_u16())
                                    .elapsed_time(elapsed_time)
                                    .build(),
                                Some(tx),
                                disable_http_logs,
                            );
                            return Err(HttpError::RequestTimeout);
                        }
                    }
                    None => sender.send_request(request).await?.into_response(),
                };
                let elapsed_time = timer.elapsed();
                http_log(
                    http_log_builder
                        .status(response.status().as_u16())
                        .elapsed_time(elapsed_time)
                        .build(),
                    Some(tx),
                    disable_http_logs,
                );
                // Return the received response to the client
                Ok(response)
            }
        }
        version => Err(HttpError::InvalidHttpVersion(version)),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod proxy_handler_tests {
    use axum::{
        Router,
        extract::{WebSocketUpgrade, ws},
        routing::{any, get, post, put},
    };
    use bytes::Bytes;
    use futures_util::{SinkExt, StreamExt};
    use http::Version;
    use http_body_util::{BodyExt, Empty};
    use hyper::{HeaderMap, Request, StatusCode, body::Incoming, service::service_fn};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use std::{sync::Arc, time::Duration};
    use tokio::{io::DuplexStream, sync::mpsc, time::sleep};
    use tokio_tungstenite::client_async;
    use tower::Service;

    use crate::{
        config::LoadBalancing,
        connection_handler::{ConnectionHttpData, MockConnectionHandler},
        connections::ConnectionMap,
        quota::{DummyQuotaHandler, TokenHolder, UserIdentification},
        reactor::MockConnectionMapReactor,
        ssh::ServerHandlerSender,
        telemetry::Telemetry,
    };

    use super::{DomainRedirect, Protocol, ProxyData, ProxyType, proxy_handler};

    #[tokio::test]
    async fn returns_bad_request_on_missing_host_header() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(
            ConnectionMap::builder()
                .load_balancing(LoadBalancing::Allow)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let request = Request::builder()
            .method("GET")
            .uri("/index.html")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = proxy_handler(
            request,
            "127.0.0.1:12345".parse().unwrap(),
            None,
            Arc::new(
                ProxyData::builder()
                    .conn_manager(Arc::clone(&conn_manager))
                    .telemetry(Arc::new(Telemetry::new()))
                    .domain_redirect(Arc::new(DomainRedirect {
                        from: "main.domain".into(),
                        to: "https://example.com".into(),
                    }))
                    .protocol(Protocol::Http { port: 80 })
                    .proxy_type(ProxyType::Tunneling)
                    .buffer_size(8_000)
                    .disable_http_logs(false)
                    .build(),
            ),
        )
        .await;
        let response = response.expect("should return response when missing host header");
        assert_eq!(response.status(), hyper::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn returns_not_found_on_missing_handler() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(
            ConnectionMap::builder()
                .load_balancing(LoadBalancing::Allow)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
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
            Arc::new(
                ProxyData::builder()
                    .conn_manager(Arc::clone(&conn_manager))
                    .telemetry(Arc::new(Telemetry::new()))
                    .domain_redirect(Arc::new(DomainRedirect {
                        from: "main.domain".into(),
                        to: "https://example.com".into(),
                    }))
                    .protocol(Protocol::Http { port: 80 })
                    .proxy_type(ProxyType::Tunneling)
                    .buffer_size(8_000)
                    .disable_http_logs(false)
                    .build(),
            ),
        )
        .await;
        let response = response.expect("should return response when not found");
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
        > = Arc::new(
            ConnectionMap::builder()
                .load_balancing(LoadBalancing::Allow)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
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
            Arc::new(
                ProxyData::builder()
                    .conn_manager(Arc::clone(&conn_manager))
                    .telemetry(Arc::new(Telemetry::new()))
                    .domain_redirect(Arc::new(DomainRedirect {
                        from: "main.domain".into(),
                        to: "https://example.com".into(),
                    }))
                    .protocol(Protocol::Http { port: 80 })
                    .proxy_type(ProxyType::Tunneling)
                    .buffer_size(8_000)
                    .disable_http_logs(false)
                    .build(),
            ),
        )
        .await;
        let response = response.expect("should return response when redirect");
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
        > = Arc::new(
            ConnectionMap::builder()
                .load_balancing(LoadBalancing::Allow)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel().never();
        mock.expect_tunneling_channel().never();
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
                http2: false,
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
            Arc::new(
                ProxyData::builder()
                    .conn_manager(Arc::clone(&conn_manager))
                    .telemetry(Arc::new(Telemetry::new()))
                    .domain_redirect(Arc::new(DomainRedirect {
                        from: "main.domain".into(),
                        to: "https://example.com".into(),
                    }))
                    .protocol(Protocol::TlsRedirect { from: 80, to: 443 })
                    .proxy_type(ProxyType::Tunneling)
                    .buffer_size(8_000)
                    .disable_http_logs(false)
                    .build(),
            ),
        )
        .await;
        let response = response.expect("should return response when HTTPS redirect");
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
        > = Arc::new(
            ConnectionMap::builder()
                .load_balancing(LoadBalancing::Allow)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel().never();
        mock.expect_tunneling_channel().never();
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
                http2: false,
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
            Arc::new(
                ProxyData::builder()
                    .conn_manager(Arc::clone(&conn_manager))
                    .telemetry(Arc::new(Telemetry::new()))
                    .domain_redirect(Arc::new(DomainRedirect {
                        from: "main.domain".into(),
                        to: "https://example.com".into(),
                    }))
                    .protocol(Protocol::TlsRedirect { from: 80, to: 8443 })
                    .proxy_type(ProxyType::Tunneling)
                    .buffer_size(8_000)
                    .disable_http_logs(false)
                    .build(),
            ),
        )
        .await;
        let response =
            response.expect("should return response whyen HTTPS redirect to non-standard port");
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
        > = Arc::new(
            ConnectionMap::builder()
                .load_balancing(LoadBalancing::Allow)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel().never();
        mock.expect_tunneling_channel().never();
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: Some(443),
                is_aliasing: false,
                http2: false,
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
            Arc::new(
                ProxyData::builder()
                    .conn_manager(Arc::clone(&conn_manager))
                    .telemetry(Arc::new(Telemetry::new()))
                    .domain_redirect(Arc::new(DomainRedirect {
                        from: "main.domain".into(),
                        to: "https://example.com".into(),
                    }))
                    .protocol(Protocol::Http { port: 80 })
                    .proxy_type(ProxyType::Tunneling)
                    .buffer_size(8_000)
                    .disable_http_logs(false)
                    .build(),
            ),
        )
        .await;
        let response = response.expect("should return response when HTTPS redirect");
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
        > = Arc::new(
            ConnectionMap::builder()
                .load_balancing(LoadBalancing::Allow)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel().never();
        mock.expect_tunneling_channel().never();
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: Some(8443),
                is_aliasing: false,
                http2: false,
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
            Arc::new(
                ProxyData::builder()
                    .conn_manager(Arc::clone(&conn_manager))
                    .telemetry(Arc::new(Telemetry::new()))
                    .domain_redirect(Arc::new(DomainRedirect {
                        from: "main.domain".into(),
                        to: "https://example.com".into(),
                    }))
                    .protocol(Protocol::Http { port: 80 })
                    .proxy_type(ProxyType::Tunneling)
                    .buffer_size(8_000)
                    .disable_http_logs(false)
                    .build(),
            ),
        )
        .await;
        let response =
            response.expect("should return response when HTTPS redirect to non-standard port");
        assert_eq!(response.status(), hyper::StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            response.headers().get("location").unwrap(),
            "https://non.standard:8443/test"
        );
    }

    #[tokio::test]
    async fn returns_error_for_outgoing_http11_request_timeout() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(
            ConnectionMap::builder()
                .load_balancing(LoadBalancing::Allow)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let (server, handler) = tokio::io::duplex(1024);
        let (logging_tx, logging_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel()
            .once()
            .return_once(move || ServerHandlerSender(logging_tx));
        mock.expect_tunneling_channel()
            .once()
            .return_once(move |_, _| Ok(handler));
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
                http2: false,
            })
        });
        conn_manager
            .insert(
                "slow.handler".into(),
                "127.0.0.1:12345".parse().unwrap(),
                TokenHolder::User(UserIdentification::Username("a".into())),
                Arc::new(mock),
            )
            .unwrap();
        let request = Request::builder()
            .version(Version::HTTP_11)
            .method("GET")
            .uri("/slow_endpoint")
            .header("host", "slow.handler")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let router = Router::new().route(
            "/slow_endpoint",
            get(async || {
                sleep(Duration::from_secs(1)).await;
                "Slow hello."
            }),
        );
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
            Arc::new(
                ProxyData::builder()
                    .conn_manager(Arc::clone(&conn_manager))
                    .telemetry(Arc::new(Telemetry::new()))
                    .domain_redirect(Arc::new(DomainRedirect {
                        from: "main.domain".into(),
                        to: "https://example.com".into(),
                    }))
                    .protocol(Protocol::Https { port: 443 })
                    .proxy_type(ProxyType::Tunneling)
                    .buffer_size(8_000)
                    .http_request_timeout(Duration::from_millis(500))
                    .disable_http_logs(false)
                    .build(),
            ),
        )
        .await;
        assert!(
            !logging_rx.is_empty(),
            "should log after timing out request"
        );
        let response = response.expect("should return response after proxy");
        assert_eq!(response.status(), hyper::StatusCode::REQUEST_TIMEOUT);
        jh.abort();
    }

    #[tokio::test]
    async fn returns_error_for_outgoing_websocket_request_timeout() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(
            ConnectionMap::builder()
                .load_balancing(LoadBalancing::Allow)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let (server, handler) = tokio::io::duplex(1024);
        let (logging_tx, logging_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel()
            .once()
            .return_once(move || ServerHandlerSender(logging_tx));
        mock.expect_tunneling_channel()
            .once()
            .return_once(move |_, _| Ok(handler));
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
                http2: false,
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
        let router = Router::new().route(
            "/ws",
            any(|ws: WebSocketUpgrade| async move {
                sleep(Duration::from_secs(1)).await;
                ws.on_upgrade(|mut socket| async move {
                    let _ = socket.send(ws::Message::Text("Success.".into())).await;
                    let _ = socket.close().await;
                })
            }),
        );
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
                Arc::new(
                    ProxyData::builder()
                        .conn_manager(Arc::clone(&conn_manager))
                        .telemetry(Arc::new(Telemetry::new()))
                        .domain_redirect(Arc::new(DomainRedirect {
                            from: "main.domain".into(),
                            to: "https://example.com".into(),
                        }))
                        .protocol(Protocol::Https { port: 443 })
                        .proxy_type(ProxyType::Tunneling)
                        .buffer_size(8_000)
                        .http_request_timeout(Duration::from_millis(500))
                        .disable_http_logs(false)
                        .build(),
                ),
            )
        });
        let jh2 = tokio::spawn(async move {
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(socket), proxy_service)
                .await
                .expect("Invalid request");
        });
        let err = match client_async("ws://with.websocket/ws", stream).await {
            Err(err) => err,
            Ok(res) => panic!("should've errored when establishing Websocket connection: {res:?}"),
        };
        match err {
            tokio_tungstenite::tungstenite::Error::Http(response) => {
                assert!(
                    response.status() == StatusCode::REQUEST_TIMEOUT,
                    "should've timed out Websocket request"
                )
            }
            _ => panic!(),
        }
        assert!(
            !logging_rx.is_empty(),
            "should log after upgrade proxying request"
        );
        jh.abort();
        jh2.abort();
    }

    #[tokio::test]
    async fn returns_error_for_outgoing_http2_request_timeout() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(
            ConnectionMap::builder()
                .load_balancing(LoadBalancing::Allow)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let (server, handler) = tokio::io::duplex(1024);
        let (logging_tx, logging_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel()
            .once()
            .return_once(move || ServerHandlerSender(logging_tx));
        mock.expect_tunneling_channel()
            .once()
            .return_once(move |_, _| Ok(handler));
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
                http2: true,
            })
        });
        conn_manager
            .insert(
                "slow.handler".into(),
                "127.0.0.1:12345".parse().unwrap(),
                TokenHolder::User(UserIdentification::Username("a".into())),
                Arc::new(mock),
            )
            .unwrap();
        let request = Request::builder()
            .version(Version::HTTP_2)
            .method("GET")
            .uri("https://slow.handler/slow_endpoint")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let router = Router::new().route(
            "/slow_endpoint",
            get(async || {
                sleep(Duration::from_secs(1)).await;
                "Slow hello."
            }),
        );
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
            Arc::new(
                ProxyData::builder()
                    .conn_manager(Arc::clone(&conn_manager))
                    .telemetry(Arc::new(Telemetry::new()))
                    .domain_redirect(Arc::new(DomainRedirect {
                        from: "main.domain".into(),
                        to: "https://example.com".into(),
                    }))
                    .protocol(Protocol::Https { port: 443 })
                    .proxy_type(ProxyType::Tunneling)
                    .buffer_size(8_000)
                    .http_request_timeout(Duration::from_millis(500))
                    .disable_http_logs(false)
                    .build(),
            ),
        )
        .await;
        assert!(
            !logging_rx.is_empty(),
            "should log after timing out request"
        );
        let response = response.expect("should return response after proxy");
        assert_eq!(response.status(), hyper::StatusCode::REQUEST_TIMEOUT);
        jh.abort();
    }

    #[tokio::test]
    async fn returns_response_for_existing_handler() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(
            ConnectionMap::builder()
                .load_balancing(LoadBalancing::Allow)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let (server, handler) = tokio::io::duplex(1024);
        let (logging_tx, logging_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel()
            .once()
            .return_once(move || ServerHandlerSender(logging_tx));
        mock.expect_tunneling_channel()
            .once()
            .return_once(move |_, _| Ok(handler));
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
                http2: false,
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
        let router = Router::new().route(
            "/api/endpoint",
            post(|headers: HeaderMap, body: String| async move {
                if headers.get("X-Forwarded-For").unwrap() == "127.0.0.1"
                    && headers.get("X-Forwarded-Host").unwrap() == "with.handler"
                    && body == "Hello world"
                {
                    "Success."
                } else {
                    "Failure."
                }
            }),
        );
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
            Arc::new(
                ProxyData::builder()
                    .conn_manager(Arc::clone(&conn_manager))
                    .telemetry(Arc::new(Telemetry::new()))
                    .domain_redirect(Arc::new(DomainRedirect {
                        from: "main.domain".into(),
                        to: "https://example.com".into(),
                    }))
                    .protocol(Protocol::Https { port: 443 })
                    .proxy_type(ProxyType::Tunneling)
                    .buffer_size(8_000)
                    .disable_http_logs(false)
                    .build(),
            ),
        )
        .await;
        assert!(!logging_rx.is_empty(), "should log after proxying request");
        let response = response.expect("should return response after proxy");
        assert_eq!(response.status(), StatusCode::OK);
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
        > = Arc::new(
            ConnectionMap::builder()
                .load_balancing(LoadBalancing::Allow)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let (server, handler) = tokio::io::duplex(1024);
        let (logging_tx, logging_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel()
            .once()
            .return_once(move || ServerHandlerSender(logging_tx));
        mock.expect_aliasing_channel()
            .once()
            .return_once(move |_, _, _| Ok(handler));
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: Some(443),
                is_aliasing: false,
                http2: false,
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
        let router = Router::new().route(
            "/api/endpoint",
            post(|headers: HeaderMap, body: String| async move {
                if headers.get("X-Forwarded-For").unwrap() == "127.0.0.1"
                    && headers.get("X-Forwarded-Host").unwrap() == "with.handler"
                    && body == "Hello world"
                {
                    "Success."
                } else {
                    "Failure."
                }
            }),
        );
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
            Arc::new(
                ProxyData::builder()
                    .conn_manager(Arc::clone(&conn_manager))
                    .telemetry(Arc::new(Telemetry::new()))
                    .domain_redirect(Arc::new(DomainRedirect {
                        from: "main.domain".into(),
                        to: "https://example.com".into(),
                    }))
                    .protocol(Protocol::Http { port: 80 })
                    .proxy_type(ProxyType::Aliasing)
                    .buffer_size(8_000)
                    .disable_http_logs(false)
                    .build(),
            ),
        )
        .await;
        assert!(!logging_rx.is_empty(), "should log after proxying request");
        let response = response.expect("should return response after proxy");
        assert_eq!(response.status(), StatusCode::OK);
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
        > = Arc::new(
            ConnectionMap::builder()
                .load_balancing(LoadBalancing::Allow)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let (server, handler) = tokio::io::duplex(1024);
        let (logging_tx, logging_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel()
            .once()
            .return_once(move || ServerHandlerSender(logging_tx));
        mock.expect_tunneling_channel()
            .once()
            .return_once(move |_, _| Ok(handler));
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
                http2: false,
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
        let router = Router::new().route(
            "/test",
            post(|headers: HeaderMap, body: String| async move {
                if headers.get("X-Forwarded-For").unwrap() == "192.168.0.1"
                    && headers.get("X-Forwarded-Host").unwrap() == "root.domain"
                    && body == "My body"
                {
                    "Success."
                } else {
                    "Failure."
                }
            }),
        );
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
            Arc::new(
                ProxyData::builder()
                    .conn_manager(Arc::clone(&conn_manager))
                    .telemetry(Arc::new(Telemetry::new()))
                    .domain_redirect(Arc::new(DomainRedirect {
                        from: "root.domain".into(),
                        to: "https://this.is.ignored".into(),
                    }))
                    .protocol(Protocol::Https { port: 443 })
                    .proxy_type(ProxyType::Tunneling)
                    .buffer_size(8_000)
                    .disable_http_logs(false)
                    .build(),
            ),
        )
        .await;
        assert!(!logging_rx.is_empty(), "should log after proxying request");
        let response = response.expect("should return response after proxying request");
        assert_eq!(response.status(), StatusCode::OK);
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
        > = Arc::new(
            ConnectionMap::builder()
                .load_balancing(LoadBalancing::Allow)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let (server, handler) = tokio::io::duplex(1024);
        let (logging_tx, logging_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel()
            .once()
            .return_once(move || ServerHandlerSender(logging_tx));
        mock.expect_tunneling_channel()
            .once()
            .return_once(move |_, _| Ok(handler));
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
                http2: false,
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
        let router = Router::new().route(
            "/ws",
            any(|ws: WebSocketUpgrade| async move {
                ws.on_upgrade(|mut socket| async move {
                    let _ = socket.send(ws::Message::Text("Success.".into())).await;
                    let _ = socket.close().await;
                })
            }),
        );
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
                Arc::new(
                    ProxyData::builder()
                        .conn_manager(Arc::clone(&conn_manager))
                        .telemetry(Arc::new(Telemetry::new()))
                        .domain_redirect(Arc::new(DomainRedirect {
                            from: "main.domain".into(),
                            to: "https://example.com".into(),
                        }))
                        .protocol(Protocol::Https { port: 443 })
                        .proxy_type(ProxyType::Tunneling)
                        .buffer_size(8_000)
                        .disable_http_logs(false)
                        .build(),
                ),
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

    #[tokio::test]
    async fn returns_http2_response_for_existing_handler() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(
            ConnectionMap::builder()
                .load_balancing(LoadBalancing::Allow)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let (server, handler) = tokio::io::duplex(1024);
        let (logging_tx, logging_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel()
            .once()
            .return_once(move || ServerHandlerSender(logging_tx));
        mock.expect_tunneling_channel()
            .once()
            .return_once(move |_, _| Ok(handler));
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
                http2: true,
            })
        });
        conn_manager
            .insert(
                "http2.handler".into(),
                "127.0.0.1:12345".parse().unwrap(),
                TokenHolder::User(UserIdentification::Username("a".into())),
                Arc::new(mock),
            )
            .unwrap();
        let (socket, stream) = tokio::io::duplex(1024);
        let router = Router::new().route(
            "/http2",
            put(|headers: HeaderMap, body: String| async move {
                if headers.get("X-Forwarded-For").unwrap() == "127.0.0.1"
                    && headers.get("X-Forwarded-Host").unwrap() == "http2.handler"
                    && body == "The future of HTTP!"
                {
                    "Success."
                } else {
                    "Failure."
                }
            }),
        );
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
        let proxy_service = service_fn(move |request| {
            proxy_handler(
                request,
                "127.0.0.1:12345".parse().unwrap(),
                None,
                Arc::new(
                    ProxyData::builder()
                        .conn_manager(Arc::clone(&conn_manager))
                        .telemetry(Arc::new(Telemetry::new()))
                        .domain_redirect(Arc::new(DomainRedirect {
                            from: "main.domain".into(),
                            to: "https://example.com".into(),
                        }))
                        .protocol(Protocol::Https { port: 443 })
                        .proxy_type(ProxyType::Tunneling)
                        .buffer_size(8_000)
                        .disable_http_logs(false)
                        .build(),
                ),
            )
        });
        let jh2 = tokio::spawn(async move {
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(socket), proxy_service)
                .await
                .expect("Invalid request");
        });
        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
                .await
                .unwrap();
        let jh3 = tokio::spawn(conn);
        let request = Request::builder()
            .method("PUT")
            .uri("https://http2.handler/http2")
            .body(String::from("The future of HTTP!"))
            .unwrap();
        let response = sender
            .send_request(request)
            .await
            .expect("should return response after proxy");
        assert!(!logging_rx.is_empty(), "should log after proxying request");
        assert_eq!(response.status(), StatusCode::OK);
        let body = String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .expect("Error collecting response")
                .to_bytes()
                .into(),
        )
        .unwrap();
        assert_eq!(body, "Success.");
        jh.abort();
        jh2.abort();
        jh3.abort();
    }
}
