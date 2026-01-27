use std::{
    collections::BTreeMap,
    error::Error,
    fmt::Debug,
    marker::PhantomData,
    net::SocketAddr,
    pin::Pin,
    str::FromStr,
    sync::{Arc, LazyLock, Mutex, atomic::AtomicUsize},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use crate::{
    connection_handler::ConnectionHandler,
    connections::ConnectionGetByHttpHost,
    droppable_handle::DroppableHandle,
    keepalive::{BorrowedKeepaliveAlias, KeepaliveAlias, KeepaliveAliasKey},
    ssh::ServerHandlerSender,
    tcp_alias::BorrowedTcpAlias,
    telemetry::{
        TELEMETRY_COUNTER_ALIAS_CONNECTIONS, TELEMETRY_COUNTER_HTTP_REQUESTS,
        TELEMETRY_HISTOGRAM_HTTP_ELAPSED_TIME, TELEMETRY_KEY_ALIAS, TELEMETRY_KEY_HOSTNAME,
    },
};

use ahash::RandomState;
use axum::{
    body::Body as AxumBody,
    response::{IntoResponse, Redirect},
};
use bon::Builder;
use dashmap::DashMap;
use http::{
    HeaderMap, HeaderName, HeaderValue, Uri, Version,
    header::CONNECTION,
    uri::{Authority, InvalidUri},
};
use http::{header::COOKIE, uri::InvalidUriParts};
use hyper::{
    Request, Response, StatusCode,
    body::{Body, Incoming},
    client::conn::{http1, http2},
    header::{HOST, UPGRADE},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use metrics::{counter, histogram};
use owo_colors::{OwoColorize, Style};
use russh::keys::ssh_key::Fingerprint;
use tokio::{
    io::{AsyncRead, AsyncWrite, copy_bidirectional_with_sizes},
    time::timeout,
};

static X_FORWARDED_FOR: LazyLock<HeaderName> =
    LazyLock::new(|| HeaderName::from_str("X-Forwarded-For").expect("valid header name"));
static X_FORWARDED_HOST: LazyLock<HeaderName> =
    LazyLock::new(|| HeaderName::from_str("X-Forwarded-Host").expect("valid header name"));
static X_FORWARDED_PROTO: LazyLock<HeaderName> =
    LazyLock::new(|| HeaderName::from_str("X-Forwarded-Proto").expect("valid header name"));
static X_FORWARDED_PORT: LazyLock<HeaderName> =
    LazyLock::new(|| HeaderName::from_str("X-Forwarded-Port").expect("valid header name"));

enum ProxyResponse {
    Axum(Response<AxumBody>),
    Proxy(TimedResponse),
}

struct TimedResponse {
    response: Response<Incoming>,
    on_drop: Option<Box<dyn FnOnce() + Send + Sync + 'static>>,
}

struct TimedResponseBody {
    body: Incoming,
    on_drop: Option<Box<dyn FnOnce() + Send + Sync + 'static>>,
}

impl IntoResponse for TimedResponse {
    fn into_response(self) -> axum::response::Response {
        let (parts, body) = self.response.into_parts();
        Response::from_parts(
            parts,
            AxumBody::new(TimedResponseBody {
                body,
                on_drop: self.on_drop,
            }),
        )
    }
}

impl Body for TimedResponseBody {
    type Data = bytes::Bytes;

    type Error = hyper::Error;

    #[inline]
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.body).poll_frame(cx)
    }

    #[inline]
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
}

impl Drop for TimedResponseBody {
    fn drop(&mut self) {
        if let Some(on_drop) = self.on_drop.take() {
            (on_drop)();
        }
    }
}

#[derive(Builder)]
struct HttpLog {
    ip: String,
    status: u16,
    method: String,
    host: String,
    uri: String,
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
    histogram!(
        TELEMETRY_HISTOGRAM_HTTP_ELAPSED_TIME,
        "method" => method.clone(),
        "host" => host.clone(),
        "uri" => uri.clone(),
    )
    .record(elapsed_time.as_secs_f64());
    let status_style = match status {
        100..=199 => Style::new().white(),
        200..=299 => Style::new().blue(),
        300..=399 => Style::new().green(),
        400..=499 => Style::new().yellow(),
        500..=599 => Style::new().red(),
        _ => unreachable!(),
    };
    let method_style = match method.as_str() {
        "POST" => Style::new().black().on_green().bold(),
        "PUT" | "PATCH" => Style::new().black().on_yellow().bold(),
        "DELETE" => Style::new().black().on_red().bold(),
        "HEAD" => Style::new().black().on_cyan().bold(),
        "OPTIONS" | "CONNECT" | "TRACE" => Style::new().black().on_magenta().bold(),
        // GET or other
        _ => Style::new().black().on_blue().bold(),
    };
    let duration = pretty_duration::pretty_duration(&elapsed_time, None);
    let line = format!(
        "{} {} {} => {} {}",
        format!("[{status}]").style(status_style),
        format!(" {method} ").style(method_style),
        host,
        uri,
        format!("({ip}) {duration}").dimmed()
    );
    #[cfg(not(coverage_nightly))]
    tracing::info!("{line}");
    if !disable_http_logs {
        let _ = tx.map(|tx| {
            let time = chrono::Utc::now().to_rfc3339();
            tx.send(format!("{} {}\r\n", time.dimmed(), line).into_bytes())
        });
    }
}

// Append the bytes to the given comma-separated entry of HeaderMap
fn append_to_header(headers: &mut HeaderMap, header_name: &HeaderName, new_value: &[u8]) {
    match headers.entry(header_name) {
        http::header::Entry::Vacant(entry) => {
            entry.insert(HeaderValue::from_bytes(new_value).expect("valid header value"));
        }
        http::header::Entry::Occupied(mut entry) => {
            let existing = entry.get().as_bytes();

            let mut combined_bytes = Vec::with_capacity(existing.len() + 2 + new_value.len());

            combined_bytes.extend_from_slice(existing);
            combined_bytes.extend_from_slice(b", ");
            combined_bytes.extend_from_slice(new_value);

            if let Ok(new_val) = HeaderValue::from_bytes(&combined_bytes) {
                entry.insert(new_val);
            }
        }
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
    #[error("Channel request denied")]
    ChannelRequestDenied,
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
    #[error("Invalid URI: {0:?}")]
    InvalidUri(#[from] InvalidUri),
    #[error("Invalid URI parts: {0:?}")]
    InvalidUriParts(#[from] InvalidUriParts),
    #[error("Missing Upgrade header")]
    MissingUpgradeHeader,
    #[error("Request timeout")]
    RequestTimeout,
}

impl IntoResponse for HttpError {
    fn into_response(self) -> axum::response::Response {
        #[cfg(not(coverage_nightly))]
        tracing::debug!(error = %self, "HTTP proxy error.");
        match self {
            HttpError::HeaderToStrError(_)
            | HttpError::MissingUriHost
            | HttpError::MissingHostHeader
            | HttpError::InvalidHostHeader
            | HttpError::InvalidHttpVersion(_)
            | HttpError::InvalidUri(_)
            | HttpError::InvalidUriParts(_)
            | HttpError::MissingUpgradeHeader => StatusCode::BAD_REQUEST,
            HttpError::RequestTimeout => StatusCode::REQUEST_TIMEOUT,
            HttpError::HandlerNotFound | HttpError::ChannelRequestDenied => StatusCode::NOT_FOUND,
            HttpError::HyperError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
        .into_response()
    }
}

type KeepalivePool<B, T> = Arc<Mutex<BTreeMap<usize, HttpChannel<B, T>>>>;

// Data commonly reused between HTTP proxy requests.
#[derive(Builder)]
pub(crate) struct ProxyData<B, M, H, T>
where
    M: ConnectionGetByHttpHost<Arc<H>> + Send + Sync + 'static,
    H: ConnectionHandler<T> + Send + Sync + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    B: Body + Debug + Send + Unpin + 'static,
    <B as Body>::Data: Send + Sync + 'static,
    <B as Body>::Error: Error + Send + Sync + 'static,
{
    #[builder(default = DashMap::default())]
    keepalive_pool_map: DashMap<KeepaliveAlias, KeepalivePool<B, T>, RandomState>,
    #[builder(default = AtomicUsize::new(0))]
    keepalive_index: AtomicUsize,
    #[builder(skip)]
    keepalive_gc_handle: Mutex<Option<DroppableHandle<()>>>,
    // An HTTP connection manager (usually ConnectionMap) that returns a tunneling/aliasing handler.
    conn_manager: M,
    // Tuple containing where to redirect requests from the main domain to.
    domain_redirect: Option<Arc<DomainRedirect>>,
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
    _phantom_data: PhantomData<H>,
}

impl<B, M, H, T> ProxyData<B, M, H, T>
where
    M: ConnectionGetByHttpHost<Arc<H>> + Send + Sync + 'static,
    H: ConnectionHandler<T> + Send + Sync + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    B: Body + Debug + Send + Unpin + 'static,
    <B as Body>::Data: Send + Sync + 'static,
    <B as Body>::Error: Error + Send + Sync + 'static,
{
    pub(crate) fn conn_manager(&self) -> &M {
        &self.conn_manager
    }

    fn get_sender(&self, key: BorrowedKeepaliveAlias) -> Option<HttpChannel<B, T>> {
        let key: &dyn KeepaliveAliasKey = &key;
        let pool = {
            let map_ref = self.keepalive_pool_map.get(key)?;
            Arc::clone(map_ref.value())
        };
        let mut pool_guard = pool.lock().expect("not poisoned");
        while let Some((_, sender)) = pool_guard.pop_first() {
            if match &sender {
                HttpChannel::Http11Sender(sender, _) => !sender.is_closed(),
                HttpChannel::Http2Sender(sender, _) => !sender.is_closed(),
                HttpChannel::Channel(_, _) => false,
            } {
                return Some(sender);
            }
        }
        None
    }
}

pub(crate) fn start_keepalive_garbage_collection<B, M, H, T>(
    proxy_data: &Arc<ProxyData<B, M, H, T>>,
) where
    M: ConnectionGetByHttpHost<Arc<H>> + Send + Sync + 'static,
    H: ConnectionHandler<T> + Send + Sync + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    B: Body + Debug + Send + Unpin + 'static,
    <B as Body>::Data: Send + Sync + 'static,
    <B as Body>::Error: Error + Send + Sync + 'static,
{
    let proxy_data_clone = Arc::clone(proxy_data);
    let mut handle = proxy_data.keepalive_gc_handle.lock().expect("not poisoned");
    if handle.is_none() {
        *handle = Some(DroppableHandle(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await;
            loop {
                interval.tick().await;
                proxy_data_clone
                    .keepalive_pool_map
                    .retain(|_, v| !v.lock().expect("not poisoned").is_empty());
            }
        })));
    }
}

// Receive an HTTP request and appropriately proxy it, with a possible upgrade to WebSocket.
pub(crate) async fn proxy_handler<B, M, H, T>(
    request: Request<B>,
    tcp_address: SocketAddr,
    fingerprint: Option<Fingerprint>,
    proxy_data: Arc<ProxyData<B, M, H, T>>,
) -> color_eyre::Result<Response<AxumBody>>
where
    M: ConnectionGetByHttpHost<Arc<H>> + Send + Sync + 'static,
    H: ConnectionHandler<T> + Send + Sync + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    B: Body + Debug + Send + Unpin + 'static,
    <B as Body>::Data: Send + Sync + 'static,
    <B as Body>::Error: Error + Send + Sync + 'static,
{
    match proxy_handler_inner(request, tcp_address, fingerprint, proxy_data).await {
        Ok(response) => Ok(match response {
            ProxyResponse::Axum(response) => response,
            ProxyResponse::Proxy(response) => response.into_response(),
        }),
        Err(error) => Ok(error.into_response()),
    }
}

pub(crate) enum HttpChannel<B, T> {
    Http11Sender(http1::SendRequest<B>, ServerHandlerSender),
    Http2Sender(http2::SendRequest<B>, ServerHandlerSender),
    Channel(T, ServerHandlerSender),
}

#[cfg_attr(
    not(coverage_nightly),
    tracing::instrument(skip(proxy_data), level = "debug")
)]
async fn proxy_handler_inner<B, M, H, T>(
    mut request: Request<B>,
    tcp_address: SocketAddr,
    fingerprint: Option<Fingerprint>,
    proxy_data: Arc<ProxyData<B, M, H, T>>,
) -> Result<ProxyResponse, HttpError>
where
    M: ConnectionGetByHttpHost<Arc<H>> + Send + Sync + 'static,
    H: ConnectionHandler<T> + Send + Sync + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    B: Body + Debug + Send + Unpin + 'static,
    <B as Body>::Data: Send + Sync + 'static,
    <B as Body>::Error: Error + Send + Sync + 'static,
{
    let conn_manager = &proxy_data.conn_manager;
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
    let ip = tcp_address.ip().to_canonical();
    let ip_string = ip.to_string();
    let http_log_builder = HttpLog::builder()
        .uri(request.uri().path().to_string())
        .method(request.method().to_string());
    // Find the HTTP handler for the given host
    let Some(handler) = conn_manager.get_by_http_host(&host, ip) else {
        // If no handler was found, check if this is a request to the root domain
        if let Some(redirect) = domain_redirect
            && redirect.from == host
        {
            // If so, redirect to the configured URL
            let response = Redirect::to(&redirect.to).into_response();
            http_log(
                http_log_builder
                    .host(host)
                    .ip(ip_string)
                    .status(response.status().as_u16())
                    .elapsed_time(timer.elapsed())
                    .build(),
                None,
                disable_http_logs,
            );
            return Ok(ProxyResponse::Axum(response));
        }
        // No handler was found, return 404
        return Err(HttpError::HandlerNotFound);
    };
    let http_data = handler.http_data();
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
                    .host(host)
                    .ip(ip_string)
                    .status(response.status().as_u16())
                    .elapsed_time(timer.elapsed())
                    .build(),
                None,
                disable_http_logs,
            );
            return Ok(ProxyResponse::Axum(response));
        }
        (Protocol::Http { port }, _, _)
        | (Protocol::TlsRedirect { from: port, .. }, _, ProxyType::Aliasing) => ("http", *port),
        (Protocol::Https { port }, _, _) => ("https", *port),
    };
    // Add proxied info to the proper headers, but don't overwrite any existing proxy headers
    let headers = request.headers_mut();
    append_to_header(headers, &X_FORWARDED_FOR, ip_string.as_bytes());
    append_to_header(headers, &X_FORWARDED_HOST, host.as_bytes());
    append_to_header(headers, &X_FORWARDED_PROTO, proto.as_bytes());
    append_to_header(headers, &X_FORWARDED_PORT, port.to_string().as_bytes());
    let http_log_builder = http_log_builder.host(host.clone()).ip(ip_string);
    // Add this request to the telemetry for the host
    if http_data.as_ref().is_some_and(|data| data.is_aliasing) {
        counter!(TELEMETRY_COUNTER_ALIAS_CONNECTIONS, TELEMETRY_KEY_ALIAS => BorrowedTcpAlias(&host, &port).to_string())
            .increment(1);
    } else {
        counter!(TELEMETRY_COUNTER_HTTP_REQUESTS, TELEMETRY_KEY_HOSTNAME => host.clone())
            .increment(1);
    }
    let is_http2 = http_data.as_ref().map(|data| data.http2).unwrap_or(false);
    let request_host = http_data
        .as_ref()
        .and_then(|data| data.host.as_deref())
        .unwrap_or(host.as_str());

    // Try to locate an already-open HTTP sender
    let proxy_http_version = match request.version() {
        Version::HTTP_2 if is_http2 => Version::HTTP_2,
        Version::HTTP_2 | Version::HTTP_11 => Version::HTTP_11,
        version => return Err(HttpError::InvalidHttpVersion(version)),
    };

    // Find the appropriate handler for this proxy type
    dbg!("a");
    loop {
        let channel = match proxy_data.get_sender(BorrowedKeepaliveAlias(
            &proxy_http_version,
            &host,
            &ip,
            &fingerprint,
        )) {
            Some(sender) => sender,
            None => match match proxy_data.proxy_type {
                ProxyType::Tunneling => {
                    dbg!("b");
                    handler
                        .tunneling_channel(tcp_address.ip(), tcp_address.port())
                        .await
                }
                ProxyType::Aliasing => {
                    handler
                        .aliasing_channel(
                            tcp_address.ip(),
                            tcp_address.port(),
                            fingerprint.as_ref(),
                        )
                        .await
                }
            } {
                Ok(io) => HttpChannel::Channel(io, handler.log_channel()),
                // If getting the handler failed, return 404 (they may have an allowlist for fingerprints/IP networks)
                Err(_) => return Err(HttpError::ChannelRequestDenied),
            },
        };
        match proxy_http_version {
            Version::HTTP_2 => {
                // Create an HTTP/2 handshake over the selected channel
                let mut uri_parts = request.uri().clone().into_parts();
                let authority = uri_parts.authority.as_mut().expect("Host has been checked");
                *authority = Authority::from_maybe_shared(
                    authority
                        .as_str()
                        .replace(authority.host(), request_host)
                        .into_bytes(),
                )?;
                *request.uri_mut() = Uri::from_parts(uri_parts)?;
                request.headers_mut().insert(
                    CONNECTION,
                    "keepalive".try_into().expect("valid HeaderValue"),
                );

                let cloned_proxy_data = Arc::clone(&proxy_data);
                let key = KeepaliveAlias(proxy_http_version, host.to_string(), ip, fingerprint);
                let cloned_key = key.clone();
                let pool_index = proxy_data
                    .keepalive_index
                    .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                let (mut sender, tx) = match channel {
                    HttpChannel::Http11Sender(_, _) => continue,
                    HttpChannel::Http2Sender(sender, tx) => (sender, tx),
                    HttpChannel::Channel(io, tx) => {
                        let (sender, conn) = hyper::client::conn::http2::handshake(
                            TokioExecutor::new(),
                            TokioIo::new(io),
                        )
                        .await?;
                        tokio::spawn(Box::pin(async move {
                            if let Err(error) = conn.await {
                                #[cfg(not(coverage_nightly))]
                                tracing::warn!(%error, "HTTP/2 connection failed.");
                            }
                            {
                                if let Some(pool_ref) =
                                    cloned_proxy_data.keepalive_pool_map.get(&cloned_key)
                                {
                                    pool_ref
                                        .value()
                                        .lock()
                                        .expect("not poisoned")
                                        .remove(&pool_index);
                                }
                            }
                        }));
                        (sender, tx)
                    }
                };

                let response = match proxy_data.http_request_timeout {
                    // Await for a response under the given duration.
                    Some(duration) => {
                        if let Ok(response) =
                            timeout(duration, sender.try_send_request(request)).await
                        {
                            response
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
                    None => sender.try_send_request(request).await,
                };
                let response = match response {
                    Ok(response) => response,
                    Err(mut error) => {
                        if let Some(recovered) = error.take_message() {
                            #[cfg(not(coverage_nightly))]
                            tracing::debug!(error = %error.error(), "Recovering HTTP/2 request to try again.");
                            request = recovered;
                            continue;
                        } else {
                            return Err(error.into_error().into());
                        }
                    }
                };

                let http_log_builder = http_log_builder.status(response.status().as_u16());
                return Ok(ProxyResponse::Proxy(TimedResponse {
                    response,
                    on_drop: Some(Box::new(move || {
                        // Log HTTP request
                        http_log(
                            http_log_builder.elapsed_time(timer.elapsed()).build(),
                            Some(tx.clone()),
                            disable_http_logs,
                        );
                        // Send sender to pool
                        proxy_data
                            .keepalive_pool_map
                            .entry(key)
                            .or_default()
                            .downgrade()
                            .value()
                            .lock()
                            .expect("not poisoned")
                            .insert(pool_index, HttpChannel::Http2Sender(sender, tx));
                    })),
                }));
            }
            Version::HTTP_11 => {
                // Ensure best-effort compatibility of proxy request with HTTP/1.1 format
                // -> Add host header if missing
                request
                    .headers_mut()
                    .insert(HOST, request_host.try_into().expect("valid host"));
                // -> Change URI to only include path and query
                *request.uri_mut() = request
                    .uri()
                    .path_and_query()
                    .map(|path| Uri::from_str(path.as_str()).expect("valid URI"))
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
                        .insert(header, value.try_into().expect("valid header value"));
                }

                // Check for an Upgrade header
                if let Some(request_upgrade) = request.headers().get(UPGRADE) {
                    // If there is an Upgrade header, make sure that it's a valid Websocket upgrade.
                    let (mut sender, tx) = match channel {
                        HttpChannel::Http11Sender(sender, tx) => (sender, tx),
                        HttpChannel::Http2Sender(_, _) => continue,
                        HttpChannel::Channel(io, tx) => {
                            let (sender, conn) =
                                hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
                            tokio::spawn(Box::pin(async move {
                                if let Err(error) = conn.with_upgrades().await {
                                    #[cfg(not(coverage_nightly))]
                                    tracing::warn!(%error, "HTTP/1.1 connection failed.");
                                }
                            }));
                            (sender, tx)
                        }
                    };

                    let request_type = request_upgrade.to_str()?.to_string();
                    // Retrieve the OnUpgrade from the incoming request
                    let upgraded_request = hyper::upgrade::on(&mut request);
                    let mut response = match proxy_data.http_request_timeout {
                        // Await for a response under the given duration.
                        Some(duration) => {
                            if let Ok(response) =
                                timeout(duration, sender.send_request(request)).await
                            {
                                response?
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
                        None => sender.send_request(request).await?,
                    };
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
                                    let mut upgraded_request = TokioIo::new(
                                        upgraded_request.await.expect("upgradable request"),
                                    );
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
                            let http_log_builder =
                                http_log_builder.status(response.status().as_u16());
                            return Ok(ProxyResponse::Proxy(TimedResponse {
                                response,
                                on_drop: Some(Box::new(move || {
                                    http_log(
                                        http_log_builder.elapsed_time(timer.elapsed()).build(),
                                        Some(tx),
                                        disable_http_logs,
                                    )
                                })),
                            }));
                        }
                        _ => {
                            let http_log_builder =
                                http_log_builder.status(response.status().as_u16());
                            return Ok(ProxyResponse::Proxy(TimedResponse {
                                response,
                                on_drop: Some(Box::new(move || {
                                    http_log(
                                        http_log_builder.elapsed_time(timer.elapsed()).build(),
                                        Some(tx),
                                        disable_http_logs,
                                    )
                                })),
                            }));
                        }
                    }
                } else {
                    // If Upgrade header is not present, simply handle the request
                    dbg!("c");
                    let cloned_proxy_data = Arc::clone(&proxy_data);
                    let key = KeepaliveAlias(proxy_http_version, host.to_string(), ip, fingerprint);
                    let cloned_key = key.clone();
                    let pool_index = proxy_data
                        .keepalive_index
                        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    let (mut sender, tx) = match channel {
                        HttpChannel::Http11Sender(sender, tx) => (sender, tx),
                        HttpChannel::Http2Sender(_, _) => continue,
                        HttpChannel::Channel(io, tx) => {
                            let (sender, conn) =
                                hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
                            tokio::spawn(Box::pin(async move {
                                if let Err(error) = conn.with_upgrades().await {
                                    #[cfg(not(coverage_nightly))]
                                    tracing::warn!(%error, "HTTP/1.1 connection failed.");
                                }
                                {
                                    if let Some(pool_ref) =
                                        cloned_proxy_data.keepalive_pool_map.get(&cloned_key)
                                    {
                                        pool_ref
                                            .value()
                                            .lock()
                                            .expect("not poisoned")
                                            .remove(&pool_index);
                                    }
                                }
                            }));
                            (sender, tx)
                        }
                    };

                    let response = match proxy_data.http_request_timeout {
                        // Await for a response under the given duration.
                        Some(duration) => {
                            if let Ok(response) =
                                timeout(duration, sender.try_send_request(request)).await
                            {
                                response
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
                        None => sender.try_send_request(request).await,
                    };
                    let response = match response {
                        Ok(response) => response,
                        Err(mut error) => {
                            if let Some(recovered) = error.take_message() {
                                #[cfg(not(coverage_nightly))]
                                tracing::debug!(error = %error.error(), "Recovering HTTP/1.1 request to try again.");
                                request = recovered;
                                continue;
                            } else {
                                return Err(error.into_error().into());
                            }
                        }
                    };

                    // Return the received response to the client
                    let http_log_builder = http_log_builder.status(response.status().as_u16());
                    return Ok(ProxyResponse::Proxy(TimedResponse {
                        response,
                        on_drop: Some(Box::new(move || {
                            // Log HTTP request
                            http_log(
                                http_log_builder.elapsed_time(timer.elapsed()).build(),
                                Some(tx.clone()),
                                disable_http_logs,
                            );
                            // Send sender to pool
                            proxy_data
                                .keepalive_pool_map
                                .entry(key)
                                .or_default()
                                .downgrade()
                                .value()
                                .lock()
                                .expect("not poisoned")
                                .insert(pool_index, HttpChannel::Http11Sender(sender, tx));
                        })),
                    }));
                }
            }
            version => return Err(HttpError::InvalidHttpVersion(version)),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod proxy_handler_tests {
    use axum::{
        Router,
        extract::{WebSocketUpgrade, ws},
        http::Uri,
        routing::{any, delete, get, post, put},
    };
    use bytes::Bytes;
    use futures_util::{SinkExt, StreamExt};
    use http::{
        Version,
        header::{HOST, LOCATION},
    };
    use http_body_util::{BodyExt, Empty};
    use hyper::{HeaderMap, Request, StatusCode, body::Incoming, service::service_fn};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use std::{sync::Arc, time::Duration};
    use tokio::{io::DuplexStream, sync::mpsc, time::sleep};
    use tokio_tungstenite::client_async;
    use tower::Service;

    use crate::{
        config::LoadBalancingStrategy,
        connection_handler::{ConnectionHttpData, MockConnectionHandler},
        connections::ConnectionMap,
        quota::{DummyQuotaHandler, TokenHolder, UserIdentification},
        reactor::MockConnectionMapReactor,
        ssh::ServerHandlerSender,
    };

    use super::{DomainRedirect, Protocol, ProxyData, ProxyType, proxy_handler};

    #[test_log::test(tokio::test)]
    async fn returns_bad_request_on_missing_host_header() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(
            ConnectionMap::builder()
                .strategy(LoadBalancingStrategy::Allow)
                .algorithm(crate::LoadBalancingAlgorithm::RoundRobin)
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

    #[test_log::test(tokio::test)]
    async fn returns_not_found_on_missing_handler() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(
            ConnectionMap::builder()
                .strategy(LoadBalancingStrategy::Allow)
                .algorithm(crate::LoadBalancingAlgorithm::RoundRobin)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let request = Request::builder()
            .method("GET")
            .uri("/index.html")
            .header(HOST, "no.handler")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = proxy_handler(
            request,
            "127.0.0.1:12345".parse().unwrap(),
            None,
            Arc::new(
                ProxyData::builder()
                    .conn_manager(Arc::clone(&conn_manager))
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

    #[test_log::test(tokio::test)]
    async fn returns_redirect_for_root_domain_and_missing_handler() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(
            ConnectionMap::builder()
                .strategy(LoadBalancingStrategy::Allow)
                .algorithm(crate::LoadBalancingAlgorithm::RoundRobin)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let request = Request::builder()
            .method("GET")
            .uri("/index.html")
            .header(HOST, "main.domain")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = proxy_handler(
            request,
            "127.0.0.1:12345".parse().unwrap(),
            None,
            Arc::new(
                ProxyData::builder()
                    .conn_manager(Arc::clone(&conn_manager))
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
        assert_eq!(response.headers()[LOCATION], "https://example.com");
    }

    #[test_log::test(tokio::test)]
    async fn returns_redirect_to_https_from_global_config() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(
            ConnectionMap::builder()
                .strategy(LoadBalancingStrategy::Allow)
                .algorithm(crate::LoadBalancingAlgorithm::RoundRobin)
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
                host: None,
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
            .header(HOST, "with.handler")
            .body(String::from("Hello world"))
            .unwrap();
        let response = proxy_handler(
            request,
            "127.0.0.1:12345".parse().unwrap(),
            None,
            Arc::new(
                ProxyData::builder()
                    .conn_manager(Arc::clone(&conn_manager))
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
            response.headers()[LOCATION],
            "https://with.handler:443/api/endpoint"
        );
    }

    #[test_log::test(tokio::test)]
    async fn returns_redirect_to_non_standard_https_port_from_global_config() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(
            ConnectionMap::builder()
                .strategy(LoadBalancingStrategy::Allow)
                .algorithm(crate::LoadBalancingAlgorithm::RoundRobin)
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
                host: None,
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
            .header(HOST, "non.standard")
            .body(String::from("Hello world"))
            .unwrap();
        let response = proxy_handler(
            request,
            "127.0.0.1:12345".parse().unwrap(),
            None,
            Arc::new(
                ProxyData::builder()
                    .conn_manager(Arc::clone(&conn_manager))
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
            response.headers()[LOCATION],
            "https://non.standard:8443/test"
        );
    }

    #[test_log::test(tokio::test)]
    async fn returns_redirect_to_https_from_connection_data() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(
            ConnectionMap::builder()
                .strategy(LoadBalancingStrategy::Allow)
                .algorithm(crate::LoadBalancingAlgorithm::RoundRobin)
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
                host: None,
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
            .header(HOST, "with.handler")
            .body(String::from("Hello world"))
            .unwrap();
        let response = proxy_handler(
            request,
            "127.0.0.1:12345".parse().unwrap(),
            None,
            Arc::new(
                ProxyData::builder()
                    .conn_manager(Arc::clone(&conn_manager))
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
            response.headers()[LOCATION],
            "https://with.handler:443/api/endpoint"
        );
    }

    #[test_log::test(tokio::test)]
    async fn returns_redirect_to_non_standard_https_port_from_connection_data() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(
            ConnectionMap::builder()
                .strategy(LoadBalancingStrategy::Allow)
                .algorithm(crate::LoadBalancingAlgorithm::RoundRobin)
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
                host: None,
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
            .header(HOST, "non.standard")
            .body(String::from("Hello world"))
            .unwrap();
        let response = proxy_handler(
            request,
            "127.0.0.1:12345".parse().unwrap(),
            None,
            Arc::new(
                ProxyData::builder()
                    .conn_manager(Arc::clone(&conn_manager))
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
            response.headers()[LOCATION],
            "https://non.standard:8443/test"
        );
    }

    #[test_log::test(tokio::test)]
    async fn returns_error_for_outgoing_http11_request_timeout() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(
            ConnectionMap::builder()
                .strategy(LoadBalancingStrategy::Allow)
                .algorithm(crate::LoadBalancingAlgorithm::RoundRobin)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let (server, handler) = tokio::io::duplex(1024);
        let (logging_tx, logging_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel()
            .once()
            .return_once(move || ServerHandlerSender(Some(logging_tx)));
        mock.expect_tunneling_channel()
            .once()
            .return_once(move |_, _| Ok(handler));
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
                http2: false,
                host: None,
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
            .header(HOST, "slow.handler")
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

    #[test_log::test(tokio::test)]
    async fn returns_error_for_outgoing_websocket_request_timeout() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(
            ConnectionMap::builder()
                .strategy(LoadBalancingStrategy::Allow)
                .algorithm(crate::LoadBalancingAlgorithm::RoundRobin)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let (server, handler) = tokio::io::duplex(1024);
        let (logging_tx, logging_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel()
            .once()
            .return_once(move || ServerHandlerSender(Some(logging_tx)));
        mock.expect_tunneling_channel()
            .once()
            .return_once(move |_, _| Ok(handler));
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
                http2: false,
                host: None,
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
        let error = match client_async("ws://with.websocket/ws", stream).await {
            Err(error) => error,
            Ok(res) => panic!("should've errored when establishing Websocket connection: {res:?}"),
        };
        match error {
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

    #[test_log::test(tokio::test)]
    async fn returns_error_for_outgoing_http2_request_timeout() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(
            ConnectionMap::builder()
                .strategy(LoadBalancingStrategy::Allow)
                .algorithm(crate::LoadBalancingAlgorithm::RoundRobin)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let (server, handler) = tokio::io::duplex(1024);
        let (logging_tx, logging_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel()
            .once()
            .return_once(move || ServerHandlerSender(Some(logging_tx)));
        mock.expect_tunneling_channel()
            .once()
            .return_once(move |_, _| Ok(handler));
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
                http2: true,
                host: None,
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

    #[test_log::test(tokio::test)]
    async fn returns_response_for_existing_handler() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(
            ConnectionMap::builder()
                .strategy(LoadBalancingStrategy::Allow)
                .algorithm(crate::LoadBalancingAlgorithm::RoundRobin)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let (server, handler) = tokio::io::duplex(1024);
        let (logging_tx, logging_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel()
            .once()
            .return_once(move || ServerHandlerSender(Some(logging_tx)));
        mock.expect_tunneling_channel()
            .once()
            .return_once(move |_, _| Ok(handler));
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
                http2: false,
                host: None,
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
            .header(HOST, "with.handler")
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
        let response = response.expect("should return response after proxy");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().frame().await.unwrap().unwrap();
        assert_eq!(body.data_ref(), Some(&Bytes::copy_from_slice(b"Success.")));
        drop(body);
        assert!(!logging_rx.is_empty(), "should log after proxying request");
        jh.abort();
    }

    #[test_log::test(tokio::test)]
    async fn returns_response_for_existing_handler_with_proxy() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(
            ConnectionMap::builder()
                .strategy(LoadBalancingStrategy::Allow)
                .algorithm(crate::LoadBalancingAlgorithm::RoundRobin)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let (server, handler) = tokio::io::duplex(1024);
        let (logging_tx, logging_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel()
            .once()
            .return_once(move || ServerHandlerSender(Some(logging_tx)));
        mock.expect_tunneling_channel()
            .once()
            .return_once(move |_, _| Ok(handler));
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
                http2: false,
                host: None,
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
            .header(HOST, "with.handler")
            .header("X-Forwarded-For", "10.15.0.1")
            .header("X-Forwarded-Host", "sand.hole")
            .body(String::from("Hello world"))
            .unwrap();
        let router = Router::new().route(
            "/api/endpoint",
            post(|headers: HeaderMap, body: String| async move {
                if headers.get("X-Forwarded-For").unwrap() == "10.15.0.1, 127.0.0.1"
                    && headers.get("X-Forwarded-Host").unwrap() == "sand.hole, with.handler"
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
        let response = response.expect("should return response after proxy");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().frame().await.unwrap().unwrap();
        assert_eq!(body.data_ref(), Some(&Bytes::copy_from_slice(b"Success.")));
        drop(body);
        assert!(!logging_rx.is_empty(), "should log after proxying request");
        jh.abort();
    }

    #[test_log::test(tokio::test)]
    async fn returns_response_for_existing_handler_with_custom_host() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(
            ConnectionMap::builder()
                .strategy(LoadBalancingStrategy::Allow)
                .algorithm(crate::LoadBalancingAlgorithm::RoundRobin)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let (server, handler) = tokio::io::duplex(1024);
        let (logging_tx, logging_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel()
            .once()
            .return_once(move || ServerHandlerSender(Some(logging_tx)));
        mock.expect_tunneling_channel()
            .once()
            .return_once(move |_, _| Ok(handler));
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
                http2: false,
                host: Some("other.host".into()),
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
            .header(HOST, "with.handler")
            .body(String::from("Hello world"))
            .unwrap();
        let router = Router::new().route(
            "/api/endpoint",
            post(|headers: HeaderMap, body: String| async move {
                if headers.get("X-Forwarded-For").unwrap() == "127.0.0.1"
                    && headers.get("X-Forwarded-Host").unwrap() == "with.handler"
                    && headers.get("Host").unwrap() == "other.host"
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
        let response = response.expect("should return response after proxy");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().frame().await.unwrap().unwrap();
        assert_eq!(body.data_ref(), Some(&Bytes::copy_from_slice(b"Success.")));
        drop(body);
        assert!(!logging_rx.is_empty(), "should log after proxying request");
        jh.abort();
    }

    #[test_log::test(tokio::test)]
    async fn returns_response_for_aliasing_handler() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(
            ConnectionMap::builder()
                .strategy(LoadBalancingStrategy::Allow)
                .algorithm(crate::LoadBalancingAlgorithm::RoundRobin)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let (server, handler) = tokio::io::duplex(1024);
        let (logging_tx, logging_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel()
            .once()
            .return_once(move || ServerHandlerSender(Some(logging_tx)));
        mock.expect_aliasing_channel()
            .once()
            .return_once(move |_, _, _| Ok(handler));
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: Some(443),
                is_aliasing: false,
                http2: false,
                host: None,
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
            .header(HOST, "with.handler")
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
        let response = response.expect("should return response after proxy");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body();
        let body = axum::body::to_bytes(body, 32).await.unwrap();
        assert_eq!(body, bytes::Bytes::from("Success."));
        drop(body);
        assert!(!logging_rx.is_empty(), "should log after proxying request");
        jh.abort();
    }

    #[test_log::test(tokio::test)]
    async fn returns_response_for_handler_of_root_domain() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(
            ConnectionMap::builder()
                .strategy(LoadBalancingStrategy::Allow)
                .algorithm(crate::LoadBalancingAlgorithm::RoundRobin)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let (server, handler) = tokio::io::duplex(1024);
        let (logging_tx, logging_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel()
            .once()
            .return_once(move || ServerHandlerSender(Some(logging_tx)));
        mock.expect_tunneling_channel()
            .once()
            .return_once(move |_, _| Ok(handler));
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
                http2: false,
                host: None,
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
            .header(HOST, "root.domain")
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
        let response = response.expect("should return response after proxying request");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body();
        let body = axum::body::to_bytes(body, 32).await.unwrap();
        assert_eq!(body, bytes::Bytes::from("Success."));
        drop(body);
        assert!(!logging_rx.is_empty(), "should log after proxying request");
        jh.abort();
    }

    #[test_log::test(tokio::test)]
    async fn returns_http11_response_for_existing_handler() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(
            ConnectionMap::builder()
                .strategy(LoadBalancingStrategy::Allow)
                .algorithm(crate::LoadBalancingAlgorithm::RoundRobin)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let (server, handler) = tokio::io::duplex(1024);
        let (logging_tx, logging_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel()
            .once()
            .return_once(move || ServerHandlerSender(Some(logging_tx)));
        mock.expect_tunneling_channel()
            .once()
            .return_once(move |_, _| Ok(handler));
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
                http2: false,
                host: None,
            })
        });
        conn_manager
            .insert(
                "http11.handler".into(),
                "127.0.0.1:12345".parse().unwrap(),
                TokenHolder::User(UserIdentification::Username("a".into())),
                Arc::new(mock),
            )
            .unwrap();
        let (socket, stream) = tokio::io::duplex(1024);
        let router = Router::new().route(
            "/http11",
            delete(|headers: HeaderMap| async move {
                if headers.get("X-Forwarded-For").unwrap() == "127.0.0.1"
                    && headers.get("X-Forwarded-Host").unwrap() == "http11.handler"
                {
                    (StatusCode::FORBIDDEN, "Can't get rid of good ol' HTTP1...")
                } else {
                    (StatusCode::BAD_REQUEST, "Failure.")
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
            .method("DELETE")
            .uri("https://http11.handler/http11")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = sender
            .send_request(request)
            .await
            .expect("should return response after proxy");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
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
        assert_eq!(body, "Can't get rid of good ol' HTTP1...");
        drop(body);
        assert!(!logging_rx.is_empty(), "should log after proxying request");
        jh.abort();
        jh2.abort();
        jh3.abort();
    }

    #[test_log::test(tokio::test)]
    async fn returns_websocket_upgrade_for_existing_handler() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(
            ConnectionMap::builder()
                .strategy(LoadBalancingStrategy::Allow)
                .algorithm(crate::LoadBalancingAlgorithm::RoundRobin)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let (server, handler) = tokio::io::duplex(1024);
        let (logging_tx, logging_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel()
            .once()
            .return_once(move || ServerHandlerSender(Some(logging_tx)));
        mock.expect_tunneling_channel()
            .once()
            .return_once(move |_, _| Ok(handler));
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
                http2: false,
                host: None,
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
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        drop(response);
        assert!(
            !logging_rx.is_empty(),
            "should log after upgrade proxying request"
        );
        assert_eq!(
            websocket.next().await.unwrap().unwrap().to_text().unwrap(),
            "Success."
        );
        jh.abort();
        jh2.abort();
    }

    #[test_log::test(tokio::test)]
    async fn returns_http2_response_for_existing_handler() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(
            ConnectionMap::builder()
                .strategy(LoadBalancingStrategy::Allow)
                .algorithm(crate::LoadBalancingAlgorithm::RoundRobin)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let (server, handler) = tokio::io::duplex(1024);
        let (logging_tx, logging_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel()
            .once()
            .return_once(move || ServerHandlerSender(Some(logging_tx)));
        mock.expect_tunneling_channel()
            .once()
            .return_once(move |_, _| Ok(handler));
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
                http2: true,
                host: None,
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
        drop(body);
        assert!(!logging_rx.is_empty(), "should log after proxying request");
        jh.abort();
        jh2.abort();
        jh3.abort();
    }

    #[test_log::test(tokio::test)]
    async fn returns_http2_response_for_existing_handler_with_custom_host() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(
            ConnectionMap::builder()
                .strategy(LoadBalancingStrategy::Allow)
                .algorithm(crate::LoadBalancingAlgorithm::RoundRobin)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let (server, handler) = tokio::io::duplex(1024);
        let (logging_tx, logging_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut mock = MockConnectionHandler::new();
        mock.expect_log_channel()
            .once()
            .return_once(move || ServerHandlerSender(Some(logging_tx)));
        mock.expect_tunneling_channel()
            .once()
            .return_once(move |_, _| Ok(handler));
        mock.expect_http_data().once().return_once(move || {
            Some(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
                http2: true,
                host: Some("other.host".into()),
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
            put(|uri: Uri, headers: HeaderMap, body: String| async move {
                if headers.get("X-Forwarded-For").unwrap() == "127.0.0.1"
                    && headers.get("X-Forwarded-Host").unwrap() == "http2.handler"
                    && uri.host().unwrap() == "other.host"
                    && &body == "The future of HTTP!"
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
        drop(body);
        assert!(!logging_rx.is_empty(), "should log after proxying request");
        jh.abort();
        jh2.abort();
        jh3.abort();
    }

    #[test_log::test(tokio::test)]
    async fn fails_for_http2_with_missing_host_in_uri() {
        let conn_manager: Arc<
            ConnectionMap<
                String,
                Arc<MockConnectionHandler<DuplexStream>>,
                MockConnectionMapReactor<String>,
            >,
        > = Arc::new(
            ConnectionMap::builder()
                .strategy(LoadBalancingStrategy::Allow)
                .algorithm(crate::LoadBalancingAlgorithm::RoundRobin)
                .quota_handler(Arc::new(Box::new(DummyQuotaHandler)))
                .build(),
        );
        let (socket, stream) = tokio::io::duplex(1024);
        let proxy_service = service_fn(move |request| {
            proxy_handler(
                request,
                "127.0.0.1:12345".parse().unwrap(),
                None,
                Arc::new(
                    ProxyData::builder()
                        .conn_manager(Arc::clone(&conn_manager))
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
        let jh = tokio::spawn(async move {
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(socket), proxy_service)
                .await
                .expect("Invalid request");
        });
        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
                .await
                .unwrap();
        let jh2 = tokio::spawn(conn);
        let request = Request::builder()
            .method("GET")
            .uri("/no_host")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = sender
            .send_request(request)
            .await
            .expect("should return response after proxy");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        jh.abort();
        jh2.abort();
    }
}
