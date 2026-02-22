use std::{
    error::Error, fmt::Debug, net::SocketAddr, pin::pin, str::FromStr, sync::Arc, time::Instant,
};

use crate::{
    connection_handler::ConnectionHandler,
    connections::ConnectionGetByHttpHost,
    http::{
        ArcProxyData, HttpError, HttpLog, Protocol, ProxyData, ProxyResponse, ProxyType,
        TimedResponse, X_FORWARDED_FOR, X_FORWARDED_HOST, X_FORWARDED_PORT, X_FORWARDED_PROTO,
        append_to_header, http_log, proxy_handler_inner,
    },
    keepalive::KeepaliveAlias,
    telemetry::{TELEMETRY_COUNTER_HTTP_REQUESTS, TELEMETRY_KEY_HOSTNAME},
};

use axum::{body::Body as AxumBody, response::IntoResponse};
use http::header::COOKIE;
use http::{Uri, Version};
use hyper::{
    Request, Response, StatusCode,
    body::Body,
    header::{HOST, UPGRADE},
};
use hyper_util::rt::TokioIo;
use metrics::counter;
use tokio::{
    io::{AsyncRead, AsyncWrite, copy_bidirectional_with_sizes},
    time::timeout,
};

#[cfg_attr(
    not(coverage_nightly),
    tracing::instrument(skip(proxy_data, handler), level = "debug")
)]
pub(crate) async fn https_11_handler<B, M, H, T>(
    request: Request<B>,
    tcp_address: SocketAddr,
    proxy_data: Arc<ProxyData<B, M, H, T>>,
    handler: Arc<H>,
    host: String,
) -> color_eyre::Result<Response<AxumBody>>
where
    M: ConnectionGetByHttpHost<Arc<H>> + Send + Sync + 'static,
    H: ConnectionHandler<T> + Send + Sync + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    B: Body + Debug + Send + Unpin + 'static,
    <B as Body>::Data: Send + Sync + 'static,
    <B as Body>::Error: Error + Send + Sync + 'static,
{
    match https_11_handler_inner(request, tcp_address, proxy_data, handler, host).await {
        Ok(response) => Ok(match response {
            ProxyResponse::Axum(response) => response,
            ProxyResponse::Proxy(response) => response.into_response(),
        }),
        Err(error) => Ok(error.into_response()),
    }
}

#[inline]
async fn https_11_handler_inner<B, M, H, T>(
    mut request: Request<B>,
    tcp_address: SocketAddr,
    proxy_data: Arc<ProxyData<B, M, H, T>>,
    handler: Arc<H>,
    host: String,
) -> Result<ProxyResponse, HttpError>
where
    M: ConnectionGetByHttpHost<Arc<H>> + Send + Sync + 'static,
    H: ConnectionHandler<T> + Send + Sync + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    B: Body + Debug + Send + Unpin + 'static,
    <B as Body>::Data: Send + Sync + 'static,
    <B as Body>::Error: Error + Send + Sync + 'static,
{
    let timer = Instant::now();
    let host_header_or_uri = match request.version() {
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
    if host != host_header_or_uri {
        // Fallback to legacy behavior
        return proxy_handler_inner(request, tcp_address, None, proxy_data).await;
    }

    let ip = tcp_address.ip().to_canonical();

    // Read protocol information for X-Forwarded headers
    let Protocol::Https { port } = proxy_data.protocol else {
        unreachable!("HTTPS-only");
    };

    // Add proxied info to the proper headers, but don't overwrite any existing proxy headers
    let headers = request.headers_mut();
    append_to_header(headers, &X_FORWARDED_FOR, ip.to_string().as_bytes());
    append_to_header(headers, &X_FORWARDED_HOST, host.as_bytes());
    append_to_header(headers, &X_FORWARDED_PROTO, b"https");
    append_to_header(headers, &X_FORWARDED_PORT, port.to_string().as_bytes());

    // Add this request to the telemetry for the host
    counter!(TELEMETRY_COUNTER_HTTP_REQUESTS, TELEMETRY_KEY_HOSTNAME => host.clone()).increment(1);

    let host_clone = host.clone();
    let http_data = handler.http_data();
    let request_host = http_data
        .as_ref()
        .and_then(|data| data.host.as_deref())
        .unwrap_or(host_clone.as_str());

    let key = KeepaliveAlias(host.clone(), ip, None);
    handle_http11_request(
        request,
        tcp_address,
        proxy_data,
        handler,
        request_host,
        key,
        timer,
    )
    .await
}

pub(crate) async fn handle_http11_request<B, M, H, T>(
    mut request: Request<B>,
    tcp_address: SocketAddr,
    proxy_data: Arc<ProxyData<B, M, H, T>>,
    handler: Arc<H>,
    request_host: &str,
    key: KeepaliveAlias,
    timer: Instant,
) -> Result<ProxyResponse, HttpError>
where
    M: ConnectionGetByHttpHost<Arc<H>> + Send + Sync + 'static,
    H: ConnectionHandler<T> + Send + Sync + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    B: Body + Debug + Send + Unpin + 'static,
    <B as Body>::Data: Send + Sync + 'static,
    <B as Body>::Error: Error + Send + Sync + 'static,
{
    let http_log_builder = HttpLog::builder()
        .uri(request.uri().path().to_string())
        .method(request.method().to_string())
        .host(key.0.clone())
        .ip(key.1.to_string());
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
    if let http::header::Entry::Occupied(occupied_entry) = request.headers_mut().entry(COOKIE) {
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
        // Get HTTP/1.1 sender and remote log channel with upgrades with a new connection
        let io = match proxy_data.proxy_type {
            ProxyType::Tunneling => {
                handler
                    .tunneling_channel(tcp_address.ip(), tcp_address.port())
                    .await
            }
            ProxyType::Aliasing => {
                handler
                    .aliasing_channel(tcp_address.ip(), tcp_address.port(), key.2.as_ref())
                    .await
            }
        };
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io?)).await?;
        tokio::spawn(Box::pin(async move {
            if let Err(error) = conn.with_upgrades().await {
                #[cfg(not(coverage_nightly))]
                tracing::warn!(%error, "HTTP/1.1 connection failed.");
            }
        }));
        let tx = handler.log_channel();

        // If there is an Upgrade header, make sure that it's a valid Websocket upgrade
        let request_type = request_upgrade.to_str()?.to_string();
        // Retrieve the OnUpgrade from the incoming request
        let upgraded_request = hyper::upgrade::on(&mut request);
        let mut response = match proxy_data.http_request_timeout {
            // Await for a response under the given duration.
            Some(duration) => {
                if let Ok(response) = timeout(duration, sender.send_request(request)).await {
                    response?
                } else {
                    let elapsed_time = timer.elapsed();
                    http_log(
                        http_log_builder
                            .status(StatusCode::GATEWAY_TIMEOUT.as_u16())
                            .elapsed_time(elapsed_time)
                            .build(),
                        Some(tx),
                        proxy_data.disable_http_logs,
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
                        let mut upgraded_request =
                            TokioIo::new(upgraded_request.await.expect("upgradable request"));
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
                let http_log_builder = http_log_builder.status(response.status().as_u16());
                Ok(ProxyResponse::Proxy(TimedResponse {
                    response,
                    on_drop: Some(Box::new(move || {
                        http_log(
                            http_log_builder.elapsed_time(timer.elapsed()).build(),
                            Some(tx),
                            proxy_data.disable_http_logs,
                        )
                    })),
                }))
            }
            _ => {
                let http_log_builder = http_log_builder.status(response.status().as_u16());
                Ok(ProxyResponse::Proxy(TimedResponse {
                    response,
                    on_drop: Some(Box::new(move || {
                        http_log(
                            http_log_builder.elapsed_time(timer.elapsed()).build(),
                            Some(tx),
                            proxy_data.disable_http_logs,
                        )
                    })),
                }))
            }
        }
    } else {
        loop {
            // If Upgrade header is not present, get HTTP/1.1 sender and remote log channel
            let (mut sender, tx, _guard) = if proxy_data.has_pool_queue
                && let Some(guard) = proxy_data.get_http11_pool_guard(key.clone())
            {
                // Race between new channel and HTTP pool
                let mut recv = guard.pool.recv();
                let mut channel_future = pin!(async {
                    match proxy_data.proxy_type {
                        ProxyType::Tunneling => {
                            handler
                                .tunneling_channel(tcp_address.ip(), tcp_address.port())
                                .await
                        }
                        ProxyType::Aliasing => {
                            handler
                                .aliasing_channel(
                                    tcp_address.ip(),
                                    tcp_address.port(),
                                    key.2.as_ref(),
                                )
                                .await
                        }
                    }
                });
                loop {
                    tokio::select! {
                        result = recv => {
                            match result {
                                // Return pool item
                                Ok(tuple) if tuple.0.is_ready() => break (tuple.0, tuple.1, guard),
                                // Connection is closed; discard pool item
                                Ok(_) => {
                                    recv = guard.pool.recv();
                                    continue;
                                },
                                Err(_) => return Err(HttpError::PoolClosed),
                            }
                        }
                        result = &mut channel_future => {
                            let (sender, conn) = hyper::client::conn::http1::handshake(
                                TokioIo::new(result?),
                            )
                            .await?;
                            tokio::spawn(Box::pin(async move {
                                if let Err(error) = conn.await {
                                    #[cfg(not(coverage_nightly))]
                                    tracing::warn!(%error, "HTTP/1.1 connection failed.");
                                }
                            }));
                            break (sender, handler.log_channel(), guard);
                        }
                    }
                }
            } else {
                // No pool timeout - get recycled sender or create new one
                'sender: loop {
                    match proxy_data.get_http11_pool_guard(key.clone()) {
                        Some(guard) => {
                            while let Ok(sender) = guard.pool.try_recv() {
                                if sender.0.is_ready() {
                                    break 'sender (sender.0, sender.1, guard);
                                }
                            }
                        }
                        None => {
                            let io = match proxy_data.proxy_type {
                                ProxyType::Tunneling => {
                                    handler
                                        .tunneling_channel(tcp_address.ip(), tcp_address.port())
                                        .await
                                }
                                ProxyType::Aliasing => {
                                    handler
                                        .aliasing_channel(
                                            tcp_address.ip(),
                                            tcp_address.port(),
                                            key.2.as_ref(),
                                        )
                                        .await
                                }
                            };
                            let (sender, conn) =
                                hyper::client::conn::http1::handshake(TokioIo::new(io?)).await?;
                            tokio::spawn(Box::pin(async move {
                                if let Err(error) = conn.await {
                                    #[cfg(not(coverage_nightly))]
                                    tracing::warn!(%error, "HTTP/1.1 connection failed.");
                                }
                            }));
                            let guard = proxy_data.create_http11_pool_guard(key.clone());
                            break (sender, handler.log_channel(), guard);
                        }
                    }
                }
            };

            // Create entry for pool
            let key_clone = key.clone();
            let pool = {
                let pool_ref = proxy_data
                    .keepalive_http11_pool_map
                    .entry(key_clone)
                    .or_insert_with(|| Arc::new(async_channel::unbounded()))
                    .downgrade();
                pool_ref.0.clone()
            };

            let response = match proxy_data.http_request_timeout {
                // Await for a response under the given duration.
                Some(duration) => {
                    if let Ok(response) = timeout(duration, sender.try_send_request(request)).await
                    {
                        response
                    } else {
                        let elapsed_time = timer.elapsed();
                        http_log(
                            http_log_builder
                                .status(StatusCode::GATEWAY_TIMEOUT.as_u16())
                                .elapsed_time(elapsed_time)
                                .build(),
                            Some(tx),
                            proxy_data.disable_http_logs,
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
                        let elapsed_time = timer.elapsed();
                        http_log(
                            http_log_builder
                                .status(StatusCode::INTERNAL_SERVER_ERROR.as_u16())
                                .elapsed_time(elapsed_time)
                                .build(),
                            Some(tx),
                            proxy_data.disable_http_logs,
                        );
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
                        proxy_data.disable_http_logs,
                    );
                    // Return sender to pool
                    tokio::spawn(async move {
                        let _ = pool.send((sender, tx)).await;
                    });
                })),
            }));
        }
    }
}
