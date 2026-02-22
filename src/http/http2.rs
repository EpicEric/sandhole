use std::{error::Error, fmt::Debug, net::SocketAddr, pin::pin, sync::Arc, time::Instant};

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
use http::{Uri, header::CONNECTION, uri::Authority};
use hyper::{Request, Response, StatusCode, body::Body};
use hyper_util::rt::{TokioExecutor, TokioIo};
use metrics::counter;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::timeout,
};

#[cfg_attr(
    not(coverage_nightly),
    tracing::instrument(skip(proxy_data, handler), level = "debug")
)]
pub(crate) async fn https_2_handler<B, M, H, T>(
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
    match http2_handler_inner(request, tcp_address, proxy_data, handler, host).await {
        Ok(response) => Ok(match response {
            ProxyResponse::Axum(response) => response,
            ProxyResponse::Proxy(response) => response.into_response(),
        }),
        Err(error) => Ok(error.into_response()),
    }
}

#[inline]
async fn http2_handler_inner<B, M, H, T>(
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
    let Some(host_uri) = request.uri().host() else {
        return Err(HttpError::MissingHostHeader);
    };
    if host != host_uri {
        // Fallback to legacy behavior
        return proxy_handler_inner(request, tcp_address, None, proxy_data).await;
    };

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
    handle_http2_request(
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

pub(crate) async fn handle_http2_request<B, M, H, T>(
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

    loop {
        // Get HTTP/2 sender and remote log channel
        let (mut sender, tx, _guard) = if proxy_data.has_pool_queue
            && let Some(guard) = proxy_data.get_http2_pool_guard(key.clone())
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
                            .aliasing_channel(tcp_address.ip(), tcp_address.port(), key.2.as_ref())
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
                        let (sender, conn) = hyper::client::conn::http2::handshake(
                            TokioExecutor::new(),
                            TokioIo::new(result?),
                        )
                        .await?;
                        tokio::spawn(Box::pin(async move {
                            if let Err(error) = conn.await {
                                #[cfg(not(coverage_nightly))]
                                tracing::warn!(%error, "HTTP/2 connection failed.");
                            }
                        }));
                        break (sender, handler.log_channel(), guard);
                    }
                }
            }
        } else {
            // No pool timeout - get recycled sender or create new one
            'sender: loop {
                match proxy_data.get_http2_pool_guard(key.clone()) {
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
                        let (sender, conn) = hyper::client::conn::http2::handshake(
                            TokioExecutor::new(),
                            TokioIo::new(io?),
                        )
                        .await?;
                        tokio::spawn(Box::pin(async move {
                            if let Err(error) = conn.await {
                                #[cfg(not(coverage_nightly))]
                                tracing::warn!(%error, "HTTP/2 connection failed.");
                            }
                        }));
                        let guard = proxy_data.create_http2_pool_guard(key.clone());
                        break (sender, handler.log_channel(), guard);
                    }
                }
            }
        };

        // Create entry for pool
        let key_clone = key.clone();
        let pool = {
            let pool_ref = proxy_data
                .keepalive_http2_pool_map
                .entry(key_clone)
                .or_insert_with(|| Arc::new(async_channel::unbounded()))
                .downgrade();
            pool_ref.0.clone()
        };

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

        let response = match proxy_data.http_request_timeout {
            // Await for a response under the given duration.
            Some(duration) => {
                if let Ok(response) = timeout(duration, sender.try_send_request(request)).await {
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
                    tracing::debug!(error = %error.error(), "Recovering HTTP/2 request to try again.");
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
                // Send sender to pool
                tokio::spawn(async move {
                    let _ = pool.send((sender, tx)).await;
                });
            })),
        }));
    }
}
