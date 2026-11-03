// sandhole: Expose HTTP/SSH/TCP services through SSH port forwarding
// Copyright (C) 2024-2026 Eric Rodrigues Pires
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for
// more details.
//
// You should have received a copy of the GNU Affero General Public License along
// with this program. If not, see <https://www.gnu.org/licenses/>.

use std::{error::Error, fmt::Debug, net::SocketAddr, str::FromStr, sync::Arc, time::Instant};

use crate::{
    connection_handler::ConnectionHandler,
    connections::ConnectionGetByHttpHost,
    http::{
        ArcProxyData, Http11PoolGuard, Http11SendRequest, HttpError, HttpLog, PooledConnection,
        ProxyData, ProxyResponse, ProxyType, TimedResponse, http_log, take_ready_connection,
    },
    keepalive::KeepaliveAlias,
    ssh::ServerHandlerSender,
};

use http::Uri;
use http::header::COOKIE;
use hyper::{
    Request, StatusCode,
    body::Body,
    header::{HOST, UPGRADE},
};
use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncRead, AsyncWrite, copy_bidirectional_with_sizes},
    time::timeout,
};

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
                        proxy_data.log_format,
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
                                let _ = timeout(
                                    duration,
                                    copy_bidirectional_with_sizes(
                                        &mut upgraded_response,
                                        &mut upgraded_request,
                                        buffer_size,
                                        buffer_size,
                                    ),
                                )
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
                            proxy_data.log_format,
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
                            proxy_data.log_format,
                        )
                    })),
                }))
            }
        }
    } else {
        loop {
            let guard = proxy_data.get_http11_pool_guard(key.clone());
            // Reuse a pooled connection rather than opening a channel for it.
            let (mut sender, tx, _guard) = if let Some(pooled) =
                take_ready_connection(&guard.pool, guard.max_idle_time, guard.max_reuse)
            {
                (pooled.connection, pooled.log_sender, guard)
            } else if proxy_data.pool_queue_timeout.is_some() {
                // Race a new channel against a connection returned to the pool.
                //
                // The open runs in its own task: russh only hands back the
                // channel once the client confirms it, so dropping an open
                // future mid-flight would leave the channel open on the session
                // with nobody left to close it. An abandoned task still runs to
                // completion, and dropping its result drops the channel.
                let mut open_task = tokio::spawn({
                    let proxy_data = Arc::clone(&proxy_data);
                    let handler = Arc::clone(&handler);
                    let key = key.clone();
                    async move { open_channel(&proxy_data, &handler, tcp_address, &key).await }
                });
                let mut recv = guard.pool.get();
                loop {
                    tokio::select! {
                        result = recv => {
                            match result {
                                Ok(pooled) => {
                                    let mut pooled = deadpool::unmanaged::Object::take(pooled);
                                    if pooled.connection.is_ready()
                                        && !pooled.is_expired(guard.max_idle_time, guard.max_reuse) {
                                        pooled.touch();
                                        break (pooled.connection, pooled.log_sender, guard);
                                    }
                                    recv = guard.pool.get();
                                },
                                Err(deadpool::unmanaged::PoolError::Timeout) => {
                                    return Err(HttpError::NoHandlerAvailable);
                                },
                                Err(_) => return Err(HttpError::PoolClosed),
                            }
                        }
                        result = &mut open_task => {
                            let io = result.map_err(|_| HttpError::PoolClosed)??;
                            break spawn_http11_connection(io, handler.log_channel(), guard).await?;
                        }
                    }
                }
            } else {
                let io = open_channel(&proxy_data, &handler, tcp_address, &key).await?;
                spawn_http11_connection(io, handler.log_channel(), guard).await?
            };

            // Create entry for pool
            let key_clone = key.clone();
            let pool_size = proxy_data.http_pool_size;

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
                            proxy_data.log_format,
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
                            proxy_data.log_format,
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
                        proxy_data.log_format,
                    );
                    // Return sender to pool
                    let pooled = PooledConnection::new(sender, tx);
                    {
                        let pool_ref = proxy_data
                            .keepalive_http11_pool_map
                            .entry(key_clone)
                            .or_insert_with(|| deadpool::unmanaged::Pool::new(pool_size))
                            .downgrade();
                        if let Err(error) = pool_ref.try_add(pooled) {
                            #[cfg(not(coverage_nightly))]
                            tracing::warn!(error = %error.1, "Failed to add HTTP/1.1 connection back to pool.");
                        }
                    }
                    drop(_guard);
                })),
            }));
        }
    }
}

// Open a channel to the proxied service.
//
// The returned future must be driven to completion: russh keeps the channel
// open on the session if the open is cancelled before the client confirms it.
async fn open_channel<B, M, H, T>(
    proxy_data: &ProxyData<B, M, H, T>,
    handler: &H,
    tcp_address: SocketAddr,
    key: &KeepaliveAlias,
) -> Result<T, HttpError>
where
    M: ConnectionGetByHttpHost<Arc<H>> + Send + Sync + 'static,
    H: ConnectionHandler<T> + Send + Sync + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    B: Body + Debug + Send + Unpin + 'static,
    <B as Body>::Data: Send + Sync + 'static,
    <B as Body>::Error: Error + Send + Sync + 'static,
{
    let channel = match proxy_data.proxy_type {
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
    Ok(channel?)
}

// Start an HTTP/1.1 connection over a freshly opened channel.
async fn spawn_http11_connection<B, T>(
    io: T,
    tx: ServerHandlerSender,
    guard: Http11PoolGuard<B>,
) -> Result<
    (
        Http11SendRequest<B>,
        ServerHandlerSender,
        Http11PoolGuard<B>,
    ),
    HttpError,
>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: Body + Debug + Send + Unpin + 'static,
    <B as Body>::Data: Send + Sync + 'static,
    <B as Body>::Error: Error + Send + Sync + 'static,
{
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
    tokio::spawn(Box::pin(async move {
        if let Err(error) = conn.await {
            #[cfg(not(coverage_nightly))]
            tracing::warn!(%error, "HTTP/1.1 connection failed.");
        }
    }));
    Ok((sender, tx, guard))
}
