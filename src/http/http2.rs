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

use std::{error::Error, fmt::Debug, net::SocketAddr, sync::Arc, time::Instant};

use crate::{
    connection_handler::ConnectionHandler,
    connections::ConnectionGetByHttpHost,
    http::{
        ArcProxyData, Http2PoolGuard, Http2SendRequest, HttpError, HttpLog, PooledConnection,
        ProxyData, ProxyResponse, ProxyType, TimedResponse, http_log, take_ready_connection,
    },
    keepalive::KeepaliveAlias,
    ssh::ServerHandlerSender,
};

use http::{Uri, header::CONNECTION, uri::Authority};
use hyper::{Request, StatusCode, body::Body};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::timeout,
};

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
        let guard = proxy_data.get_http2_pool_guard(key.clone());
        // Reuse a pooled connection rather than opening a channel for it.
        let (mut sender, tx, _guard) = if let Some(pooled) =
            take_ready_connection(&guard.pool, guard.max_idle_time, guard.max_reuse)
        {
            (pooled.connection, pooled.log_sender, guard)
        } else if proxy_data.pool_queue_timeout.is_some() {
            // Race a new channel against a connection returned to the pool.
            //
            // The open runs in its own task: russh only hands back the channel
            // once the client confirms it, so dropping an open future
            // mid-flight would leave the channel open on the session with
            // nobody left to close it. An abandoned task still runs to
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
                        break spawn_http2_connection(io, handler.log_channel(), guard).await?;
                    }
                }
            }
        } else {
            let io = open_channel(&proxy_data, &handler, tcp_address, &key).await?;
            spawn_http2_connection(io, handler.log_channel(), guard).await?
        };

        // Create entry for pool
        let key_clone = key.clone();
        let pool_size = proxy_data.http_pool_size;

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
                        proxy_data.log_format,
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
                    proxy_data.log_format,
                );
                // Send sender to pool
                let pooled = PooledConnection::new(sender, tx);
                {
                    let pool_ref = proxy_data
                        .keepalive_http2_pool_map
                        .entry(key_clone)
                        .or_insert_with(|| deadpool::unmanaged::Pool::new(pool_size))
                        .downgrade();
                    if let Err(error) = pool_ref.try_add(pooled) {
                        #[cfg(not(coverage_nightly))]
                        tracing::warn!(error = %error.1, "Failed to add HTTP/2 connection back to pool.");
                    }
                }
                drop(_guard);
            })),
        }));
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

// Start an HTTP/2 connection over a freshly opened channel.
async fn spawn_http2_connection<B, T>(
    io: T,
    tx: ServerHandlerSender,
    guard: Http2PoolGuard<B>,
) -> Result<(Http2SendRequest<B>, ServerHandlerSender, Http2PoolGuard<B>), HttpError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: Body + Debug + Send + Unpin + 'static,
    <B as Body>::Data: Send + Sync + 'static,
    <B as Body>::Error: Error + Send + Sync + 'static,
{
    let (sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io)).await?;
    tokio::spawn(Box::pin(async move {
        if let Err(error) = conn.await {
            #[cfg(not(coverage_nightly))]
            tracing::warn!(%error, "HTTP/2 connection failed.");
        }
    }));
    Ok((sender, tx, guard))
}
