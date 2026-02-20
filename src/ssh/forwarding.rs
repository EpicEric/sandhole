use std::{
    borrow::Borrow,
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
};

use chrono::Utc;
use color_eyre::eyre::eyre;
use http::Request;
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use metrics::{counter, gauge};
use owo_colors::OwoColorize;
use russh::{
    Channel,
    keys::ssh_key::Fingerprint,
    server::{Handle, Msg},
};
use tokio::{io::copy_bidirectional_with_sizes, sync::Semaphore, time::timeout};

use crate::{
    SandholeServer,
    admin::ADMIN_ALIAS_PORT,
    connection_handler::ConnectionHandler,
    connections::ConnectionGetByHttpHost,
    http::proxy_handler,
    ssh::{
        AuthenticatedData, ServerHandlerSender, UserData, auth::UserSessionRestriction,
        connection_handler::SshTunnelHandler,
    },
    tcp::PortHandler,
    tcp_alias::{BorrowedTcpAlias, TcpAlias, TcpAliasKey},
    telemetry::{
        TELEMETRY_COUNTER_ADMIN_ALIAS_CONNECTIONS, TELEMETRY_COUNTER_ALIAS_CONNECTIONS,
        TELEMETRY_COUNTER_SNI_CONNECTIONS, TELEMETRY_COUNTER_SSH_CONNECTIONS,
        TELEMETRY_COUNTER_TCP_CONNECTIONS, TELEMETRY_GAUGE_ADMIN_ALIAS_CONNECTIONS_CURRENT,
        TELEMETRY_GAUGE_ALIAS_CONNECTIONS_CURRENT, TELEMETRY_GAUGE_SNI_CONNECTIONS_CURRENT,
        TELEMETRY_GAUGE_SSH_CONNECTIONS_CURRENT, TELEMETRY_GAUGE_TCP_CONNECTIONS_CURRENT,
        TELEMETRY_KEY_ALIAS, TELEMETRY_KEY_HOSTNAME, TELEMETRY_KEY_PORT,
    },
};

pub(crate) struct RemoteForwardingContext<'a> {
    pub(crate) server: &'a Arc<SandholeServer>,
    pub(crate) user_data: &'a mut UserData,
    pub(crate) peer: &'a SocketAddr,
    pub(crate) user: &'a Option<String>,
    pub(crate) key_fingerprint: &'a Option<Fingerprint>,
    pub(crate) tx: &'a ServerHandlerSender,
}

pub(crate) struct LocalForwardingContext<'a> {
    pub(crate) server: &'a Arc<SandholeServer>,
    pub(crate) auth_data: &'a mut AuthenticatedData,
    pub(crate) peer: &'a SocketAddr,
    pub(crate) key_fingerprint: &'a Option<Fingerprint>,
    pub(crate) tx: &'a ServerHandlerSender,
}

pub(crate) trait ForwardingHandlerStrategy {
    async fn remote_forwarding(
        &mut self,
        context: &mut RemoteForwardingContext,
        address: &str,
        port: &mut u32,
        handle: Handle,
    ) -> Result<bool, russh::Error>;

    async fn cancel_remote_forwarding(
        &mut self,
        context: &mut RemoteForwardingContext,
        address: &str,
        port: u16,
    ) -> Result<bool, russh::Error>;

    async fn local_forwarding(
        &mut self,
        context: &mut LocalForwardingContext,
        address: &str,
        port: u16,
        originator_address: &str,
        originator_port: u16,
        channel: Channel<Msg>,
    ) -> Result<bool, russh::Error>;
}

pub(crate) struct Forwarder;

impl Forwarder {
    pub(crate) async fn remote_forwarding(
        context: &mut RemoteForwardingContext<'_>,
        address: &str,
        port: &mut u32,
        ssh_port: u16,
        http_port: Option<u16>,
        https_port: Option<u16>,
        handle: Handle,
    ) -> Result<bool, russh::Error> {
        if *port == 22 || *port == u32::from(ssh_port) {
            SshForwardingHandler
                .remote_forwarding(context, address, port, handle)
                .await
        } else if *port == 80
            || *port == 443
            || http_port.is_some_and(|http_port| *port == u32::from(http_port))
            || https_port.is_some_and(|https_port| *port == u32::from(https_port))
        {
            HttpForwardingHandler
                .remote_forwarding(context, address, port, handle)
                .await
        } else if context.server.is_alias(address) {
            AliasForwardingHandler
                .remote_forwarding(context, address, port, handle)
                .await
        } else {
            TcpForwardingHandler
                .remote_forwarding(context, address, port, handle)
                .await
        }
    }

    pub(crate) async fn cancel_remote_forwarding(
        context: &mut RemoteForwardingContext<'_>,
        address: &str,
        port: u16,
        ssh_port: u16,
        http_port: Option<u16>,
        https_port: Option<u16>,
    ) -> Result<bool, russh::Error> {
        match port {
            port if port == 22 || port == ssh_port => {
                SshForwardingHandler
                    .cancel_remote_forwarding(context, address, port)
                    .await
            }
            port if port == 80
                || port == 443
                || http_port.is_some_and(|http_port| port == http_port)
                || https_port.is_some_and(|https_port| port == https_port) =>
            {
                HttpForwardingHandler
                    .cancel_remote_forwarding(context, address, port)
                    .await
            }
            _ if context.server.is_alias(address) => {
                AliasForwardingHandler
                    .cancel_remote_forwarding(context, address, port)
                    .await
            }
            _ => {
                TcpForwardingHandler
                    .cancel_remote_forwarding(context, address, port)
                    .await
            }
        }
    }

    pub(crate) async fn local_forwarding(
        context: &mut LocalForwardingContext<'_>,
        address: &str,
        port: u16,
        originator_address: &str,
        originator_port: u16,
        channel: Channel<Msg>,
    ) -> Result<bool, russh::Error> {
        if port == 22 || port == context.server.ssh_port {
            SshForwardingHandler
                .local_forwarding(
                    context,
                    address,
                    port,
                    originator_address,
                    originator_port,
                    channel,
                )
                .await
        } else if port == 80
            || port == 443
            || port == context.server.http_port
            || port == context.server.https_port
        {
            HttpForwardingHandler
                .local_forwarding(
                    context,
                    address,
                    port,
                    originator_address,
                    originator_port,
                    channel,
                )
                .await
        } else if context.server.is_alias(address) {
            AliasForwardingHandler
                .local_forwarding(
                    context,
                    address,
                    port,
                    originator_address,
                    originator_port,
                    channel,
                )
                .await
        } else {
            TcpForwardingHandler
                .local_forwarding(
                    context,
                    address,
                    port,
                    originator_address,
                    originator_port,
                    channel,
                )
                .await
        }
    }
}

pub(crate) struct SshForwardingHandler;
pub(crate) struct HttpForwardingHandler;
pub(crate) struct AliasForwardingHandler;
pub(crate) struct TcpForwardingHandler;

impl ForwardingHandlerStrategy for SshForwardingHandler {
    async fn remote_forwarding(
        &mut self,
        context: &mut RemoteForwardingContext<'_>,
        address: &str,
        port: &mut u32,
        handle: Handle,
    ) -> Result<bool, russh::Error> {
        if context.server.disable_aliasing {
            let _ = context.tx.send(
                format!(
                    "{} {} Aliasing is disabled\r\n",
                    Utc::now().to_rfc3339().dimmed(),
                    "Error".black().on_red().bold()
                )
                .into_bytes(),
            );
            return Ok(false);
        }
        // SSH host must be alias (to be accessed via ProxyJump or ProxyCommand)
        if !context.server.is_alias(address) {
            let error = eyre!("must be alias, not localhost");
            #[cfg(not(coverage_nightly))]
            tracing::info!(
                peer = %context.peer, alias = %address, %error,
                "Failed to bind SSH alias.",
            );
            let _ = context.tx.send(
                format!(
                    "{} {} Alias is required for SSH host\r\n",
                    Utc::now().to_rfc3339().dimmed(),
                    " Error ".black().on_red().bold(),
                )
                .into_bytes(),
            );
            return Ok(false);
        }
        // Add handler to SSH connection map
        let semaphore = Arc::new(Semaphore::new(
            context.user_data.max_pool_size.load(Ordering::Acquire),
        ));
        match context.server.ssh.insert(
            address.to_string(),
            *context.peer,
            context.user_data.quota_key.clone(),
            Arc::new(SshTunnelHandler {
                allow_fingerprint: Arc::clone(&context.user_data.allow_fingerprint),
                http_data: None,
                pool: Arc::clone(&semaphore),
                pool_timeout: context.server.pool_timeout,
                ip_connections: Arc::default(),
                max_connections_per_ip: context.server.max_connections_per_ip,
                ip_filter: Arc::clone(&context.user_data.ip_filter),
                handle,
                tx: context.tx.clone(),
                peer: *context.peer,
                address: address.to_string(),
                port: *port,
                limiter: context.user_data.limiter.clone(),
            }),
        ) {
            Err(error) => {
                // Adding to connection map failed.
                #[cfg(not(coverage_nightly))]
                tracing::info!(peer = %context.peer, alias = %address, %error, "Rejecting SSH.");
                let _ = context.tx.send(
                    format!(
                        "{} {} Cannot listen to SSH on {}:{} ({})\r\n",
                        Utc::now().to_rfc3339().dimmed(),
                        " Error ".black().on_red().bold(),
                        address,
                        context.server.ssh_port,
                        error,
                    )
                    .into_bytes(),
                );
                Ok(false)
            }
            _ => {
                // Adding to connection map succeeded.
                #[cfg(not(coverage_nightly))]
                tracing::info!(peer = %context.peer, alias = %address, "Serving SSH connection...");
                let _ = context.tx.send(
                    format!(
                        "{} {:>14} forwarding on {}:{}\r\n{}{}\r\n",
                        Utc::now().to_rfc3339().dimmed(),
                        "Starting SSH".green().bold(),
                        address,
                        context.server.ssh_port,
                        "  = hint: connect with ".dimmed(),
                        if context.server.ssh_port == 22 {
                            format!(
                                " ssh -J {} {} ",
                                context
                                    .server
                                    .domain
                                    .as_deref()
                                    .unwrap_or("<Sandhole's IP>"),
                                address
                            )
                        } else {
                            format!(
                                " ssh -J {}:{} {} -p {} ",
                                context
                                    .server
                                    .domain
                                    .as_deref()
                                    .unwrap_or("<Sandhole's IP>"),
                                context.server.ssh_port,
                                address,
                                context.server.ssh_port
                            )
                        }
                        .black()
                        .on_white()
                        .bold(),
                    )
                    .into_bytes(),
                );
                context.user_data.host_addressing.insert(
                    TcpAlias(address.to_string(), *port as u16),
                    (address.to_string(), semaphore),
                );
                Ok(true)
            }
        }
    }

    async fn cancel_remote_forwarding(
        &mut self,
        context: &mut RemoteForwardingContext<'_>,
        address: &str,
        port: u16,
    ) -> Result<bool, russh::Error> {
        if let Some(assigned_host) = context
            .user_data
            .host_addressing
            .remove(&BorrowedTcpAlias(address, &port) as &dyn TcpAliasKey)
        {
            context.server.ssh.remove(&assigned_host.0, context.peer);
            #[cfg(not(coverage_nightly))]
            tracing::info!(
                peer = %context.peer, alias = &assigned_host.0,
                "Stopped SSH forwarding.",
            );
            let _ = context.tx.send(
                format!(
                    "{} {:>14} forwarding on {}:{}\r\n",
                    Utc::now().to_rfc3339().dimmed(),
                    "Stopping SSH".yellow().bold(),
                    address,
                    context.server.ssh_port,
                )
                .into_bytes(),
            );
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn local_forwarding(
        &mut self,
        context: &mut LocalForwardingContext<'_>,
        address: &str,
        port: u16,
        originator_address: &str,
        originator_port: u16,
        channel: Channel<Msg>,
    ) -> Result<bool, russh::Error> {
        let ip = context.peer.ip().to_canonical();
        if let Some(handler) = context.server.ssh.get(address, ip)
            && let Ok(mut io) = handler
                .aliasing_channel(
                    context.peer.ip(),
                    context.peer.port(),
                    context.key_fingerprint.as_ref(),
                )
                .await
        {
            let gauge = gauge!(TELEMETRY_GAUGE_SSH_CONNECTIONS_CURRENT, TELEMETRY_KEY_ALIAS => address.to_string());
            gauge.increment(1);
            counter!(TELEMETRY_COUNTER_SSH_CONNECTIONS, TELEMETRY_KEY_ALIAS => address.to_string())
                .increment(1);
            let _ = handler.log_channel().send(
                format!(
                    "{} {:>14} - {}:{} => {}:{}\r\n",
                    Utc::now().to_rfc3339().dimmed(),
                    "Proxying SSH".blue().bold(),
                    originator_address,
                    originator_port,
                    address,
                    port,
                )
                .into_bytes(),
            );
            match context.auth_data {
                // Serve SSH for unauthed user, then add disconnection timeout if this is the last proxy connection
                AuthenticatedData::None { proxy_data } => {
                    let guard = proxy_data.clone();
                    let tcp_connection_timeout = context.server.tcp_connection_timeout;
                    let buffer_size = context.server.buffer_size;
                    tokio::spawn(async move {
                        let mut stream = channel.into_stream();
                        match tcp_connection_timeout {
                            Some(duration) => {
                                let _ = timeout(duration, async {
                                    copy_bidirectional_with_sizes(
                                        &mut stream,
                                        &mut io,
                                        buffer_size,
                                        buffer_size,
                                    )
                                    .await
                                })
                                .await;
                            }
                            None => {
                                let _ = copy_bidirectional_with_sizes(
                                    &mut stream,
                                    &mut io,
                                    buffer_size,
                                    buffer_size,
                                )
                                .await;
                            }
                        }
                        drop(guard);
                        gauge.decrement(1);
                    });
                }
                // Serve SSH normally for authed user
                _ => {
                    let tcp_connection_timeout = context.server.tcp_connection_timeout;
                    let buffer_size = context.server.buffer_size;
                    tokio::spawn(async move {
                        let mut stream = channel.into_stream();
                        match tcp_connection_timeout {
                            Some(duration) => {
                                let _ = timeout(duration, async {
                                    copy_bidirectional_with_sizes(
                                        &mut stream,
                                        &mut io,
                                        buffer_size,
                                        buffer_size,
                                    )
                                    .await
                                })
                                .await;
                            }
                            None => {
                                let _ = copy_bidirectional_with_sizes(
                                    &mut stream,
                                    &mut io,
                                    buffer_size,
                                    buffer_size,
                                )
                                .await;
                            }
                        }
                        gauge.decrement(1);
                    });
                }
            }
            #[cfg(not(coverage_nightly))]
            tracing::debug!(
                peer = %context.peer, remote = %handler.peer, alias = %address,
                "Accepted SSH connection.",
            );
            return Ok(true);
        }
        let _ = context.tx.send(
            format!(
                "{} {} Unknown SSH alias '{}'\r\n",
                Utc::now().to_rfc3339().dimmed(),
                " Error ".black().on_red().bold(),
                address,
            )
            .into_bytes(),
        );
        Ok(false)
    }
}

impl ForwardingHandlerStrategy for HttpForwardingHandler {
    async fn remote_forwarding(
        &mut self,
        context: &mut RemoteForwardingContext<'_>,
        address: &str,
        port: &mut u32,
        handle: Handle,
    ) -> Result<bool, russh::Error> {
        // Handle alias-only mode
        if matches!(
            context.user_data.session_restriction,
            UserSessionRestriction::TcpAliasOnly
        ) {
            // HTTP host must be alias (to be accessed via local forwarding)
            if !context.server.is_alias(address) {
                let error = eyre!("must be alias, not localhost");
                #[cfg(not(coverage_nightly))]
                tracing::info!(
                    peer = %context.peer, alias = %address, %error,
                    "Failed to bind HTTP alias.",
                );
                let _ = context.tx.send(
                    format!(
                        "{} {} Failed to bind HTTP alias '{}' ({})\r\n",
                        Utc::now().to_rfc3339().dimmed(),
                        " Error ".black().on_red().bold(),
                        address,
                        error,
                    )
                    .into_bytes(),
                );
                return Ok(false);
            }
            // Add handler to TCP connection map
            let semaphore = Arc::new(Semaphore::new(
                context.user_data.max_pool_size.load(Ordering::Acquire),
            ));
            match context.server.alias.insert(
                TcpAlias(address.into(), 80),
                *context.peer,
                context.user_data.quota_key.clone(),
                Arc::new(SshTunnelHandler {
                    allow_fingerprint: Arc::clone(&context.user_data.allow_fingerprint),
                    http_data: Some(Arc::clone(&context.user_data.http_data)),
                    pool: Arc::clone(&semaphore),
                    pool_timeout: context.server.pool_timeout,
                    ip_connections: Arc::default(),
                    max_connections_per_ip: context.server.max_connections_per_ip,
                    ip_filter: Arc::clone(&context.user_data.ip_filter),
                    handle,
                    tx: context.tx.clone(),
                    peer: *context.peer,
                    address: address.into(),
                    port: *port,
                    limiter: context.user_data.limiter.clone(),
                }),
            ) {
                Err(error) => {
                    // Adding to connection map failed.
                    #[cfg(not(coverage_nightly))]
                    tracing::info!(
                        peer = %context.peer, %error, alias = %address,
                        "Rejecting HTTP alias.",
                    );
                    let _ = context.tx.send(
                        format!(
                            "{} {} Failed to bind HTTP alias '{}' ({})\r\n",
                            Utc::now().to_rfc3339().dimmed(),
                            " Error ".black().on_red().bold(),
                            address,
                            error,
                        )
                        .into_bytes(),
                    );
                    Ok(false)
                }
                _ => {
                    // Adding to connection map succeeded.
                    #[cfg(not(coverage_nightly))]
                    tracing::info!(peer = %context.peer, alias = %address, "Tunneling HTTP...");
                    let _ = context.tx.send(
                        format!(
                            "{} {:>14} tunneling for HTTP alias {}:{}\r\n",
                            Utc::now().to_rfc3339().dimmed(),
                            "Starting alias".green().bold(),
                            address,
                            port,
                        )
                        .into_bytes(),
                    );
                    context.user_data.alias_addressing.insert(
                        TcpAlias(address.into(), 80),
                        (TcpAlias(address.into(), 80), semaphore),
                    );
                    Ok(true)
                }
            }
        // Handle SNI proxy-only mode
        } else if matches!(
            context.user_data.session_restriction,
            UserSessionRestriction::SniProxyOnly
        ) {
            // Assign an HTTP address according to server policies
            match context
                .server
                .address_delegator
                .get_http_address(address, context.user, context.key_fingerprint, context.peer)
                .await
            {
                Ok(assigned_host) => {
                    // Add handler to TCP connection map
                    let semaphore = Arc::new(Semaphore::new(
                        context.user_data.max_pool_size.load(Ordering::Acquire),
                    ));
                    match context.server.sni.insert(
                        assigned_host.clone(),
                        *context.peer,
                        context.user_data.quota_key.clone(),
                        Arc::new(SshTunnelHandler {
                            allow_fingerprint: Arc::clone(&context.user_data.allow_fingerprint),
                            http_data: Some(Arc::clone(&context.user_data.http_data)),
                            pool: Arc::clone(&semaphore),
                            pool_timeout: context.server.pool_timeout,
                            ip_connections: Arc::default(),
                            max_connections_per_ip: context.server.max_connections_per_ip,
                            ip_filter: Arc::clone(&context.user_data.ip_filter),
                            handle,
                            tx: context.tx.clone(),
                            peer: *context.peer,
                            address: address.into(),
                            port: *port,
                            limiter: context.user_data.limiter.clone(),
                        }),
                    ) {
                        Err(error) => {
                            // Adding to connection map failed.
                            #[cfg(not(coverage_nightly))]
                            tracing::info!(
                                peer = %context.peer, %error, host = %address,
                                "Rejecting SNI proxy.",
                            );
                            let _ = context.tx.send(
                                format!(
                                    "{} {} Failed to bind SNI proxy '{}' ({})\r\n",
                                    Utc::now().to_rfc3339().dimmed(),
                                    " Error ".black().on_red().bold(),
                                    address,
                                    error,
                                )
                                .into_bytes(),
                            );
                            Ok(false)
                        }
                        _ => {
                            // Adding to connection map succeeded.
                            #[cfg(not(coverage_nightly))]
                            tracing::info!(peer = %context.peer, host = %address, "Serving SNI proxy...",);
                            let _ = context.tx.send(
                                format!(
                                    "{} {:>14} proxy for {}\r\n",
                                    Utc::now().to_rfc3339().dimmed(),
                                    "Starting SNI".green().bold(),
                                    match context.server.https_port {
                                        443 => format!("https://{address}"),
                                        port => format!("https://{address}:{port}"),
                                    }
                                    .underline(),
                                )
                                .into_bytes(),
                            );
                            context.user_data.host_addressing.insert(
                                TcpAlias(address.into(), *port as u16),
                                (assigned_host, semaphore),
                            );
                            Ok(true)
                        }
                    }
                }
                Err(error) => {
                    #[cfg(not(coverage_nightly))]
                    tracing::info!(
                        peer = %context.peer, %error, host = %address,
                        "Rejecting SNI proxy.",
                    );
                    let _ = context.tx.send(
                        format!(
                            "{} {} Failed to bind SNI proxy '{}' ({})\r\n",
                            Utc::now().to_rfc3339().dimmed(),
                            " Error ".black().on_red().bold(),
                            address,
                            error,
                        )
                        .into_bytes(),
                    );
                    Ok(false)
                }
            }
        // Reject when HTTP is disabled
        } else if context.server.disable_http {
            let error = eyre!("HTTP is disabled");
            #[cfg(not(coverage_nightly))]
            tracing::info!(
                peer = %context.peer, host = %address, %error,
                "Failed to bind HTTP host.",
            );
            let _ = context.tx.send(
                format!(
                    "{} {} Cannot listen to HTTP host {} ({})\r\n",
                    Utc::now().to_rfc3339().dimmed(),
                    " Error ".black().on_red().bold(),
                    address,
                    error,
                )
                .into_bytes(),
            );
            Ok(false)
        // Handle regular tunneling for HTTP services
        } else {
            // Assign an HTTP address according to server policies
            match context
                .server
                .address_delegator
                .get_http_address(address, context.user, context.key_fingerprint, context.peer)
                .await
            {
                Ok(assigned_host) => {
                    // Add handler to HTTP connection map
                    let semaphore = Arc::new(Semaphore::new(
                        context.user_data.max_pool_size.load(Ordering::Acquire),
                    ));
                    match context.server.http.insert(
                        assigned_host.clone(),
                        *context.peer,
                        context.user_data.quota_key.clone(),
                        Arc::new(SshTunnelHandler {
                            allow_fingerprint: Arc::clone(&context.user_data.allow_fingerprint),
                            http_data: Some(Arc::clone(&context.user_data.http_data)),
                            pool: Arc::clone(&semaphore),
                            pool_timeout: context.server.pool_timeout,
                            ip_connections: Arc::default(),
                            max_connections_per_ip: context.server.max_connections_per_ip,
                            ip_filter: Arc::clone(&context.user_data.ip_filter),
                            handle,
                            tx: context.tx.clone(),
                            peer: *context.peer,
                            address: address.to_string(),
                            port: *port,
                            limiter: context.user_data.limiter.clone(),
                        }),
                    ) {
                        Err(error) => {
                            // Adding to connection map failed.
                            #[cfg(not(coverage_nightly))]
                            tracing::info!(
                                peer = %context.peer, host = %assigned_host, %error,
                                "Rejecting HTTP.",
                            );
                            let _ = context.tx.send(
                                format!(
                                    "{} {} Cannot listen to HTTP on http://{} for {} ({})\r\n",
                                    Utc::now().to_rfc3339().dimmed(),
                                    " Error ".black().on_red().bold(),
                                    match context.server.http_port {
                                        80 => assigned_host.clone(),
                                        port => format!("{assigned_host}:{port}"),
                                    },
                                    address,
                                    error,
                                )
                                .into_bytes(),
                            );
                            Ok(false)
                        }
                        _ => {
                            // Adding to connection map succeeded.
                            #[cfg(not(coverage_nightly))]
                            tracing::info!(peer = %context.peer, host = %assigned_host, "Serving HTTP...");
                            let _ = context.tx.send(
                                format!(
                                    "{} {:>14} on {} for {}\r\n",
                                    Utc::now().to_rfc3339().dimmed(),
                                    "Starting HTTP".green().bold(),
                                    match context.server.http_port {
                                        80 => format!("http://{assigned_host}"),
                                        port => format!("http://{assigned_host}:{port}"),
                                    }
                                    .underline(),
                                    if address.is_empty() {
                                        "unspecified address".into()
                                    } else {
                                        format!("address {address}")
                                    },
                                )
                                .into_bytes(),
                            );
                            if !context.server.disable_https {
                                let _ = context.tx.send(
                                    format!(
                                        "{} {:>14} on {} for {}\r\n",
                                        Utc::now().to_rfc3339().dimmed(),
                                        "Starting HTTPS".green().bold(),
                                        match context.server.https_port {
                                            443 => format!("https://{assigned_host}"),
                                            port => format!("https://{assigned_host}:{port}"),
                                        }
                                        .underline(),
                                        if address.is_empty() {
                                            "unspecified address".into()
                                        } else {
                                            format!("address {address}")
                                        },
                                    )
                                    .into_bytes(),
                                );
                            }
                            context.user_data.host_addressing.insert(
                                TcpAlias(address.to_string(), *port as u16),
                                (assigned_host, semaphore),
                            );
                            Ok(true)
                        }
                    }
                }
                Err(error) => {
                    // Assigning a host failed.
                    #[cfg(not(coverage_nightly))]
                    tracing::info!(
                        peer = %context.peer, %address, %error,
                        "Rejecting HTTP.",
                    );
                    let _ = context.tx.send(
                        format!(
                            "{} {} Cannot listen to HTTP for {} ({})\r\n",
                            Utc::now().to_rfc3339().dimmed(),
                            " Error ".black().on_red().bold(),
                            address,
                            error,
                        )
                        .into_bytes(),
                    );
                    Ok(false)
                }
            }
        }
    }

    async fn cancel_remote_forwarding(
        &mut self,
        context: &mut RemoteForwardingContext<'_>,
        address: &str,
        port: u16,
    ) -> Result<bool, russh::Error> {
        if matches!(
            context.user_data.session_restriction,
            UserSessionRestriction::TcpAliasOnly
        ) {
            // Handle TCP alias-only mode
            if let Some(assigned_alias) = context
                .user_data
                .alias_addressing
                .remove(&BorrowedTcpAlias(address, &80) as &dyn TcpAliasKey)
            {
                let key: &dyn TcpAliasKey = assigned_alias.0.borrow();
                context.server.alias.remove(key, context.peer);
                #[cfg(not(coverage_nightly))]
                tracing::info!(
                    peer = %context.peer, alias = %assigned_alias.0.0, port = %assigned_alias.0.1,
                    "Stopped TCP aliasing.",
                );
                let _ = context.tx.send(
                    format!(
                        "{} {:>14} for HTTP alias {}\r\n",
                        Utc::now().to_rfc3339().dimmed(),
                        "Stopping alias".yellow().bold(),
                        address,
                    )
                    .into_bytes(),
                );
                Ok(true)
            } else {
                Ok(false)
            }
        } else if matches!(
            context.user_data.session_restriction,
            UserSessionRestriction::SniProxyOnly
        ) {
            // Handle SNI proxy-only mode
            if let Some(assigned_alias) = context
                .user_data
                .host_addressing
                .remove(&BorrowedTcpAlias(address, &{ port }) as &dyn TcpAliasKey)
            {
                context.server.sni.remove(&assigned_alias.0, context.peer);
                #[cfg(not(coverage_nightly))]
                tracing::info!(
                    peer = %context.peer, host = %assigned_alias.0,
                    "Stopped SNI proxying.",
                );
                let _ = context.tx.send(
                    format!(
                        "{} {:>14} proxy for {}\r\n",
                        Utc::now().to_rfc3339().dimmed(),
                        "Stopping SNI".yellow().bold(),
                        address,
                    )
                    .into_bytes(),
                );
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            // Handle regular tunneling for HTTP services
            if let Some(assigned_host) = context
                .user_data
                .host_addressing
                .remove(&BorrowedTcpAlias(address, &{ port }) as &dyn TcpAliasKey)
            {
                context.server.http.remove(&assigned_host.0, context.peer);
                #[cfg(not(coverage_nightly))]
                tracing::info!(
                    peer = %context.peer, host = %assigned_host.0,
                    "Stopped HTTP forwarding.",
                );
                let _ = context.tx.send(
                    format!(
                        "{} {:>14} for {}\r\n",
                        Utc::now().to_rfc3339().dimmed(),
                        "Stopping HTTP".yellow().bold(),
                        address,
                    )
                    .into_bytes(),
                );
                if !context.server.disable_https {
                    let _ = context.tx.send(
                        format!(
                            "{} {:>14} for {}\r\n",
                            Utc::now().to_rfc3339().dimmed(),
                            "Stopping HTTPS".yellow().bold(),
                            address,
                        )
                        .into_bytes(),
                    );
                }
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }

    async fn local_forwarding(
        &mut self,
        context: &mut LocalForwardingContext<'_>,
        address: &str,
        _port: u16,
        _originator_address: &str,
        _originator_port: u16,
        channel: Channel<Msg>,
    ) -> Result<bool, russh::Error> {
        let ip = context.peer.ip().to_canonical();
        if let Some(tunnel_handler) = context.server.sni.get(address, ip) {
            let mut stream = channel.into_stream();
            if let Ok(mut channel) = tunnel_handler
                .tunneling_channel(ip, context.peer.port())
                .await
            {
                let gauge = gauge!(TELEMETRY_GAUGE_SNI_CONNECTIONS_CURRENT, TELEMETRY_KEY_HOSTNAME => address.to_string());
                gauge.increment(1);
                counter!(TELEMETRY_COUNTER_SNI_CONNECTIONS, TELEMETRY_KEY_HOSTNAME => address.to_string())
                    .increment(1);
                let tcp_connection_timeout = context.server.tcp_connection_timeout;
                let buffer_size = context.server.buffer_size;
                tokio::spawn(async move {
                    match tcp_connection_timeout {
                        Some(duration) => {
                            let _ = timeout(duration, async {
                                let _ = copy_bidirectional_with_sizes(
                                    &mut stream,
                                    &mut channel,
                                    buffer_size,
                                    buffer_size,
                                )
                                .await;
                            })
                            .await;
                        }
                        None => {
                            let _ = copy_bidirectional_with_sizes(
                                &mut stream,
                                &mut channel,
                                buffer_size,
                                buffer_size,
                            )
                            .await;
                        }
                    }
                    gauge.decrement(1);
                });
                return Ok(true);
            };
        } else if let Some(handler) = context
            .server
            .aliasing_proxy_data
            .conn_manager()
            .get_by_http_host(address, ip)
            && handler.can_alias(ip, context.peer.port(), context.key_fingerprint.as_ref())
        {
            let peer = *context.peer;
            let fingerprint = *context.key_fingerprint;
            let proxy_data = Arc::clone(&context.server.aliasing_proxy_data);
            let address = address.to_string();
            let service = service_fn(move |mut req: Request<Incoming>| {
                // Set HTTP host via header
                req.headers_mut()
                    .insert("host", address.clone().try_into().expect("valid address"));
                proxy_handler(req, peer, fingerprint, Arc::clone(&proxy_data))
            });
            let io = TokioIo::new(channel.into_stream());
            let tcp_connection_timeout = context.server.tcp_connection_timeout;
            match context.auth_data {
                // Serve HTTP for unauthed user, then add disconnection timeout if this is the last proxy connection
                AuthenticatedData::None { proxy_data } => {
                    let guard = proxy_data.clone();
                    tokio::spawn(async move {
                        let server = auto::Builder::new(TokioExecutor::new());
                        let conn = server.serve_connection_with_upgrades(io, service);
                        match tcp_connection_timeout {
                            Some(duration) => {
                                let _ = timeout(duration, conn).await;
                            }
                            None => {
                                let _ = conn.await;
                            }
                        }
                        drop(guard);
                    });
                }
                // Serve HTTP normally for authed user
                _ => {
                    tokio::spawn(async move {
                        let server = auto::Builder::new(TokioExecutor::new());
                        let conn = server.serve_connection_with_upgrades(io, service);
                        match tcp_connection_timeout {
                            Some(duration) => {
                                let _ = timeout(duration, conn).await;
                            }
                            None => {
                                let _ = conn.await;
                            }
                        }
                    });
                }
            }

            return Ok(true);
        }
        let _ = context.tx.send(
            format!(
                "{} {} Unknown HTTP alias '{}'\r\n",
                Utc::now().to_rfc3339().dimmed(),
                " Error ".black().on_red().bold(),
                address,
            )
            .into_bytes(),
        );
        Ok(false)
    }
}

impl ForwardingHandlerStrategy for AliasForwardingHandler {
    async fn remote_forwarding(
        &mut self,
        context: &mut RemoteForwardingContext<'_>,
        address: &str,
        port: &mut u32,
        handle: Handle,
    ) -> Result<bool, russh::Error> {
        if context.server.disable_aliasing {
            let _ = context.tx.send(
                format!(
                    "{} {} Aliasing is disabled\r\n",
                    Utc::now().to_rfc3339().dimmed(),
                    " Error ".black().on_red().bold(),
                )
                .into_bytes(),
            );
            return Ok(false);
        }
        // If alias, the user must provide the port number themselves
        let assigned_port = if *port == 0 {
            let error = eyre!("cannot assign random port to alias");
            #[cfg(not(coverage_nightly))]
            tracing::debug!(
                peer = %context.peer, alias = %address, %error,
                "Failed to bind port for alias.",
            );
            let _ = context.tx.send(
                format!(
                    "{} {} Cannot listen to random port for alias {} ({})\r\n{}\r\n",
                    Utc::now().to_rfc3339().dimmed(),
                    " Error ".black().on_red().bold(),
                    address,
                    error,
                    "  = hint: specify the desired port instead of 0".dimmed(),
                )
                .into_bytes(),
            );
            return Ok(false);
        } else if *port == ADMIN_ALIAS_PORT as u32 {
            // Port 10 is reserved for admin aliases
            let error = eyre!("port {ADMIN_ALIAS_PORT} is reserved by Sandhole");
            #[cfg(not(coverage_nightly))]
            tracing::debug!(
                peer = %context.peer, alias = %address, %error,
                "Failed to bind port for alias.",
            );
            let _ = context.tx.send(
                format!(
                    "{} {} Cannot listen on port {} for alias {} ({})\r\n{}\r\n",
                    Utc::now().to_rfc3339().dimmed(),
                    " Error ".black().on_red().bold(),
                    port,
                    address,
                    error,
                    "  = hint: specify a different port".dimmed(),
                )
                .into_bytes(),
            );
            return Ok(false);
        } else {
            // Allow user-requested port
            *port as u16
        };
        // Add handler to alias connection map
        let semaphore = Arc::new(Semaphore::new(
            context.user_data.max_pool_size.load(Ordering::Acquire),
        ));
        match context.server.alias.insert(
            TcpAlias(address.to_string(), assigned_port),
            *context.peer,
            context.user_data.quota_key.clone(),
            Arc::new(SshTunnelHandler {
                allow_fingerprint: Arc::clone(&context.user_data.allow_fingerprint),
                http_data: None,
                pool: Arc::clone(&semaphore),
                pool_timeout: context.server.pool_timeout,
                ip_connections: Arc::default(),
                max_connections_per_ip: context.server.max_connections_per_ip,
                ip_filter: Arc::clone(&context.user_data.ip_filter),
                handle,
                tx: context.tx.clone(),
                peer: *context.peer,
                address: address.to_string(),
                port: *port,
                limiter: context.user_data.limiter.clone(),
            }),
        ) {
            Err(error) => {
                // Adding to connection map failed.
                #[cfg(not(coverage_nightly))]
                tracing::info!(
                    peer = %context.peer, alias = %address, port = %assigned_port, %error,
                    "Rejecting port for alias.",
                );
                let _ = context.tx.send(
                    format!(
                        "{} {} Cannot listen on port {} for alias {} ({})\r\n",
                        Utc::now().to_rfc3339().dimmed(),
                        " Error ".black().on_red().bold(),
                        &assigned_port,
                        address,
                        error,
                    )
                    .into_bytes(),
                );
                Ok(false)
            }
            _ => {
                // Adding to connection map succeeded.
                context.user_data.alias_addressing.insert(
                    TcpAlias(address.to_string(), *port as u16),
                    (TcpAlias(address.to_string(), assigned_port), semaphore),
                );
                #[cfg(not(coverage_nightly))]
                tracing::info!(
                    peer = %context.peer, alias = %address, port = %assigned_port,
                    "Tunneling port for alias...",
                );
                let _ = context.tx.send(
                    format!(
                        "{} {:>14} tunneling for {}:{}\r\n",
                        Utc::now().to_rfc3339().dimmed(),
                        "Starting alias".green().bold(),
                        address,
                        &assigned_port,
                    )
                    .into_bytes(),
                );
                Ok(true)
            }
        }
    }

    async fn cancel_remote_forwarding(
        &mut self,
        context: &mut RemoteForwardingContext<'_>,
        address: &str,
        port: u16,
    ) -> Result<bool, russh::Error> {
        if let Some(assigned_alias) =
            context
                .user_data
                .alias_addressing
                .remove(&BorrowedTcpAlias(address, &{ port }) as &dyn TcpAliasKey)
        {
            let key: &dyn TcpAliasKey = assigned_alias.0.borrow();
            context.server.alias.remove(key, context.peer);
            #[cfg(not(coverage_nightly))]
            tracing::info!(
                peer = %context.peer, alias = %assigned_alias.0.0, port = %assigned_alias.0.1,
                "Stopped TCP aliasing.",
            );
            let _ = context.tx.send(
                format!(
                    "{} {:>14} for {}:{}\r\n",
                    Utc::now().to_rfc3339().dimmed(),
                    "Stopping alias".yellow().bold(),
                    address,
                    port,
                )
                .into_bytes(),
            );
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn local_forwarding(
        &mut self,
        context: &mut LocalForwardingContext<'_>,
        address: &str,
        port: u16,
        originator_address: &str,
        originator_port: u16,
        channel: Channel<Msg>,
    ) -> Result<bool, russh::Error> {
        let ip = context.peer.ip().to_canonical();
        if let Some(handler) = context
            .server
            .admin_alias
            .get(&BorrowedTcpAlias(address, &port) as &dyn TcpAliasKey, ip)
        {
            if let AuthenticatedData::Admin { .. } = context.auth_data {
                if let Ok(mut io) = handler
                    .aliasing_channel(ip, context.peer.port(), context.key_fingerprint.as_ref())
                    .await
                {
                    let alias = TcpAlias(address.into(), port);
                    let gauge = gauge!(TELEMETRY_GAUGE_ADMIN_ALIAS_CONNECTIONS_CURRENT, TELEMETRY_KEY_ALIAS => alias.to_string());
                    gauge.increment(1);
                    counter!(TELEMETRY_COUNTER_ADMIN_ALIAS_CONNECTIONS, TELEMETRY_KEY_ALIAS => alias.to_string())
                    .increment(1);
                    let tcp_connection_timeout = context.server.tcp_connection_timeout;
                    let buffer_size = context.server.buffer_size;
                    tokio::spawn(async move {
                        let mut stream = channel.into_stream();
                        match tcp_connection_timeout {
                            Some(duration) => {
                                let _ = timeout(duration, async {
                                    copy_bidirectional_with_sizes(
                                        &mut stream,
                                        &mut io,
                                        buffer_size,
                                        buffer_size,
                                    )
                                    .await
                                })
                                .await;
                            }
                            None => {
                                let _ = copy_bidirectional_with_sizes(
                                    &mut stream,
                                    &mut io,
                                    buffer_size,
                                    buffer_size,
                                )
                                .await;
                            }
                        }
                        gauge.decrement(1);
                    });
                    #[cfg(not(coverage_nightly))]
                    tracing::debug!(
                        peer = %context.peer, alias = %address, port = %port,
                        "Accepted admin alias connection.",
                    );
                    return Ok(true);
                }
            } else {
                #[cfg(not(coverage_nightly))]
                tracing::debug!(
                    peer = %context.peer, fingerprint = ?context.key_fingerprint, alias = %address, port = %port,
                    "Non-admin user attempt to local forward admin alias",
                )
            }
        } else if let Some(handler) = context
            .server
            .alias
            .get(&BorrowedTcpAlias(address, &port) as &dyn TcpAliasKey, ip)
            && let Ok(mut io) = handler
                .aliasing_channel(ip, context.peer.port(), context.key_fingerprint.as_ref())
                .await
        {
            let alias = TcpAlias(address.into(), port);
            let gauge = gauge!(TELEMETRY_GAUGE_ALIAS_CONNECTIONS_CURRENT, TELEMETRY_KEY_ALIAS => alias.to_string());
            gauge.increment(1);
            counter!(TELEMETRY_COUNTER_ALIAS_CONNECTIONS, TELEMETRY_KEY_ALIAS => alias.to_string())
                .increment(1);
            let _ = handler.log_channel().send(
                format!(
                    "{} {:>14} - {}:{} => {}:{}\r\n",
                    Utc::now().to_rfc3339().dimmed(),
                    "Proxying alias".blue().bold(),
                    originator_address,
                    originator_port,
                    address,
                    port,
                )
                .into_bytes(),
            );
            match context.auth_data {
                // Serve TCP for unauthed user, then add disconnection timeout if this is the last proxy connection
                AuthenticatedData::None { proxy_data } => {
                    let guard = proxy_data.clone();
                    let tcp_connection_timeout = context.server.tcp_connection_timeout;
                    let buffer_size = context.server.buffer_size;
                    tokio::spawn(async move {
                        let mut stream = channel.into_stream();
                        match tcp_connection_timeout {
                            Some(duration) => {
                                let _ = timeout(duration, async {
                                    copy_bidirectional_with_sizes(
                                        &mut stream,
                                        &mut io,
                                        buffer_size,
                                        buffer_size,
                                    )
                                    .await
                                })
                                .await;
                            }
                            None => {
                                let _ = copy_bidirectional_with_sizes(
                                    &mut stream,
                                    &mut io,
                                    buffer_size,
                                    buffer_size,
                                )
                                .await;
                            }
                        }
                        drop(guard);
                        gauge.decrement(1);
                    });
                }
                // Serve alias normally for authed user
                _ => {
                    let tcp_connection_timeout = context.server.tcp_connection_timeout;
                    let buffer_size = context.server.buffer_size;
                    tokio::spawn(async move {
                        let mut stream = channel.into_stream();
                        match tcp_connection_timeout {
                            Some(duration) => {
                                let _ = timeout(duration, async {
                                    copy_bidirectional_with_sizes(
                                        &mut stream,
                                        &mut io,
                                        buffer_size,
                                        buffer_size,
                                    )
                                    .await
                                })
                                .await;
                            }
                            None => {
                                let _ = copy_bidirectional_with_sizes(
                                    &mut stream,
                                    &mut io,
                                    buffer_size,
                                    buffer_size,
                                )
                                .await;
                            }
                        }
                        gauge.decrement(1);
                    });
                }
            }
            #[cfg(not(coverage_nightly))]
            tracing::debug!(
                peer = %context.peer, remote = %handler.peer, alias = %address, port = %port,
                "Accepted alias connection.",
            );
            return Ok(true);
        }
        let _ = context.tx.send(
            format!(
                "{} {} Unknown alias '{}:{}'\r\n",
                Utc::now().to_rfc3339().dimmed(),
                " Error ".black().on_red().bold(),
                address,
                port,
            )
            .into_bytes(),
        );
        Ok(false)
    }
}

impl ForwardingHandlerStrategy for TcpForwardingHandler {
    async fn remote_forwarding(
        &mut self,
        context: &mut RemoteForwardingContext<'_>,
        address: &str,
        port: &mut u32,
        handle: Handle,
    ) -> Result<bool, russh::Error> {
        // Forbid binding TCP if disabled
        if context.server.disable_tcp {
            let error = eyre!("TCP is disabled");
            #[cfg(not(coverage_nightly))]
            tracing::info!(
                peer = %context.peer, %port, %error,
                "Failed to bind TCP port.",
            );
            let _ = context.tx.send(
                format!(
                    "{} {} Cannot listen to TCP on port {}:{} ({})\r\n",
                    Utc::now().to_rfc3339().dimmed(),
                    " Error ".black().on_red().bold(),
                    context
                        .server
                        .domain
                        .as_deref()
                        .unwrap_or("<Sandhole's IP>"),
                    port,
                    error,
                )
                .into_bytes(),
            );
            Ok(false)
        // Forbid binding TCP on alias-only mode
        } else if matches!(
            context.user_data.session_restriction,
            UserSessionRestriction::TcpAliasOnly
        ) {
            let error = eyre!("session is in alias-only mode");
            #[cfg(not(coverage_nightly))]
            tracing::info!(
                peer = %context.peer, %port, %error,
                "Failed to bind TCP port.",
            );
            let _ = context.tx.send(
                format!(
                    "{} {} Cannot listen to TCP on port {}:{} ({})\r\n",
                    Utc::now().to_rfc3339().dimmed(),
                    " Error ".black().on_red().bold(),
                    context
                        .server
                        .domain
                        .as_deref()
                        .unwrap_or("<Sandhole's IP>"),
                    port,
                    error,
                )
                .into_bytes(),
            );
            Ok(false)
        // Forbid binding low TCP ports
        } else if (1..1024).contains(port) {
            let error = eyre!("port too low");
            #[cfg(not(coverage_nightly))]
            tracing::info!(
                peer = %context.peer, %port, %error,
                "Failed to bind TCP port.",
            );
            let _ = context.tx.send(
                format!(
                    "{} {} Cannot listen to TCP on port {}:{} ({})\r\n",
                    Utc::now().to_rfc3339().dimmed(),
                    " Error ".black().on_red().bold(),
                    context
                        .server
                        .domain
                        .as_deref()
                        .unwrap_or("<Sandhole's IP>"),
                    port,
                    error,
                )
                .into_bytes(),
            );
            Ok(false)
        } else {
            // When port is 0, assign a random one
            let assigned_port = if *port == 0 {
                let assigned_port = match context.server.tcp_handler.get_free_port().await {
                    Ok(port) => port,
                    Err(error) => {
                        #[cfg(not(coverage_nightly))]
                        tracing::info!(
                            peer = %context.peer, alias = %address, %error,
                            "Failed to bind random TCP port for alias.",
                        );
                        let _ = context.tx.send(
                            format!(
                                "{} {} Cannot listen to TCP on random port of {} ({})\r\n",
                                Utc::now().to_rfc3339().dimmed(),
                                " Error ".black().on_red().bold(),
                                address,
                                error,
                            )
                            .into_bytes(),
                        );
                        return Ok(false);
                    }
                };
                // Set port to communicate it back to the client
                *port = assigned_port.into();
                assigned_port
            // Ignore user-requested port, assign any free one
            } else if context.server.force_random_ports {
                match context.server.tcp_handler.get_free_port().await {
                    Ok(port) => port,
                    Err(error) => {
                        #[cfg(not(coverage_nightly))]
                        tracing::info!(
                            peer = %context.peer, alias = %address, %error,
                            "Failed to bind random TCP port for alias.",
                        );
                        let _ = context.tx.send(
                            format!(
                                "{} {} Cannot listen to TCP on random port of {} ({})\r\n",
                                Utc::now().to_rfc3339().dimmed(),
                                " Error ".black().on_red().bold(),
                                port,
                                error,
                            )
                            .into_bytes(),
                        );
                        return Ok(false);
                    }
                }
            // Allow user-requested port when server allows binding on any port
            } else {
                match context
                    .server
                    .tcp_handler
                    .create_port_listener(*port as u16)
                    .await
                {
                    Ok(_) => (),
                    Err(error) => {
                        // Creating port listener failed.
                        #[cfg(not(coverage_nightly))]
                        tracing::info!(
                            peer = %context.peer, %port, %error,
                            "Rejecting TCP.",
                        );
                        let _ = context.tx.send(
                            format!(
                                "{} {} Cannot listen to TCP on {}:{} ({})\r\n",
                                Utc::now().to_rfc3339().dimmed(),
                                " Error ".black().on_red().bold(),
                                context
                                    .server
                                    .domain
                                    .as_deref()
                                    .unwrap_or("<Sandhole's IP>"),
                                &port,
                                error,
                            )
                            .into_bytes(),
                        );
                        return Ok(false);
                    }
                }
                *port as u16
            };
            // Add handler to TCP connection map
            let semaphore = Arc::new(Semaphore::new(
                context.user_data.max_pool_size.load(Ordering::Acquire),
            ));
            match context.server.tcp.insert(
                assigned_port,
                *context.peer,
                context.user_data.quota_key.clone(),
                Arc::new(SshTunnelHandler {
                    allow_fingerprint: Arc::clone(&context.user_data.allow_fingerprint),
                    http_data: None,
                    pool: Arc::clone(&semaphore),
                    pool_timeout: context.server.pool_timeout,
                    ip_connections: Arc::default(),
                    max_connections_per_ip: context.server.max_connections_per_ip,
                    ip_filter: Arc::clone(&context.user_data.ip_filter),
                    handle,
                    tx: context.tx.clone(),
                    peer: *context.peer,
                    address: address.to_string(),
                    port: *port,
                    limiter: context.user_data.limiter.clone(),
                }),
            ) {
                Err(error) => {
                    // Adding to connection map failed.
                    #[cfg(not(coverage_nightly))]
                    tracing::info!(
                        peer = %context.peer, port = %assigned_port, %error,
                        "Rejecting TCP.",
                    );
                    let _ = context.tx.send(
                        format!(
                            "{} {} Cannot listen to TCP on {}:{} ({})\r\n",
                            Utc::now().to_rfc3339().dimmed(),
                            " Error ".black().on_red().bold(),
                            context
                                .server
                                .domain
                                .as_deref()
                                .unwrap_or("<Sandhole's IP>"),
                            &assigned_port,
                            error,
                        )
                        .into_bytes(),
                    );
                    Ok(false)
                }
                _ => {
                    // Adding to connection map succeeded.
                    context.user_data.port_addressing.insert(
                        TcpAlias(address.to_string(), *port as u16),
                        (assigned_port, semaphore),
                    );
                    #[cfg(not(coverage_nightly))]
                    tracing::info!(
                        peer = %context.peer, port = %assigned_port,
                        "Serving TCP...",
                    );
                    let _ = context.tx.send(
                        format!(
                            "{} {:>14} port on {}:{}\r\n",
                            Utc::now().to_rfc3339().dimmed(),
                            "Starting TCP".green().bold(),
                            context
                                .server
                                .domain
                                .as_deref()
                                .unwrap_or("<Sandhole's IP>"),
                            &assigned_port,
                        )
                        .into_bytes(),
                    );
                    Ok(true)
                }
            }
        }
    }

    async fn cancel_remote_forwarding(
        &mut self,
        context: &mut RemoteForwardingContext<'_>,
        address: &str,
        port: u16,
    ) -> Result<bool, russh::Error> {
        if let Some(assigned_port) =
            context
                .user_data
                .port_addressing
                .remove(&BorrowedTcpAlias(address, &{ port }) as &dyn TcpAliasKey)
        {
            context.server.tcp.remove(&assigned_port.0, context.peer);
            #[cfg(not(coverage_nightly))]
            tracing::info!(
                peer = %context.peer, port = %port,
                "Stopped TCP forwarding.",
            );
            let _ = context.tx.send(
                format!(
                    "{} {:>14} port on {}:{}\r\n",
                    Utc::now().to_rfc3339().dimmed(),
                    "Stopping TCP".yellow().bold(),
                    context
                        .server
                        .domain
                        .as_deref()
                        .unwrap_or("<Sandhole's IP>"),
                    &assigned_port.0,
                )
                .into_bytes(),
            );
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn local_forwarding(
        &mut self,
        context: &mut LocalForwardingContext<'_>,
        address: &str,
        port: u16,
        originator_address: &str,
        originator_port: u16,
        channel: Channel<Msg>,
    ) -> Result<bool, russh::Error> {
        let ip = context.peer.ip().to_canonical();
        if let Some(handler) = context.server.tcp.get(&port, ip)
            && let Ok(mut io) = handler
                .aliasing_channel(ip, context.peer.port(), context.key_fingerprint.as_ref())
                .await
        {
            let gauge = gauge!(TELEMETRY_GAUGE_TCP_CONNECTIONS_CURRENT, TELEMETRY_KEY_PORT => port.to_string());
            gauge.increment(1);
            counter!(TELEMETRY_COUNTER_TCP_CONNECTIONS, TELEMETRY_KEY_PORT => port.to_string())
                .increment(1);
            let _ = handler.log_channel().send(
                format!(
                    "{} {:>14} - {}:{} => {}:{}\r\n",
                    Utc::now().to_rfc3339().dimmed(),
                    "Proxying TCP".blue().bold(),
                    originator_address,
                    originator_port,
                    address,
                    port,
                )
                .into_bytes(),
            );
            match context.auth_data {
                // Serve TCP for unauthed user, then add disconnection timeout if this is the last proxy connection
                AuthenticatedData::None { proxy_data } => {
                    let guard = proxy_data.clone();
                    let tcp_connection_timeout = context.server.tcp_connection_timeout;
                    let buffer_size = context.server.buffer_size;
                    tokio::spawn(async move {
                        let mut stream = channel.into_stream();
                        match tcp_connection_timeout {
                            Some(duration) => {
                                let _ = timeout(duration, async {
                                    copy_bidirectional_with_sizes(
                                        &mut stream,
                                        &mut io,
                                        buffer_size,
                                        buffer_size,
                                    )
                                    .await
                                })
                                .await;
                            }
                            None => {
                                let _ = copy_bidirectional_with_sizes(
                                    &mut stream,
                                    &mut io,
                                    buffer_size,
                                    buffer_size,
                                )
                                .await;
                            }
                        }
                        drop(guard);
                        gauge.decrement(1);
                    });
                }
                // Serve TCP normally for authed user
                _ => {
                    let tcp_connection_timeout = context.server.tcp_connection_timeout;
                    let buffer_size = context.server.buffer_size;
                    tokio::spawn(async move {
                        let mut stream = channel.into_stream();
                        match tcp_connection_timeout {
                            Some(duration) => {
                                let _ = timeout(duration, async {
                                    copy_bidirectional_with_sizes(
                                        &mut stream,
                                        &mut io,
                                        buffer_size,
                                        buffer_size,
                                    )
                                    .await
                                })
                                .await;
                            }
                            None => {
                                let _ = copy_bidirectional_with_sizes(
                                    &mut stream,
                                    &mut io,
                                    buffer_size,
                                    buffer_size,
                                )
                                .await;
                            }
                        }
                        gauge.decrement(1);
                    });
                }
            }
            #[cfg(not(coverage_nightly))]
            tracing::debug!(
                peer = %context.peer, remote = %handler.peer, port = %port,
                "Accepted TCP connection.",
            );
            return Ok(true);
        }
        let _ = context.tx.send(
            format!(
                "{} {} Unknown TCP port '{}'\r\n",
                Utc::now().to_rfc3339().dimmed(),
                " Error ".black().on_red().bold(),
                port
            )
            .into_bytes(),
        );
        Ok(false)
    }
}
