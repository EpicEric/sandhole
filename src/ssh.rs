use std::{
    borrow::Borrow,
    collections::{HashMap, HashSet},
    fmt::Display,
    net::SocketAddr,
    ops::Deref,
    sync::Arc,
};

use crate::{
    admin::AdminInterface,
    error::ServerError,
    fingerprints::AuthenticationType,
    handler::ConnectionHandler,
    tcp::PortHandler,
    tcp_alias::{BorrowedTcpAlias, TcpAlias, TcpAliasKey},
    SandholeServer,
};

use async_trait::async_trait;
use log::{debug, info, warn};
use russh::{
    server::{Auth, Handler, Msg, Session},
    Channel, ChannelId, ChannelStream, Disconnect, MethodSet,
};
use russh_keys::key::PublicKey;
use tokio::{
    io::{copy_bidirectional, AsyncWriteExt},
    sync::{mpsc, oneshot, Mutex, RwLock},
    time::{sleep, timeout},
};

#[derive(Clone)]
pub(crate) struct SshTunnelHandler {
    allow_fingerprint: Arc<RwLock<Box<dyn Fn(Option<String>) -> bool + Send + Sync>>>,
    handle: russh::server::Handle,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    peer: SocketAddr,
    address: String,
    port: u32,
}

impl SshTunnelHandler {
    pub(crate) fn new(
        allow_fingerprint: Arc<RwLock<Box<dyn Fn(Option<String>) -> bool + Send + Sync>>>,
        handle: russh::server::Handle,
        tx: mpsc::UnboundedSender<Vec<u8>>,
        peer: SocketAddr,
        address: String,
        port: u32,
    ) -> Self {
        SshTunnelHandler {
            allow_fingerprint,
            handle,
            address,
            peer,
            port,
            tx,
        }
    }
}

#[async_trait]
impl ConnectionHandler<ChannelStream<Msg>> for SshTunnelHandler {
    fn log_channel(&self) -> mpsc::UnboundedSender<Vec<u8>> {
        self.tx.clone()
    }
    async fn tunneling_channel(
        &self,
        ip: &str,
        port: u16,
        fingerprint: Option<String>,
    ) -> anyhow::Result<ChannelStream<Msg>> {
        // TO-DO: Check reference for allowed fingerprints (maybe with a closure)
        if !(self.allow_fingerprint.read().await)(fingerprint.clone()) {
            Err(ServerError::FingerprintDenied)?
        }
        let channel = self
            .handle
            .channel_open_forwarded_tcpip(self.address.clone(), self.port, ip, port.into())
            .await?
            .into_stream();
        Ok(channel)
    }
}

struct UserData {
    allow_fingerprint: Arc<RwLock<Box<dyn Fn(Option<String>) -> bool + Send + Sync>>>,
    col_width: Option<u32>,
    row_height: Option<u32>,
    ssh_hosts: HashSet<String>,
    http_hosts: HashSet<String>,
    tcp_aliases: HashSet<TcpAlias>,
    host_addressing: HashMap<(String, u32), String>,
    port_addressing: HashMap<(String, u32), TcpAlias>,
}

impl Default for UserData {
    fn default() -> Self {
        Self {
            allow_fingerprint: Arc::new(RwLock::new(Box::new(|_| true))),
            col_width: Default::default(),
            row_height: Default::default(),
            ssh_hosts: Default::default(),
            http_hosts: Default::default(),
            tcp_aliases: Default::default(),
            host_addressing: Default::default(),
            port_addressing: Default::default(),
        }
    }
}

#[derive(Default)]
struct AdminData {
    admin_interface: Option<AdminInterface>,
}

enum AuthenticatedData {
    None,
    Proxy,
    User {
        user_data: Box<UserData>,
    },
    Admin {
        user_data: Box<UserData>,
        admin_data: Box<AdminData>,
    },
}

impl From<AuthenticationType> for AuthenticatedData {
    fn from(value: AuthenticationType) -> Self {
        match value {
            AuthenticationType::None => AuthenticatedData::None,
            AuthenticationType::User => AuthenticatedData::User {
                user_data: Box::default(),
            },
            AuthenticationType::Admin => AuthenticatedData::Admin {
                user_data: Box::default(),
                admin_data: Box::default(),
            },
        }
    }
}

impl Display for AuthenticatedData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthenticatedData::None => f.write_str("no authentication"),
            AuthenticatedData::Proxy => f.write_str("no authentication (proxy)"),
            AuthenticatedData::User { .. } => f.write_str("user authentication"),
            AuthenticatedData::Admin { .. } => f.write_str("admin authentication"),
        }
    }
}

pub(crate) struct ServerHandler {
    cancelation_tx: Option<oneshot::Sender<()>>,
    peer: SocketAddr,
    user: Option<String>,
    key_fingerprint: Option<String>,
    is_proxied: Arc<Mutex<bool>>,
    auth_data: AuthenticatedData,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: Option<mpsc::UnboundedReceiver<Vec<u8>>>,
    server: Arc<SandholeServer>,
}

pub(crate) trait Server {
    fn new_client(
        &mut self,
        peer_address: Option<SocketAddr>,
        cancelation_tx: oneshot::Sender<()>,
    ) -> ServerHandler;
}

impl Server for Arc<SandholeServer> {
    fn new_client(
        &mut self,
        peer_address: Option<SocketAddr>,
        cancelation_tx: oneshot::Sender<()>,
    ) -> ServerHandler {
        let (tx, rx) = mpsc::unbounded_channel();
        let peer_address = peer_address.unwrap();
        ServerHandler {
            cancelation_tx: Some(cancelation_tx),
            peer: peer_address,
            user: None,
            key_fingerprint: None,
            is_proxied: Arc::new(Mutex::new(false)),
            auth_data: AuthenticatedData::None,
            tx,
            rx: Some(rx),
            server: Arc::clone(self),
        }
    }
}

#[async_trait]
impl Handler for ServerHandler {
    type Error = russh::Error;

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let Some(mut rx) = self.rx.take() else {
            return Ok(false);
        };
        if let AuthenticatedData::None = self.auth_data {
            return Err(russh::Error::Disconnect);
        }
        let mut stream = channel.into_stream();
        tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                if stream.write_all(&message).await.is_err() {
                    break;
                }
            }
        });
        Ok(true)
    }

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::PUBLICKEY),
        })
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if let Some(api_login) = self.server.api_login.deref() {
            if let Ok(is_authenticated) =
                timeout(self.server.authentication_request_timeout, async {
                    api_login.authenticate(user, password).await
                })
                .await
            {
                if is_authenticated {
                    self.auth_data = AuthenticatedData::from(AuthenticationType::User);
                    info!("{} connected with {} (password)", self.peer, self.auth_data);
                    return Ok(Auth::Accept);
                }
            } else {
                warn!("Authentication request timed out");
            }
        }
        Ok(Auth::Reject {
            proceed_with_methods: None,
        })
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        let fingerprint = public_key.fingerprint();
        self.user = Some(user.to_string());
        self.key_fingerprint = Some(fingerprint);
        let authentication = self
            .server
            .fingerprints_validator
            .authenticate_fingerprint(self.key_fingerprint.as_ref().unwrap());
        self.auth_data = AuthenticatedData::from(authentication);
        info!(
            "{} connected with {} (public key)",
            self.peer, self.auth_data
        );
        match authentication {
            AuthenticationType::None => {
                // Start timer for user to do local port forwarding.
                // Otherwise, the connection will be canceled upon expiration
                let authenticated = Arc::clone(&self.is_proxied);
                let Some(cancelation_tx) = self.cancelation_tx.take() else {
                    return Err(russh::Error::Disconnect);
                };
                let timeout = self.server.idle_connection_timeout;
                tokio::spawn(async move {
                    sleep(timeout).await;
                    if !*authenticated.lock().await {
                        let _ = cancelation_tx.send(());
                    }
                });
                Ok(Auth::Accept)
            }
            AuthenticationType::User | AuthenticationType::Admin => Ok(Auth::Accept),
        }
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Sending Ctrl+C ends the session and disconnects the client
        if data == [3] {
            // self.tx.send(b"\x1b[?25h".to_vec()).unwrap();
            session.disconnect(Disconnect::ByApplication, "", "English");
            return Ok(());
        }
        debug!("received data {:?}", data);
        match &mut self.auth_data {
            AuthenticatedData::None => return Err(russh::Error::Disconnect),
            AuthenticatedData::Proxy | AuthenticatedData::User { .. } => (),
            AuthenticatedData::Admin { admin_data, .. } => {
                if let Some(admin_interface) = admin_data.admin_interface.as_mut() {
                    match data {
                        // Tab
                        b"\t" => admin_interface.advance_tab(),
                        // Up
                        b"\x1b[A" => admin_interface.move_up(),
                        // Down
                        b"\x1b[B" => admin_interface.move_down(),
                        _ => (),
                    }
                }
            }
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!("exec_request data {:?}", data);
        let cmd = String::from_utf8_lossy(data);
        match (cmd.split_whitespace().next(), &mut self.auth_data) {
            (
                Some("admin"),
                AuthenticatedData::Admin {
                    user_data,
                    admin_data,
                },
            ) => {
                let mut admin_interface =
                    AdminInterface::new(self.tx.clone(), Arc::clone(&self.server));
                if let (Some(col_width), Some(row_height)) =
                    (user_data.col_width, user_data.row_height)
                {
                    let _ = admin_interface.resize(col_width as u16, row_height as u16);
                }
                admin_data.admin_interface = Some(admin_interface);
            }
            (
                Some(cmd),
                AuthenticatedData::User { user_data } | AuthenticatedData::Admin { user_data, .. },
            ) if cmd.starts_with("allowed-fingerprints=") => {
                let set: HashSet<String> = cmd
                    .trim_start_matches("allowed-fingerprints=")
                    .split(',')
                    .filter_map(|key| key.split(':').last().map(|k| k.to_string()))
                    .collect();
                *user_data.allow_fingerprint.write().await =
                    Box::new(move |fingerprint| fingerprint.is_some_and(|fp| set.contains(&fp)))
            }
            (Some(command), _) => {
                debug!(
                    "Invalid command {} received for {} ({})",
                    command, self.auth_data, self.peer
                );
                let _ = self
                    .tx
                    .send(format!("Ignoring unknown command {}...", command).into_bytes());
            }
            (None, _) => (),
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!("pty_request");
        match &mut self.auth_data {
            AuthenticatedData::User { user_data } | AuthenticatedData::Admin { user_data, .. } => {
                user_data.col_width = Some(col_width);
                user_data.row_height = Some(row_height);
            }
            AuthenticatedData::None | AuthenticatedData::Proxy => (),
        }
        session.channel_success(channel);
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        _channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let AuthenticatedData::Admin {
            ref mut admin_data, ..
        } = self.auth_data
        {
            if let Some(ref mut admin_interface) = admin_data.admin_interface {
                if admin_interface
                    .resize(col_width as u16, row_height as u16)
                    .is_err()
                {
                    warn!("Failed to resize terminal");
                }
            }
        }

        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // Only allow remote forwarding for authorized keys
        let user_data = match &mut self.auth_data {
            AuthenticatedData::User { user_data } | AuthenticatedData::Admin { user_data, .. } => {
                user_data
            }
            AuthenticatedData::None | AuthenticatedData::Proxy => {
                return Err(russh::Error::Disconnect)
            }
        };
        let handle = session.handle();
        match *port {
            22 => {
                // Assign SSH host through config
                let assigned_host = self
                    .server
                    .address_delegator
                    .get_address(address, &self.user, &self.key_fingerprint, &self.peer)
                    .await;
                if !is_alias(&assigned_host) {
                    info!(
                        "Failed to bind SSH for {}: must be alias, not localhost",
                        self.peer
                    );
                    let _ = self.tx.send(
                        "Error: Alias is required for SSH host"
                            .to_string()
                            .into_bytes(),
                    );
                    return Ok(false);
                }
                if self
                    .server
                    .ssh
                    .insert(
                        assigned_host.clone(),
                        self.peer,
                        Arc::new(SshTunnelHandler::new(
                            Arc::clone(&user_data.allow_fingerprint),
                            handle,
                            self.tx.clone(),
                            self.peer,
                            address.to_string(),
                            *port,
                        )),
                    )
                    .is_ok()
                {
                    user_data.ssh_hosts.insert(assigned_host.clone());
                    user_data
                        .host_addressing
                        .insert((address.to_string(), *port), assigned_host.clone());
                    info!("Serving SSH for {} ({})", &assigned_host, self.peer);
                    let _ = self.tx.send(
                        format!(
                            "Serving SSH on {}:{}\r\n\
                                \x1b[2mhint: connect with ssh -J {}{} {}{}\x1b[0m\r\n",
                            &assigned_host,
                            self.server.ssh_port,
                            self.server.domain,
                            if self.server.ssh_port == 22 {
                                "".into()
                            } else {
                                format!(":{}", self.server.ssh_port)
                            },
                            &assigned_host,
                            if self.server.ssh_port == 22 {
                                "".into()
                            } else {
                                format!(" -p {}", self.server.ssh_port)
                            },
                        )
                        .into_bytes(),
                    );
                    Ok(true)
                } else {
                    info!("Rejecting SSH for {} ({})", &assigned_host, self.peer);
                    let _ = self.tx.send(
                        format!(
                            "Cannot listen on SSH {}:{} (already bound by another service)",
                            &assigned_host, self.server.ssh_port,
                        )
                        .into_bytes(),
                    );
                    Ok(false)
                }
            }
            80 | 443 => {
                // Assign HTTP host through config
                let assigned_host = self
                    .server
                    .address_delegator
                    .get_address(address, &self.user, &self.key_fingerprint, &self.peer)
                    .await;
                if self
                    .server
                    .http
                    .insert(
                        assigned_host.clone(),
                        self.peer,
                        Arc::new(SshTunnelHandler::new(
                            Arc::clone(&user_data.allow_fingerprint),
                            handle,
                            self.tx.clone(),
                            self.peer,
                            address.to_string(),
                            *port,
                        )),
                    )
                    .is_ok()
                {
                    user_data.http_hosts.insert(assigned_host.clone());
                    user_data
                        .host_addressing
                        .insert((address.to_string(), *port), assigned_host.clone());
                    info!("Serving HTTP for {} ({})", &assigned_host, self.peer);
                    let _ = self.tx.send(
                        format!(
                            "Serving HTTP on http://{}{}\r\n",
                            &assigned_host,
                            match self.server.http_port {
                                80 => "".into(),
                                port => format!(":{}", port),
                            }
                        )
                        .into_bytes(),
                    );
                    let _ = self.tx.send(
                        format!(
                            "Serving HTTPS on https://{}{}\r\n",
                            &assigned_host,
                            match self.server.https_port {
                                443 => "".into(),
                                port => format!(":{}", port),
                            }
                        )
                        .into_bytes(),
                    );
                    Ok(true)
                } else {
                    info!("Rejecting HTTP for {} ({})", &assigned_host, self.peer);
                    let _ = self.tx.send(
                        format!(
                            "Cannot listen on HTTP on http://{}{} (already bound by another service)",
                            &assigned_host,
                            match self.server.http_port {
                                80 => "".into(),
                                port => format!(":{}", port),
                            }
                        )
                        .into_bytes(),
                    );
                    Ok(false)
                }
            }
            // Handle TCP
            1..=1024 if !is_alias(address) => {
                info!(
                    "Failed to bind TCP port {} ({}): port too low",
                    port, self.peer
                );
                Ok(false)
            }
            _ => {
                let assigned_port = if *port == 0 {
                    let assigned_port = self.server.tcp_handler.get_free_port().await;
                    *port = assigned_port.into();
                    assigned_port
                } else if self.server.force_random_ports {
                    self.server.tcp_handler.get_free_port().await
                } else {
                    *port as u16
                };
                let tcp_alias = if is_alias(address) {
                    address
                } else {
                    "localhost"
                };
                if self
                    .server
                    .tcp
                    .insert(
                        TcpAlias(tcp_alias.to_string(), assigned_port),
                        self.peer,
                        Arc::new(SshTunnelHandler::new(
                            Arc::clone(&user_data.allow_fingerprint),
                            handle,
                            self.tx.clone(),
                            self.peer,
                            address.to_string(),
                            *port,
                        )),
                    )
                    .is_ok()
                {
                    user_data
                        .tcp_aliases
                        .insert(TcpAlias(tcp_alias.to_string(), assigned_port));
                    user_data.port_addressing.insert(
                        (address.to_string(), *port),
                        TcpAlias(tcp_alias.to_string(), assigned_port),
                    );
                    if is_alias(address) {
                        info!(
                            "Tunneling TCP port {} for alias {} ({})",
                            &assigned_port, address, self.peer
                        );
                        let _ = self.tx.send(
                            format!(
                                "Serving TCP port {} for alias {}\r\n",
                                &assigned_port, address,
                            )
                            .into_bytes(),
                        );
                    } else {
                        info!(
                            "Serving TCP for localhost:{} ({})",
                            &assigned_port, self.peer
                        );
                        let _ = self.tx.send(
                            format!(
                                "Serving TCP port on {}:{}\r\n",
                                self.server.domain, &assigned_port,
                            )
                            .into_bytes(),
                        );
                    }
                    Ok(true)
                } else {
                    if is_alias(address) {
                        info!(
                            "Rejecting TCP port {} for alias {} ({})",
                            &assigned_port, address, self.peer
                        );
                        let _ = self.tx.send(
                            format!(
                                "Cannot listen on TCP port {} for alias {} (already bound by another service)\r\n",
                                &assigned_port, address,
                            )
                            .into_bytes(),
                        );
                    } else {
                        info!(
                            "Rejecting TCP for localhost:{} ({})",
                            &assigned_port, self.peer
                        );
                        let _ = self.tx.send(
                            format!(
                                "Cannot listen on TCP port {}:{} (already bound by another service)\r\n",
                                self.server.domain, &assigned_port,
                            )
                            .into_bytes(),
                        );
                    }
                    Ok(false)
                }
            }
        }
    }

    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let user_data = match &mut self.auth_data {
            AuthenticatedData::User { user_data } | AuthenticatedData::Admin { user_data, .. } => {
                user_data
            }
            AuthenticatedData::None | AuthenticatedData::Proxy => {
                return Err(russh::Error::Disconnect)
            }
        };
        match port {
            22 => {
                if let Some(assigned_host) = user_data
                    .host_addressing
                    .remove(&(address.to_string(), port))
                {
                    self.server.ssh.remove(&assigned_host, self.peer);
                    user_data.ssh_hosts.remove(&assigned_host);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            80 | 443 => {
                if let Some(assigned_host) = user_data
                    .host_addressing
                    .remove(&(address.to_string(), port))
                {
                    self.server.http.remove(&assigned_host, self.peer);
                    user_data.http_hosts.remove(&assigned_host);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => {
                if let Some(assigned_alias) = user_data
                    .port_addressing
                    .remove(&(address.to_string(), port))
                {
                    let key: &dyn TcpAliasKey = assigned_alias.borrow();
                    self.server.tcp.remove(key, self.peer);
                    user_data.tcp_aliases.remove(key);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let port_to_connect = port_to_connect as u16;
        if port_to_connect == self.server.http_port || port_to_connect == self.server.https_port {
            if let Some(handler) = self.server.http.get(host_to_connect) {
                if let Ok(mut io) = handler
                    .tunneling_channel(
                        originator_address,
                        originator_port as u16,
                        self.key_fingerprint.clone(),
                    )
                    .await
                {
                    if let AuthenticatedData::None = self.auth_data {
                        self.auth_data = AuthenticatedData::Proxy;
                        *self.is_proxied.lock().await = true;
                    }
                    let _ = handler.log_channel().send(
                        format!(
                            "New HTTP proxy from {}:{} => http://{}",
                            originator_address, originator_port, host_to_connect
                        )
                        .into_bytes(),
                    );
                    tokio::spawn(async move {
                        let mut stream = channel.into_stream();
                        let _ = copy_bidirectional(&mut stream, &mut io).await;
                    });
                    info!(
                        "Accepted connection from {} => {} ({})",
                        self.peer, host_to_connect, handler.peer,
                    );
                    let _ = self
                        .tx
                        .send(format!("Forwarding HTTP from {}\r\n", host_to_connect).into_bytes());
                    return Ok(true);
                }
            }
        } else if port_to_connect == self.server.ssh_port {
            if let Some(handler) = self.server.ssh.get(host_to_connect) {
                if let Ok(mut io) = handler
                    .tunneling_channel(
                        originator_address,
                        originator_port as u16,
                        self.key_fingerprint.clone(),
                    )
                    .await
                {
                    if let AuthenticatedData::None = self.auth_data {
                        self.auth_data = AuthenticatedData::Proxy;
                        *self.is_proxied.lock().await = true;
                    }
                    let _ = handler.log_channel().send(
                        format!(
                            "New SSH proxy from {}:{} => {}:{}",
                            originator_address, originator_port, host_to_connect, port_to_connect
                        )
                        .into_bytes(),
                    );
                    tokio::spawn(async move {
                        let mut stream = channel.into_stream();
                        let _ = copy_bidirectional(&mut stream, &mut io).await;
                    });
                    info!(
                        "Accepted connection from {} => {} ({})",
                        self.peer, host_to_connect, handler.peer,
                    );
                    let _ = self
                        .tx
                        .send(format!("Forwarding SSH from {}\r\n", host_to_connect).into_bytes());
                    return Ok(true);
                }
            }
        } else if let Some(handler) = self
            .server
            .tcp
            .get(&BorrowedTcpAlias(host_to_connect, &port_to_connect) as &dyn TcpAliasKey)
        {
            if let Ok(mut io) = handler
                .tunneling_channel(
                    originator_address,
                    originator_port as u16,
                    self.key_fingerprint.clone(),
                )
                .await
            {
                if let AuthenticatedData::None = self.auth_data {
                    self.auth_data = AuthenticatedData::Proxy;
                    *self.is_proxied.lock().await = true;
                }
                let _ = handler.log_channel().send(
                    format!(
                        "New TCP proxy from {}:{} => {}:{}",
                        originator_address, originator_port, host_to_connect, port_to_connect
                    )
                    .into_bytes(),
                );
                tokio::spawn(async move {
                    let mut stream = channel.into_stream();
                    let _ = copy_bidirectional(&mut stream, &mut io).await;
                });
                info!(
                    "Accepted connection from {} => {} ({})",
                    self.peer, host_to_connect, handler.peer,
                );
                let _ = self
                    .tx
                    .send(format!("Forwarding TCP from {}\r\n", host_to_connect).into_bytes());
                return Ok(true);
            }
        }
        if let AuthenticatedData::None = self.auth_data {
            Err(russh::Error::Disconnect)
        } else {
            Ok(false)
        }
    }
}

impl Drop for ServerHandler {
    fn drop(&mut self) {
        match &mut self.auth_data {
            AuthenticatedData::User { user_data } | AuthenticatedData::Admin { user_data, .. } => {
                for host in user_data.ssh_hosts.iter() {
                    self.server.ssh.remove(host, self.peer);
                }
                for host in user_data.http_hosts.iter() {
                    self.server.http.remove(host, self.peer);
                }
                for port in user_data.tcp_aliases.iter() {
                    self.server.tcp.remove(port, self.peer);
                }
            }
            AuthenticatedData::Proxy | AuthenticatedData::None => (),
        }
        info!("{} disconnected", self.peer);
    }
}

fn is_alias(address: &str) -> bool {
    address != "localhost" && !address.is_empty() && address != "*"
}
