use std::{
    borrow::Borrow,
    collections::{BTreeSet, HashMap, HashSet},
    fmt::Display,
    net::SocketAddr,
    sync::Arc,
};

use crate::{
    admin::AdminInterface,
    droppable_handle::DroppableHandle,
    error::ServerError,
    fingerprints::AuthenticationType,
    handler::ConnectionHandler,
    login::AuthenticationRequest,
    tcp::{is_alias, PortHandler, NO_ALIAS_HOST},
    tcp_alias::{BorrowedTcpAlias, TcpAlias, TcpAliasKey},
    SandholeServer,
};

use async_trait::async_trait;
use log::{debug, info, warn};
use russh::{
    server::{Auth, Handler, Msg, Session},
    Channel, ChannelId, ChannelStream, Disconnect, MethodSet,
};
use russh_keys::PublicKey;
use ssh_key::{Fingerprint, HashAlg};
use tokio::{
    io::{copy_bidirectional, AsyncWriteExt},
    sync::{mpsc, oneshot, Mutex, RwLock},
    time::{sleep, timeout},
};

#[derive(Clone)]
pub(crate) struct SshTunnelHandler {
    allow_fingerprint: Arc<RwLock<Box<FingerprintFn>>>,
    handle: russh::server::Handle,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    peer: SocketAddr,
    address: String,
    port: u32,
}

impl SshTunnelHandler {
    pub(crate) fn new(
        allow_fingerprint: Arc<RwLock<Box<FingerprintFn>>>,
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

impl Drop for SshTunnelHandler {
    fn drop(&mut self) {
        let _ = self.tx.send(
            format!(
                "\x1b[1;33mWARNING:\x1b[0m The handler for {}:{} has been dropped. \
                No new connections will be accepted.\r\n",
                self.address, self.port
            )
            .into_bytes(),
        );
    }
}

#[async_trait]
impl ConnectionHandler<ChannelStream<Msg>> for SshTunnelHandler {
    fn log_channel(&self) -> mpsc::UnboundedSender<Vec<u8>> {
        self.tx.clone()
    }

    async fn tunneling_channel(&self, ip: &str, port: u16) -> anyhow::Result<ChannelStream<Msg>> {
        let channel = self
            .handle
            .channel_open_forwarded_tcpip(self.address.clone(), self.port, ip, port.into())
            .await?
            .into_stream();
        Ok(channel)
    }

    async fn aliasing_channel<'a>(
        &self,
        ip: &str,
        port: u16,
        fingerprint: Option<&'a Fingerprint>,
    ) -> anyhow::Result<ChannelStream<Msg>> {
        if !(self.allow_fingerprint.read().await)(fingerprint) {
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

type FingerprintFn = dyn Fn(Option<&Fingerprint>) -> bool + Send + Sync;

struct UserData {
    allow_fingerprint: Arc<RwLock<Box<FingerprintFn>>>,
    col_width: Option<u32>,
    row_height: Option<u32>,
    ssh_hosts: HashSet<String>,
    http_hosts: HashSet<String>,
    tcp_aliases: HashSet<TcpAlias>,
    host_addressing: HashMap<TcpAlias, String>,
    port_addressing: HashMap<TcpAlias, TcpAlias>,
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
    None {
        cancelation_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    },
    Proxy,
    User {
        user_data: Box<UserData>,
        quota_key: String,
    },
    Admin {
        user_data: Box<UserData>,
        admin_data: Box<AdminData>,
    },
}

impl Display for AuthenticatedData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthenticatedData::None { .. } => f.write_str("no authentication"),
            AuthenticatedData::Proxy => f.write_str("no authentication (proxy)"),
            AuthenticatedData::User { .. } => f.write_str("user authentication"),
            AuthenticatedData::Admin { .. } => f.write_str("admin authentication"),
        }
    }
}

pub(crate) struct ServerHandler {
    _timeout_handle: Option<DroppableHandle<()>>,
    peer: SocketAddr,
    user: Option<String>,
    key_fingerprint: Option<Fingerprint>,
    auth_data: AuthenticatedData,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: Option<mpsc::UnboundedReceiver<Vec<u8>>>,
    open_session_join_handle: Option<DroppableHandle<()>>,
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
    // Create a new handler for the SSH connection.
    fn new_client(
        &mut self,
        peer_address: Option<SocketAddr>,
        cancelation_tx: oneshot::Sender<()>,
    ) -> ServerHandler {
        if let Some(peer) = &peer_address {
            info!("{} connected", peer);
        }
        let (tx, rx) = mpsc::unbounded_channel();
        let peer_address = peer_address.unwrap();
        ServerHandler {
            _timeout_handle: None,
            peer: peer_address,
            user: None,
            key_fingerprint: None,
            auth_data: AuthenticatedData::None {
                cancelation_tx: Arc::new(Mutex::new(Some(cancelation_tx))),
            },
            tx,
            rx: Some(rx),
            open_session_join_handle: None,
            server: Arc::clone(self),
        }
    }
}

#[async_trait]
impl Handler for ServerHandler {
    type Error = russh::Error;

    // Handle creation of a channel for sending and receiving logs to the client.
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let Some(mut rx) = self.rx.take() else {
            return Ok(false);
        };
        if let AuthenticatedData::None { .. } = self.auth_data {
            return Err(russh::Error::Disconnect);
        }
        let mut stream = channel.into_stream();
        let join_handle = tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                if stream.write_all(&message).await.is_err() {
                    break;
                }
            }
        });
        self.open_session_join_handle = Some(DroppableHandle(join_handle));
        Ok(true)
    }

    // Return the default authentication method.
    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::PUBLICKEY),
        })
    }

    // Authenticate users with a password if the API login service is available.
    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if let Some(ref api_login) = self.server.api_login {
            if let Ok(is_authenticated) =
                timeout(self.server.authentication_request_timeout, async {
                    api_login
                        .authenticate(&AuthenticationRequest {
                            user,
                            password,
                            remote_address: &self.peer,
                        })
                        .await
                })
                .await
            {
                if is_authenticated {
                    self.user = Some(user.into());
                    self.auth_data = AuthenticatedData::User {
                        user_data: Box::default(),
                        quota_key: format!("u:{}", user),
                    };
                    info!("{} connected with {} (password)", self.peer, self.auth_data);
                    return Ok(Auth::Accept);
                } else {
                    warn!("{} failed password authentication", self.peer);
                }
            } else {
                warn!("Authentication request timed out");
            }
        }
        Ok(Auth::Reject {
            proceed_with_methods: None,
        })
    }

    // Receive an authentication request and handle it by validating the fingerprint,
    // marking the session as unauthenticated if unknown to potentially clean up if unproxied.
    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        let fingerprint = public_key.fingerprint(HashAlg::Sha256);
        self.user = Some(user.into());
        self.key_fingerprint = Some(fingerprint);
        let authentication = self
            .server
            .fingerprints_validator
            .authenticate_fingerprint(self.key_fingerprint.as_ref().unwrap());
        info!(
            "{} connected with {} (public key)",
            self.peer, self.auth_data
        );
        match authentication {
            AuthenticationType::None => {
                // Start timer for user to do local port forwarding.
                // Otherwise, the connection will be canceled upon expiration
                let AuthenticatedData::None { ref cancelation_tx } = self.auth_data else {
                    warn!("{} is already authenticated", self.peer);
                    return Ok(Auth::Reject {
                        proceed_with_methods: None,
                    });
                };
                let cancelation_tx = Arc::clone(cancelation_tx);
                let timeout = self.server.idle_connection_timeout;
                self._timeout_handle = Some(DroppableHandle(tokio::spawn(async move {
                    sleep(timeout).await;
                    if let Some(cancelation_tx) = cancelation_tx.lock().await.take() {
                        let _ = cancelation_tx.send(());
                    }
                })));
                Ok(Auth::Accept)
            }
            AuthenticationType::User => {
                self.auth_data = AuthenticatedData::User {
                    user_data: Box::default(),
                    quota_key: format!("f:{}", fingerprint),
                };
                Ok(Auth::Accept)
            }
            AuthenticationType::Admin => {
                self.auth_data = AuthenticatedData::Admin {
                    user_data: Box::default(),
                    admin_data: Box::default(),
                };
                Ok(Auth::Accept)
            }
        }
    }

    // Handle data received from the client such as key presses.
    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Sending Ctrl+C ends the session and disconnects the client
        if data == [3] {
            session.disconnect(Disconnect::ByApplication, "", "English")?;
            return Ok(());
        }
        debug!("received data {:?}", data);
        match &mut self.auth_data {
            AuthenticatedData::None { .. } => return Err(russh::Error::Disconnect),
            AuthenticatedData::Proxy | AuthenticatedData::User { .. } => (),
            AuthenticatedData::Admin { admin_data, .. } => {
                if let Some(admin_interface) = admin_data.admin_interface.as_mut() {
                    match data {
                        // Tab
                        b"\t" => admin_interface.next_tab(),
                        // Shift+Tab
                        b"\x1b[Z" => admin_interface.previous_tab(),
                        // Up
                        b"\x1b[A" | b"k" => admin_interface.move_up(),
                        // Down
                        b"\x1b[B" | b"j" => admin_interface.move_down(),
                        // Left
                        b"\x1b[D" | b"h" => admin_interface.move_left(),
                        // Right
                        b"\x1b[C" | b"l" => admin_interface.move_right(),
                        _ => (),
                    }
                }
            }
        }
        Ok(())
    }

    // Receive and handle any additional commands from the client where appropriate.
    async fn exec_request(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!("exec_request data {:?}", data);
        let cmd = String::from_utf8_lossy(data);
        for command in cmd.split_whitespace() {
            match (command, &mut self.auth_data) {
                (
                    "admin",
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
                    command,
                    AuthenticatedData::User { user_data, .. }
                    | AuthenticatedData::Admin { user_data, .. },
                ) if command.starts_with("allowed-fingerprints=") => {
                    let set: BTreeSet<Fingerprint> = command
                        .trim_start_matches("allowed-fingerprints=")
                        .split(',')
                        .filter_map(|key| key.parse::<Fingerprint>().ok())
                        .collect();
                    *user_data.allow_fingerprint.write().await =
                        Box::new(move |fingerprint| fingerprint.is_some_and(|fp| set.contains(fp)))
                }
                (command, _) => {
                    debug!(
                        "Invalid command {} received for {} ({})",
                        command, self.auth_data, self.peer
                    );
                    let _ = self
                        .tx
                        .send(format!("Ignoring unknown command {}...", command).into_bytes());
                }
            }
        }
        Ok(())
    }

    // Set up data for the PTY in order to properly use the TUI.
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
            AuthenticatedData::User { user_data, .. }
            | AuthenticatedData::Admin { user_data, .. } => {
                user_data.col_width = Some(col_width);
                user_data.row_height = Some(row_height);
                session.channel_success(channel)?;
            }
            AuthenticatedData::None { .. } | AuthenticatedData::Proxy => (),
        }
        Ok(())
    }

    // Handle changes to the client's window size.
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

    // Handle a remote forwarding request for the client.
    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if *port > u16::MAX.into() {
            return Err(russh::Error::Disconnect);
        }
        // Only allow remote forwarding for authorized keys
        let (user_data, quota_key) = match &mut self.auth_data {
            AuthenticatedData::User {
                user_data,
                quota_key,
            } => (user_data, Some(quota_key.clone())),
            AuthenticatedData::Admin { user_data, .. } => (user_data, None),
            AuthenticatedData::None { .. } | AuthenticatedData::Proxy => {
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
                if let Err(err) = self.server.ssh.insert(
                    assigned_host.clone(),
                    self.peer,
                    quota_key,
                    Arc::new(SshTunnelHandler::new(
                        Arc::clone(&user_data.allow_fingerprint),
                        handle,
                        self.tx.clone(),
                        self.peer,
                        address.to_string(),
                        *port,
                    )),
                ) {
                    info!("Rejecting SSH for {} ({})", &assigned_host, self.peer);
                    let _ = self.tx.send(
                        format!(
                            "Cannot listen to SSH on {}:{} ({})",
                            &assigned_host, self.server.ssh_port, err,
                        )
                        .into_bytes(),
                    );
                    Ok(false)
                } else {
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
                    user_data.ssh_hosts.insert(assigned_host.clone());
                    user_data
                        .host_addressing
                        .insert(TcpAlias(address.to_string(), *port as u16), assigned_host);
                    Ok(true)
                }
            }
            80 | 443 => {
                // Assign HTTP host through config
                let assigned_host = self
                    .server
                    .address_delegator
                    .get_address(address, &self.user, &self.key_fingerprint, &self.peer)
                    .await;
                if let Err(err) = self.server.http.insert(
                    assigned_host.clone(),
                    self.peer,
                    quota_key,
                    Arc::new(SshTunnelHandler::new(
                        Arc::clone(&user_data.allow_fingerprint),
                        handle,
                        self.tx.clone(),
                        self.peer,
                        address.to_string(),
                        *port,
                    )),
                ) {
                    info!("Rejecting HTTP for {} ({})", &assigned_host, self.peer);
                    let _ = self.tx.send(
                        format!(
                            "Cannot listen to HTTP on http://{}{} ({})",
                            &assigned_host,
                            match self.server.http_port {
                                80 => "".into(),
                                port => format!(":{}", port),
                            },
                            err,
                        )
                        .into_bytes(),
                    );
                    Ok(false)
                } else {
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
                    user_data.http_hosts.insert(assigned_host.clone());
                    user_data
                        .host_addressing
                        .insert(TcpAlias(address.to_string(), *port as u16), assigned_host);
                    Ok(true)
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
                    NO_ALIAS_HOST
                };
                if let Err(err) = self.server.tcp.insert(
                    TcpAlias(tcp_alias.to_string(), assigned_port),
                    self.peer,
                    quota_key,
                    Arc::new(SshTunnelHandler::new(
                        Arc::clone(&user_data.allow_fingerprint),
                        handle,
                        self.tx.clone(),
                        self.peer,
                        address.to_string(),
                        *port,
                    )),
                ) {
                    if is_alias(address) {
                        info!(
                            "Rejecting TCP port {} for alias {} ({})",
                            &assigned_port, address, self.peer
                        );
                        let _ = self.tx.send(
                            format!(
                                "Cannot listen to TCP on port {} for alias {} ({})\r\n",
                                &assigned_port, address, err,
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
                                "Cannot listen to TCP on {}:{} ({})\r\n",
                                self.server.domain, &assigned_port, err,
                            )
                            .into_bytes(),
                        );
                    }
                    Ok(false)
                } else {
                    user_data
                        .tcp_aliases
                        .insert(TcpAlias(tcp_alias.to_string(), assigned_port));
                    user_data.port_addressing.insert(
                        TcpAlias(address.to_string(), *port as u16),
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
                }
            }
        }
    }

    // Handle closure of a remote forwarding request.
    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if port > u16::MAX.into() {
            return Err(russh::Error::Disconnect);
        }
        let user_data = match &mut self.auth_data {
            AuthenticatedData::User { user_data, .. }
            | AuthenticatedData::Admin { user_data, .. } => user_data,
            AuthenticatedData::None { .. } | AuthenticatedData::Proxy => {
                return Err(russh::Error::Disconnect)
            }
        };
        match port {
            22 => {
                if let Some(assigned_host) =
                    user_data
                        .host_addressing
                        .remove(&BorrowedTcpAlias(address, &(port as u16)) as &dyn TcpAliasKey)
                {
                    self.server.ssh.remove(&assigned_host, &self.peer);
                    user_data.ssh_hosts.remove(&assigned_host);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            80 | 443 => {
                if let Some(assigned_host) =
                    user_data
                        .host_addressing
                        .remove(&BorrowedTcpAlias(address, &(port as u16)) as &dyn TcpAliasKey)
                {
                    self.server.http.remove(&assigned_host, &self.peer);
                    user_data.http_hosts.remove(&assigned_host);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => {
                if let Some(assigned_alias) =
                    user_data
                        .port_addressing
                        .remove(&BorrowedTcpAlias(address, &(port as u16)) as &dyn TcpAliasKey)
                {
                    let key: &dyn TcpAliasKey = assigned_alias.borrow();
                    self.server.tcp.remove(key, &self.peer);
                    user_data.tcp_aliases.remove(key);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }

    // Handle a local forwarding request (i.e. proxy tunnel for aliases).
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if port_to_connect > u16::MAX.into() || originator_port > u16::MAX.into() {
            return Err(russh::Error::Disconnect);
        }
        let port_to_connect = port_to_connect as u16;
        if port_to_connect == self.server.http_port || port_to_connect == self.server.https_port {
            if let Some(handler) = self.server.http.get(host_to_connect) {
                if let Ok(mut io) = handler
                    .aliasing_channel(
                        originator_address,
                        originator_port as u16,
                        self.key_fingerprint.as_ref(),
                    )
                    .await
                {
                    if let AuthenticatedData::None { ref cancelation_tx } = self.auth_data {
                        cancelation_tx.lock().await.take();
                        self.auth_data = AuthenticatedData::Proxy;
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
                    .aliasing_channel(
                        originator_address,
                        originator_port as u16,
                        self.key_fingerprint.as_ref(),
                    )
                    .await
                {
                    if let AuthenticatedData::None { ref cancelation_tx } = self.auth_data {
                        cancelation_tx.lock().await.take();
                        self.auth_data = AuthenticatedData::Proxy;
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
                .aliasing_channel(
                    originator_address,
                    originator_port as u16,
                    self.key_fingerprint.as_ref(),
                )
                .await
            {
                if let AuthenticatedData::None { ref cancelation_tx } = self.auth_data {
                    cancelation_tx.lock().await.take();
                    self.auth_data = AuthenticatedData::Proxy;
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
        if let AuthenticatedData::None { .. } = self.auth_data {
            Err(russh::Error::Disconnect)
        } else {
            Ok(false)
        }
    }
}

impl Drop for ServerHandler {
    fn drop(&mut self) {
        info!("{} disconnected", self.peer);
        match self.auth_data {
            AuthenticatedData::User { .. } | AuthenticatedData::Admin { .. } => {
                let server = Arc::clone(&self.server);
                let peer = self.peer;
                tokio::task::spawn_blocking(move || {
                    server.ssh.remove_by_address(&peer);
                    server.http.remove_by_address(&peer);
                    server.tcp.remove_by_address(&peer);
                });
            }
            AuthenticatedData::Proxy | AuthenticatedData::None { .. } => (),
        }
    }
}
