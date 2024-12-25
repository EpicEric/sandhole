use std::{
    borrow::Borrow,
    collections::{BTreeSet, HashMap, HashSet},
    fmt::Display,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use crate::{
    admin::AdminInterface,
    connection_handler::ConnectionHandler,
    droppable_handle::DroppableHandle,
    error::ServerError,
    fingerprints::AuthenticationType,
    http::proxy_handler,
    login::AuthenticationRequest,
    quota::{TokenHolder, UserIdentification},
    tcp::{is_alias, PortHandler, NO_ALIAS_HOST},
    tcp_alias::{BorrowedTcpAlias, TcpAlias, TcpAliasKey},
    SandholeServer,
};

use async_trait::async_trait;
use http::Request;
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use log::{debug, info, warn};
use russh::{
    server::{Auth, Handler, Msg, Session},
    Channel, ChannelId, ChannelStream, MethodSet,
};
use russh_keys::PublicKey;
use ssh_key::{Fingerprint, HashAlg};
use tokio::{
    io::{copy_bidirectional, AsyncWriteExt},
    sync::{mpsc, watch, Mutex, RwLock},
    time::{sleep, timeout},
};

type FingerprintFn = dyn Fn(Option<&Fingerprint>) -> bool + Send + Sync;

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
        if (self.allow_fingerprint.read().await)(fingerprint) {
            let channel = self
                .handle
                .channel_open_forwarded_tcpip(self.address.clone(), self.port, ip, port.into())
                .await?
                .into_stream();
            Ok(channel)
        } else {
            Err(ServerError::FingerprintDenied.into())
        }
    }
}

struct UserData {
    allow_fingerprint: Arc<RwLock<Box<FingerprintFn>>>,
    quota_key: TokenHolder,
    col_width: Option<u32>,
    row_height: Option<u32>,
    ssh_hosts: HashSet<String>,
    http_hosts: HashSet<String>,
    tcp_aliases: HashSet<TcpAlias>,
    host_addressing: HashMap<TcpAlias, String>,
    port_addressing: HashMap<TcpAlias, TcpAlias>,
}

impl UserData {
    fn new(quota_key: TokenHolder) -> Self {
        Self {
            allow_fingerprint: Arc::new(RwLock::new(Box::new(|_| true))),
            quota_key,
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

struct AdminData {
    admin_interface: Option<AdminInterface>,
}

impl AdminData {
    fn new() -> Self {
        Self {
            admin_interface: None,
        }
    }
}

enum AuthenticatedData {
    None {
        proxy_count: Arc<AtomicUsize>,
    },
    User {
        user_data: Box<UserData>,
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
            AuthenticatedData::User { .. } => f.write_str("user authentication"),
            AuthenticatedData::Admin { .. } => f.write_str("admin authentication"),
        }
    }
}

pub(crate) struct ServerHandler {
    id: usize,
    timeout_handle: Arc<Mutex<Option<DroppableHandle<()>>>>,
    peer: SocketAddr,
    user: Option<String>,
    key_fingerprint: Option<Fingerprint>,
    cancelation_tx: watch::Sender<()>,
    auth_data: AuthenticatedData,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: Option<mpsc::UnboundedReceiver<Vec<u8>>>,
    open_session_join_handle: Option<DroppableHandle<()>>,
    server: Arc<SandholeServer>,
}

pub(crate) trait Server {
    fn new_client(
        &mut self,
        peer_address: SocketAddr,
        cancelation_tx: watch::Sender<()>,
    ) -> ServerHandler;
}

impl Server for Arc<SandholeServer> {
    // Create a new handler for the SSH connection.
    fn new_client(
        &mut self,
        peer_address: SocketAddr,
        cancelation_tx: watch::Sender<()>,
    ) -> ServerHandler {
        let id = self.session_id.fetch_add(1, Ordering::AcqRel);
        info!("{} connected", peer_address);
        let (tx, rx) = mpsc::unbounded_channel();
        ServerHandler {
            id,
            timeout_handle: Arc::new(Mutex::new(None)),
            peer: peer_address,
            user: None,
            key_fingerprint: None,
            cancelation_tx,
            auth_data: AuthenticatedData::None {
                proxy_count: Arc::new(AtomicUsize::new(0)),
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
            if matches!(self.auth_data, AuthenticatedData::None { .. }) {
                return Err(russh::Error::Disconnect);
            }
            return Ok(false);
        };
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
                    self.server
                        .sessions_password
                        .lock()
                        .unwrap()
                        .entry(user.into())
                        .or_default()
                        .insert(self.id, self.cancelation_tx.clone());
                    self.user = Some(user.into());
                    self.auth_data = AuthenticatedData::User {
                        user_data: Box::new(UserData::new(TokenHolder::User(
                            UserIdentification::Username(user.into()),
                        ))),
                    };
                    info!(
                        "{} ({}) connected with {} (password)",
                        user, self.peer, self.auth_data
                    );
                    return Ok(Auth::Accept);
                } else {
                    warn!("{} ({}) failed password authentication", user, self.peer);
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
            .authenticate_fingerprint(&fingerprint);
        match authentication {
            AuthenticationType::None => {
                // Start timer for user to do local port forwarding.
                // Otherwise, the connection will be canceled upon expiration
                let cancelation_tx = self.cancelation_tx.clone();
                let timeout = self.server.idle_connection_timeout;
                *self.timeout_handle.lock().await =
                    Some(DroppableHandle(tokio::spawn(async move {
                        sleep(timeout).await;
                        let _ = cancelation_tx.send(());
                    })));
            }
            AuthenticationType::User => {
                self.server
                    .sessions_publickey
                    .lock()
                    .unwrap()
                    .entry(fingerprint)
                    .or_default()
                    .insert(self.id, self.cancelation_tx.clone());
                self.auth_data = AuthenticatedData::User {
                    user_data: Box::new(UserData::new(TokenHolder::User(
                        UserIdentification::PublicKey(fingerprint),
                    ))),
                };
            }
            AuthenticationType::Admin => {
                self.auth_data = AuthenticatedData::Admin {
                    user_data: Box::new(UserData::new(TokenHolder::Admin(
                        UserIdentification::PublicKey(fingerprint),
                    ))),
                    admin_data: Box::new(AdminData::new()),
                };
            }
        }
        info!(
            "{} ({}) connected with {} (public key {})",
            user, self.peer, self.auth_data, fingerprint
        );
        Ok(Auth::Accept)
    }

    // Handle data received from the client such as key presses.
    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Ctrl+C ends the session and disconnects the client
        if data == b"\x03" {
            let _ = self.cancelation_tx.send(());
            return Ok(());
        }
        debug!("received data {:?}", data);
        match &mut self.auth_data {
            AuthenticatedData::None { .. } | AuthenticatedData::User { .. } => (),
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
                        // Esc
                        b"\x1b" => admin_interface.cancel(),
                        // Enter
                        b"\r" => admin_interface.enter(),
                        // Delete
                        b"\x1b[3~" => admin_interface.delete(),
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
            AuthenticatedData::None { .. } => (),
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
                    warn!("Failed to resize terminal for {}", self.peer);
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
        let user_data = match &mut self.auth_data {
            AuthenticatedData::User { user_data, .. }
            | AuthenticatedData::Admin { user_data, .. } => user_data,
            AuthenticatedData::None { .. } => return Err(russh::Error::Disconnect),
        };
        let handle = session.handle();
        match *port {
            // Assign SSH host through config
            22 => {
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
                        "Error: Alias is required for SSH host\r\n"
                            .to_string()
                            .into_bytes(),
                    );
                    return Ok(false);
                }
                if let Err(err) = self.server.ssh.insert(
                    assigned_host.clone(),
                    self.peer,
                    user_data.quota_key.clone(),
                    Arc::new(SshTunnelHandler::new(
                        Arc::clone(&user_data.allow_fingerprint),
                        handle,
                        self.tx.clone(),
                        self.peer,
                        address.to_string(),
                        *port,
                    )),
                ) {
                    info!(
                        "Rejecting SSH for {} ({}) - {}",
                        &assigned_host, self.peer, err
                    );
                    let _ = self.tx.send(
                        format!(
                            "Cannot listen to SSH on {}:{} ({})\r\n",
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
            // Assign HTTP host through config
            80 | 443 => {
                let assigned_host = self
                    .server
                    .address_delegator
                    .get_address(address, &self.user, &self.key_fingerprint, &self.peer)
                    .await;
                if let Err(err) = self.server.http.insert(
                    assigned_host.clone(),
                    self.peer,
                    user_data.quota_key.clone(),
                    Arc::new(SshTunnelHandler::new(
                        Arc::clone(&user_data.allow_fingerprint),
                        handle,
                        self.tx.clone(),
                        self.peer,
                        address.to_string(),
                        *port,
                    )),
                ) {
                    info!(
                        "Rejecting HTTP for {} ({}) - {}",
                        &assigned_host, self.peer, err
                    );
                    let _ = self.tx.send(
                        format!(
                            "Cannot listen to HTTP on http://{}{} ({})\r\n",
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
            1..1024 if !is_alias(address) => {
                info!(
                    "Failed to bind TCP port {} ({}): port too low",
                    port, self.peer
                );
                let _ = self.tx.send(
                    format!(
                        "Cannot listen to TCP on port {}:{} (port too low)\r\n",
                        &self.server.domain, port,
                    )
                    .into_bytes(),
                );
                Ok(false)
            }
            _ => {
                let assigned_port = if *port == 0 {
                    let assigned_port = match self.server.tcp_handler.get_free_port().await {
                        Ok(port) => port,
                        Err(err) => {
                            info!(
                                "Failed to bind random TCP port for alias {} ({}) - {}",
                                address, self.peer, err,
                            );
                            let _ = self.tx.send(
                                format!(
                                    "Cannot listen to TCP on random port of {} ({})\r\n",
                                    port, err,
                                )
                                .into_bytes(),
                            );
                            return Ok(false);
                        }
                    };
                    *port = assigned_port.into();
                    assigned_port
                } else if self.server.force_random_ports {
                    match self.server.tcp_handler.get_free_port().await {
                        Ok(port) => port,
                        Err(err) => {
                            info!(
                                "Failed to bind random TCP port for alias {} ({}) - {}",
                                address, self.peer, err,
                            );
                            let _ = self.tx.send(
                                format!(
                                    "Cannot listen to TCP on random port of {} ({})\r\n",
                                    port, err
                                )
                                .into_bytes(),
                            );
                            return Ok(false);
                        }
                    }
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
                    user_data.quota_key.clone(),
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
                            "Rejecting TCP port {} for alias {} ({}) - {}",
                            &assigned_port, address, self.peer, err,
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
                            "Rejecting TCP for localhost:{} ({}) - {}",
                            &assigned_port, self.peer, err,
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
                                "Tunneling TCP port {} for alias {}\r\n",
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
            AuthenticatedData::None { .. } => return Err(russh::Error::Disconnect),
        };
        match port {
            22 => {
                if let Some(assigned_host) =
                    user_data
                        .host_addressing
                        .remove(&BorrowedTcpAlias(address, &(port as u16)) as &dyn TcpAliasKey)
                {
                    info!(
                        "Stopped SSH forwarding for {} ({})",
                        &assigned_host, self.peer
                    );
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
                    info!(
                        "Stopped HTTP forwarding for {} ({})",
                        &assigned_host, self.peer
                    );
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
                    info!(
                        "Stopped TCP forwarding for {}:{} ({})",
                        &assigned_alias.0, assigned_alias.1, self.peer
                    );
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
            let peer = self.peer;
            let fingerprint = self.key_fingerprint;
            let proxy_data = Arc::clone(&self.server.aliasing_proxy_data);
            let service = service_fn(move |req: Request<Incoming>| {
                proxy_handler(req, peer, fingerprint, Arc::clone(&proxy_data))
            });
            let io = TokioIo::new(channel.into_stream());
            match self.auth_data {
                AuthenticatedData::None { ref proxy_count } => {
                    self.timeout_handle.lock().await.take();
                    proxy_count.fetch_add(1, Ordering::Release);
                    let proxy_count = Arc::clone(proxy_count);
                    let timeout_handle = Arc::clone(&self.timeout_handle);
                    let idle_connection_timeout = self.server.idle_connection_timeout;
                    let cancelation_tx = self.cancelation_tx.clone();
                    tokio::spawn(async move {
                        let server = auto::Builder::new(TokioExecutor::new());
                        let conn = server.serve_connection_with_upgrades(io, service);
                        let _ = conn.await;
                        if proxy_count.fetch_sub(1, Ordering::AcqRel) == 1 {
                            *timeout_handle.lock().await =
                                Some(DroppableHandle(tokio::spawn(async move {
                                    sleep(idle_connection_timeout).await;
                                    let _ = cancelation_tx.send(());
                                })));
                        }
                    });
                }
                _ => {
                    tokio::spawn(async move {
                        let server = auto::Builder::new(TokioExecutor::new());
                        let conn = server.serve_connection_with_upgrades(io, service);
                        let _ = conn.await;
                    });
                }
            }

            return Ok(true);
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
                    let _ = handler.log_channel().send(
                        format!(
                            "New SSH proxy from {}:{} => {}:{}\r\n",
                            originator_address, originator_port, host_to_connect, port_to_connect
                        )
                        .into_bytes(),
                    );
                    match self.auth_data {
                        AuthenticatedData::None { ref proxy_count } => {
                            self.timeout_handle.lock().await.take();
                            proxy_count.fetch_add(1, Ordering::Release);
                            let proxy_count = Arc::clone(proxy_count);
                            let timeout_handle = Arc::clone(&self.timeout_handle);
                            let idle_connection_timeout = self.server.idle_connection_timeout;
                            let cancelation_tx = self.cancelation_tx.clone();
                            let tcp_connection_timeout = self.server.tcp_connection_timeout;
                            tokio::spawn(async move {
                                let mut stream = channel.into_stream();
                                match tcp_connection_timeout {
                                    Some(duration) => {
                                        let _ = timeout(duration, async {
                                            copy_bidirectional(&mut stream, &mut io).await
                                        })
                                        .await;
                                    }
                                    None => {
                                        let _ = copy_bidirectional(&mut stream, &mut io).await;
                                    }
                                }
                                if proxy_count.fetch_sub(1, Ordering::AcqRel) == 1 {
                                    *timeout_handle.lock().await =
                                        Some(DroppableHandle(tokio::spawn(async move {
                                            sleep(idle_connection_timeout).await;
                                            let _ = cancelation_tx.send(());
                                        })));
                                }
                            });
                        }
                        _ => {
                            let tcp_connection_timeout = self.server.tcp_connection_timeout;
                            tokio::spawn(async move {
                                let mut stream = channel.into_stream();
                                match tcp_connection_timeout {
                                    Some(duration) => {
                                        let _ = timeout(duration, async {
                                            copy_bidirectional(&mut stream, &mut io).await
                                        })
                                        .await;
                                    }
                                    None => {
                                        let _ = copy_bidirectional(&mut stream, &mut io).await;
                                    }
                                }
                            });
                        }
                    }
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
                let _ = handler.log_channel().send(
                    format!(
                        "New TCP proxy from {}:{} => {}:{}\r\n",
                        originator_address, originator_port, host_to_connect, port_to_connect
                    )
                    .into_bytes(),
                );
                match self.auth_data {
                    AuthenticatedData::None { ref proxy_count } => {
                        self.timeout_handle.lock().await.take();
                        proxy_count.fetch_add(1, Ordering::Release);
                        let proxy_count = Arc::clone(proxy_count);
                        let timeout_handle = Arc::clone(&self.timeout_handle);
                        let idle_connection_timeout = self.server.idle_connection_timeout;
                        let cancelation_tx = self.cancelation_tx.clone();
                        let tcp_connection_timeout = self.server.tcp_connection_timeout;
                        tokio::spawn(async move {
                            let mut stream = channel.into_stream();
                            match tcp_connection_timeout {
                                Some(duration) => {
                                    let _ = timeout(duration, async {
                                        copy_bidirectional(&mut stream, &mut io).await
                                    })
                                    .await;
                                }
                                None => {
                                    let _ = copy_bidirectional(&mut stream, &mut io).await;
                                }
                            }
                            if proxy_count.fetch_sub(1, Ordering::AcqRel) == 1 {
                                *timeout_handle.lock().await =
                                    Some(DroppableHandle(tokio::spawn(async move {
                                        sleep(idle_connection_timeout).await;
                                        let _ = cancelation_tx.send(());
                                    })));
                            }
                        });
                    }
                    _ => {
                        let tcp_connection_timeout = self.server.tcp_connection_timeout;
                        tokio::spawn(async move {
                            let mut stream = channel.into_stream();
                            match tcp_connection_timeout {
                                Some(duration) => {
                                    let _ = timeout(duration, async {
                                        copy_bidirectional(&mut stream, &mut io).await
                                    })
                                    .await;
                                }
                                None => {
                                    let _ = copy_bidirectional(&mut stream, &mut io).await;
                                }
                            }
                        });
                    }
                }
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
        if let AuthenticatedData::None { ref proxy_count } = self.auth_data {
            if proxy_count.load(Ordering::Acquire) == 0 {
                return Err(russh::Error::Disconnect);
            }
        }
        Ok(false)
    }
}

impl Drop for ServerHandler {
    fn drop(&mut self) {
        let user = self.user.as_ref().map(String::as_ref).unwrap_or("unknown");
        info!("{} ({}) disconnected", user, self.peer);
        match self.auth_data {
            AuthenticatedData::User { .. } | AuthenticatedData::Admin { .. } => {
                let server = Arc::clone(&self.server);
                let id = self.id;
                let peer = self.peer;
                tokio::task::spawn_blocking(move || {
                    server.ssh.remove_by_address(&peer);
                    server.http.remove_by_address(&peer);
                    server.tcp.remove_by_address(&peer);
                    server
                        .sessions_password
                        .lock()
                        .unwrap()
                        .retain(|_, session| {
                            session.remove(&id);
                            !session.is_empty()
                        });
                    server
                        .sessions_publickey
                        .lock()
                        .unwrap()
                        .retain(|_, session| {
                            session.remove(&id);
                            !session.is_empty()
                        });
                });
            }
            AuthenticatedData::None { .. } => (),
        }
    }
}
