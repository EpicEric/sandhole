use std::{
    borrow::Borrow,
    collections::{BTreeSet, HashMap},
    fmt::Display,
    mem,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use crate::{
    SandholeServer,
    admin::AdminInterface,
    connection_handler::{ConnectionHandler, ConnectionHttpData},
    connections::ConnectionGetByHttpHost,
    droppable_handle::DroppableHandle,
    error::ServerError,
    fingerprints::AuthenticationType,
    http::proxy_handler,
    ip::{IpFilter, IpFilterConfig},
    login::AuthenticationRequest,
    quota::{TokenHolder, UserIdentification},
    tcp::PortHandler,
    tcp_alias::{BorrowedTcpAlias, TcpAlias, TcpAliasKey},
};

use anyhow::anyhow;
use async_speed_limit::{Limiter, Resource, clock::StandardClock};
use enumflags2::{BitFlags, bitflags};
use http::Request;
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use ipnet::IpNet;
use russh::{
    Channel, ChannelId, ChannelStream, MethodKind, MethodSet,
    keys::{HashAlg, PublicKey, ssh_key::Fingerprint},
    server::{Auth, Handler, Msg, Session},
};
use tokio::{
    io::copy_bidirectional_with_sizes,
    sync::{
        Mutex, RwLock,
        mpsc::{self, UnboundedReceiver, UnboundedSender},
    },
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

type FingerprintFn = dyn Fn(Option<&Fingerprint>) -> bool + Send + Sync;

// Struct for generating tunneling/aliasing channels from an underlying SSH connection,
// via remote forwarding. It also includes a log channel to communicate messages
// (such as HTTP logs) back to the SSH connection.
#[derive(Clone)]
pub(crate) struct SshTunnelHandler {
    // Closure to verify valid fingerprints for local forwardings. Default is to allow all.
    allow_fingerprint: Arc<RwLock<Box<FingerprintFn>>>,
    // Optional extra data available for HTTP tunneling/aliasing connections.
    http_data: Option<Arc<RwLock<ConnectionHttpData>>>,
    // Optional IP filtering for this handler's tunneling and aliasing channels.
    ip_filter: Arc<RwLock<Option<IpFilter>>>,
    // Handle to the SSH connection, in order to create remote forwarding channels.
    handle: russh::server::Handle,
    // Sender to the opened data session for logging.
    tx: ServerHandlerSender,
    // IP and port of the SSH connection, for logging.
    peer: SocketAddr,
    // Address used for the remote forwarding, required for the client to open the correct session channels.
    address: String,
    // Port used for the remote forwarding, required for the client to open the correct session channels.
    port: u32,
    // Limiter for rate limiting.
    limiter: Limiter,
}

impl Drop for SshTunnelHandler {
    fn drop(&mut self) {
        // Notify user of their handler being dropped, i.e. when using LoadBalancing::Replace.
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

impl ConnectionHandler<Resource<ChannelStream<Msg>, StandardClock>> for SshTunnelHandler {
    fn log_channel(&self) -> ServerHandlerSender {
        self.tx.clone()
    }

    async fn tunneling_channel(
        &self,
        ip: IpAddr,
        port: u16,
    ) -> anyhow::Result<Resource<ChannelStream<Msg>, StandardClock>> {
        // Check if this IP is not blocked
        if self
            .ip_filter
            .read()
            .await
            .as_ref()
            .is_none_or(|filter| filter.is_allowed(ip))
        {
            let channel = self
                .handle
                .channel_open_forwarded_tcpip(
                    self.address.clone(),
                    self.port,
                    ip.to_string(),
                    port.into(),
                )
                .await?
                .into_stream();
            Ok(self.limiter.clone().limit(channel))
        } else {
            Err(ServerError::TunnelingNotAllowed.into())
        }
    }

    async fn can_alias(
        &self,
        ip: IpAddr,
        _port: u16,
        fingerprint: Option<&'_ Fingerprint>,
    ) -> bool {
        // Check if this IP is not blocked for the alias
        self.ip_filter
            .read()
            .await
            .as_ref()
            .is_none_or(|filter| filter.is_allowed(ip))
            // Check if the given fingerprint is allowed to local-forward this alias
            && (self.allow_fingerprint.read().await)(fingerprint)
    }

    async fn aliasing_channel(
        &self,
        ip: IpAddr,
        port: u16,
        fingerprint: Option<&'_ Fingerprint>,
    ) -> anyhow::Result<Resource<ChannelStream<Msg>, StandardClock>> {
        if self.can_alias(ip, port, fingerprint).await {
            let channel = self
                .handle
                .channel_open_forwarded_tcpip(
                    self.address.clone(),
                    self.port,
                    ip.to_string(),
                    port.into(),
                )
                .await?
                .into_stream();
            Ok(self.limiter.clone().limit(channel))
        } else {
            Err(ServerError::AliasingNotAllowed.into())
        }
    }

    async fn http_data(&self) -> Option<ConnectionHttpData> {
        Some(self.http_data.as_ref()?.read().await.clone())
    }
}

// Data shared by user and admin SSH sessions,
struct UserData {
    // Closure to verify valid fingerprints for local forwardings. Default is to allow all.
    allow_fingerprint: Arc<RwLock<Box<FingerprintFn>>>,
    // Extra data available for HTTP tunneling/aliasing connections.
    http_data: Arc<RwLock<ConnectionHttpData>>,
    // Optional IP filtering for this connection's tunneling and aliasing channels.
    ip_filter: Arc<RwLock<Option<IpFilter>>>,
    // Whether this session only has aliases, from the `tcp-alias`` or `allowed-fingerprints` options.
    tcp_alias_only: bool,
    // Whether this session only has SNI proxies, from the `sni-proxy` option.
    sni_proxy_only: bool,
    // Identifier for the user, used for creating quota tokens.
    quota_key: TokenHolder,
    // Map to keep track of opened host-based connections (HTTP and SSH), to clean up when the forwarding is canceled.
    host_addressing: HashMap<TcpAlias, String>,
    // Map to keep track of opened port-based connections (TCP), to clean up when the forwarding is canceled.
    port_addressing: HashMap<TcpAlias, u16>,
    // Map to keep track of opened alias-based connections (aliases), to clean up when the forwarding is canceled.
    alias_addressing: HashMap<TcpAlias, TcpAlias>,
    // IPs allowed to connect to this user's services.
    allowlist: Option<Vec<IpNet>>,
    // IPs disallowed from connecting to this user's services.
    blocklist: Option<Vec<IpNet>>,
    // Rate limiter for this user's services.
    limiter: Limiter,
}

impl UserData {
    fn new(quota_key: TokenHolder, limiter: Limiter) -> Self {
        Self {
            allow_fingerprint: Arc::new(RwLock::new(Box::new(|_| true))),
            http_data: Arc::new(RwLock::new(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
                http2: false,
            })),
            ip_filter: Arc::new(RwLock::new(None)),
            tcp_alias_only: false,
            sni_proxy_only: false,
            quota_key,
            host_addressing: Default::default(),
            port_addressing: Default::default(),
            alias_addressing: Default::default(),
            allowlist: Default::default(),
            blocklist: Default::default(),
            limiter,
        }
    }
}

// Data exclusive to the admin SSH session.
struct AdminData {
    // Flag indicating whether this session has any forwardings associated with it.
    // Used to prevent forwardings and the admin interface from being used together in a single session.
    is_forwarding: bool,
    // An allocated pseudo-terminal with the admin TUI.
    admin_interface: Option<AdminInterface>,
    // Width (in columns) of the user's pseudo-terminal.
    col_width: Option<u32>,
    // Height (in rows) of the user's pseudo-terminal.
    row_height: Option<u32>,
}

impl AdminData {
    fn new() -> Self {
        Self {
            is_forwarding: false,
            admin_interface: None,
            col_width: Default::default(),
            row_height: Default::default(),
        }
    }
}

// Possible authentication states and data.
enum AuthenticatedData {
    // User is not authenticated; only allowed to local forward connections.
    None {
        proxy_count: Arc<AtomicUsize>,
    },
    // User is authenticated, and allowed to remote forward connections.
    User {
        user_data: Box<UserData>,
    },
    // User is authenticated, and allowed to remote forward connections or access the admin TUI.
    Admin {
        user_data: Box<UserData>,
        admin_data: Box<AdminData>,
    },
}

impl Display for AuthenticatedData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthenticatedData::None { .. } => f.write_str("NONE"),
            AuthenticatedData::User { .. } => f.write_str("USER"),
            AuthenticatedData::Admin { .. } => f.write_str("ADMIN"),
        }
    }
}

#[bitflags]
#[repr(u16)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum ExecCommand {
    Admin,
    AllowedFingerprints,
    TcpAlias,
    ForceHttps,
    Http2,
    SniProxy,
    IpAllowlist,
    IpBlocklist,
}

#[derive(Debug, Clone)]
pub(crate) struct ServerHandlerSender(pub(crate) UnboundedSender<Vec<u8>>);

impl ServerHandlerSender {
    pub(crate) fn send(&self, message: Vec<u8>) -> Result<(), std::io::Error> {
        self.0
            .send(message)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::BrokenPipe, error))
    }
}

// Shared data for each SSH connection.
pub(crate) struct ServerHandler {
    // The unique ID of this connection.
    id: usize,
    // A handle to a task that disconnects unauthed users after a while.
    timeout_handle: Arc<Mutex<Option<DroppableHandle<()>>>>,
    // The IP and port of this connection.
    peer: SocketAddr,
    // The username from this connection's authentication (always present).
    user: Option<String>,
    // The fingerprint of the public key from authentication (may be missing).
    key_fingerprint: Option<Fingerprint>,
    // Channel to communicate that this connection must be closed.
    cancellation_token: CancellationToken,
    // User-specific data, set after authentication.
    auth_data: AuthenticatedData,
    // ID for the open session channel.
    channel_id: Option<ChannelId>,
    // Sender for data session messages, used for sending logs and TUI state to the client.
    tx: ServerHandlerSender,
    rx: Option<UnboundedReceiver<Vec<u8>>>,
    // Handle for the opened data session task. Initially None.
    open_session_join_handle: Option<DroppableHandle<()>>,
    // Reference to the Sandhole data, for accessing configuration and services.
    server: Arc<SandholeServer>,
    // Commands running on the open session channel.
    commands: BitFlags<ExecCommand>,
}

pub(crate) trait Server {
    fn new_client(
        &mut self,
        peer_address: SocketAddr,
        cancellation_token: CancellationToken,
    ) -> ServerHandler;
}

impl Server for Arc<SandholeServer> {
    // Create a new handler for the SSH connection.
    fn new_client(
        &mut self,
        peer_address: SocketAddr,
        cancellation_token: CancellationToken,
    ) -> ServerHandler {
        let id = self.session_id.fetch_add(1, Ordering::AcqRel);
        info!(peer = %peer_address, "SSH client connected.");
        let (tx, rx) = mpsc::unbounded_channel();
        ServerHandler {
            id,
            timeout_handle: Arc::new(Mutex::new(None)),
            peer: peer_address,
            user: None,
            key_fingerprint: None,
            cancellation_token,
            auth_data: AuthenticatedData::None {
                proxy_count: Arc::new(AtomicUsize::new(0)),
            },
            commands: Default::default(),
            channel_id: None,
            tx: ServerHandlerSender(tx),
            rx: Some(rx),
            open_session_join_handle: None,
            server: Arc::clone(self),
        }
    }
}

impl Handler for ServerHandler {
    type Error = russh::Error;

    // Handle creation of a channel for sending logs or TUI updates to the client.
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // Only the first session will receive data. Others are rejected.
        let Some(mut rx) = self.rx.take() else {
            if matches!(self.auth_data, AuthenticatedData::None { .. }) {
                return Err(russh::Error::Disconnect);
            }
            return Ok(false);
        };
        self.channel_id = Some(channel.id());
        let graceful_cancellation_token = CancellationToken::new();
        let graceful_shutdown_rx = graceful_cancellation_token.clone();
        let cancellation_token =
            mem::replace(&mut self.cancellation_token, graceful_cancellation_token);
        let join_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = graceful_shutdown_rx.cancelled() => {
                        // Flush the remaining messages
                        while let Ok(message) = rx.try_recv() {
                            if channel.data(message.as_ref()).await.is_err() {
                                break;
                            }
                        }
                        if channel.eof().await.is_ok() {
                            let _ = channel.close().await;
                        }
                        // Close the connection after a small wait
                        sleep(Duration::from_millis(100)).await;
                        cancellation_token.cancel();
                        break;
                    }
                    message = rx.recv() => {
                        let Some(message) = message else { break };
                        if channel.data(message.as_ref()).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        self.open_session_join_handle = Some(DroppableHandle(join_handle));
        Ok(true)
    }

    // Return the default authentication method.
    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::from([MethodKind::PublicKey].as_slice())),
            partial_success: false,
        })
    }

    // Authenticate users with a password if the API login service is available.
    #[tracing::instrument(skip(self), fields(peer = %self.peer), level = "debug")]
    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        // Check if the API login service has been initialized.
        if let Some(ref api_login) = self.server.api_login {
            // Send an auth request with a timeout.
            match timeout(self.server.authentication_request_timeout, async {
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
                Ok(Ok(is_authenticated)) => {
                    // Check if authentication succeeded.
                    if is_authenticated {
                        // Add this session to the password sessions, allowing it to be canceled via the admin TUI.
                        let limiter = {
                            let mut user_sessions = self.server.sessions_password.lock().unwrap();
                            let entry = user_sessions.entry(user.into()).or_insert((
                                Limiter::new(self.server.rate_limit),
                                HashMap::default(),
                            ));
                            entry.1.insert(self.id, self.cancellation_token.clone());
                            entry.0.clone()
                        };
                        self.user = Some(user.into());
                        // Add user data, identifying its tokens by the username.
                        self.auth_data = AuthenticatedData::User {
                            user_data: Box::new(UserData::new(
                                TokenHolder::User(UserIdentification::Username(user.into())),
                                limiter,
                            )),
                        };
                        info!(
                            peer = %self.peer, %user, role = %self.auth_data, "SSH client authenticated with password.",
                        );
                        return Ok(Auth::Accept);
                    } else {
                        warn!(peer = %self.peer, %user, "Failed password authentication.");
                    }
                }
                Ok(Err(error)) => {
                    error!(peer = %self.peer, %user, %error, "SSH authentication error.");
                }
                _ => {
                    warn!(peer = %self.peer, "Authentication request timed out.");
                }
            }
        }
        Ok(Auth::Reject {
            proceed_with_methods: None,
            partial_success: false,
        })
    }

    // Receive an authentication request and handle it by validating the fingerprint,
    // marking the session as unauthenticated if unknown to potentially clean up if unproxied.
    #[tracing::instrument(skip(self), fields(peer = %self.peer), level = "debug")]
    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        let fingerprint = public_key.fingerprint(HashAlg::Sha256);
        self.user = Some(user.into());
        self.key_fingerprint = Some(fingerprint);
        // Check if the fingerprint is known.
        let authentication = self
            .server
            .fingerprints_validator
            .authenticate_fingerprint(&fingerprint);
        match authentication {
            // If key is unknown, allow connecting for the purposes of local forwarding.
            AuthenticationType::None => {
                if self.server.disable_aliasing {
                    return Ok(Auth::Reject {
                        proceed_with_methods: None,
                        partial_success: false,
                    });
                } else {
                    // Start timer for user to do local port forwarding.
                    // Otherwise, the connection will be canceled upon expiration
                    let cancellation_token = self.cancellation_token.clone();
                    let timeout = self.server.idle_connection_timeout;
                    *self.timeout_handle.lock().await =
                        Some(DroppableHandle(tokio::spawn(async move {
                            sleep(timeout).await;
                            cancellation_token.cancel();
                        })));
                }
            }
            AuthenticationType::User => {
                // Add this session to the public key sessions, allowing it to be canceled via the admin TUI.
                let limiter = {
                    let mut user_sessions = self.server.sessions_publickey.lock().unwrap();
                    let entry = user_sessions
                        .entry(fingerprint)
                        .or_insert((Limiter::new(self.server.rate_limit), HashMap::default()));
                    entry.1.insert(self.id, self.cancellation_token.clone());
                    entry.0.clone()
                };
                // Add user data, identifying its tokens by the public key.
                self.auth_data = AuthenticatedData::User {
                    user_data: Box::new(UserData::new(
                        TokenHolder::User(UserIdentification::PublicKey(fingerprint)),
                        limiter,
                    )),
                };
            }
            AuthenticationType::Admin => {
                // Add admin data, identifying its tokens by the public key.
                let limiter = Limiter::new(f64::INFINITY);
                self.auth_data = AuthenticatedData::Admin {
                    user_data: Box::new(UserData::new(
                        TokenHolder::Admin(UserIdentification::PublicKey(fingerprint)),
                        limiter,
                    )),
                    admin_data: Box::new(AdminData::new()),
                };
            }
        }
        info!(
            peer = %self.peer, %user, fingerprint = %fingerprint, role = %self.auth_data, "SSH client authenticated with public key."
        );
        Ok(Auth::Accept)
    }

    // Handle data received from the client such as key presses.
    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self
            .channel_id
            .is_some_and(|channel_id| channel_id == channel)
        {
            debug!(peer = %self.peer, ?data, "Received channel data.");
            match &mut self.auth_data {
                // Ignore other commands for non-admin users
                AuthenticatedData::None { .. } | AuthenticatedData::User { .. } => (),
                AuthenticatedData::Admin { admin_data, .. } => {
                    // Handle the proper key press in the admin TUI.
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
                            // Ctrl+C
                            b"\x03" => admin_interface.disable(),
                            _ => (),
                        }
                    }
                }
            }
            // Ctrl+C (0x03) ends the session and disconnects the client
            if data == b"\x03" {
                self.cancellation_token.cancel();
            }
        }
        Ok(())
    }

    // Receive and handle any additional commands from the client where appropriate.
    #[tracing::instrument(skip(self), fields(peer = %self.peer), level = "debug")]
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!(peer = %self.peer, ?data, "Received exec_request data.");
        let mut success = true;
        let cmd = String::from_utf8_lossy(data);
        // Split commands by whitespace and handle each.
        'parse: for command in cmd.split_whitespace() {
            match (command, &mut self.auth_data) {
                // - `admin` command creates an admin interface if the user is an admin
                ("admin", AuthenticatedData::Admin { admin_data, .. }) => {
                    if self.commands.contains(ExecCommand::Admin) {
                        let _ = self
                            .tx
                            .send(b"Invalid option \"admin\": duplicated command\r\n".to_vec());
                        success = false;
                        break;
                    }
                    if admin_data.is_forwarding {
                        let _ = self.tx.send(
                            b"Invalid option \"admin\": cannot open admin interface while forwarding\r\n"
                                .to_vec(),
                        );
                        success = false;
                        self.cancellation_token.cancel();
                        break;
                    }
                    let tx = self.tx.clone();
                    let mut admin_interface = AdminInterface::new(tx, Arc::clone(&self.server));
                    // Resize if we already have data about the PTY
                    if let (Some(col_width), Some(row_height)) =
                        (admin_data.col_width, admin_data.row_height)
                    {
                        let _ = admin_interface.resize(col_width as u16, row_height as u16);
                    }
                    admin_data.admin_interface = Some(admin_interface);
                    self.commands.insert(ExecCommand::Admin);
                }
                // - `allowed-fingerprints` sets this connection as alias-only,
                //   and requires local forwardings to have one of the specified key fingerprints.
                (
                    command,
                    AuthenticatedData::User { user_data, .. }
                    | AuthenticatedData::Admin { user_data, .. },
                ) if command.starts_with("allowed-fingerprints=") => {
                    if self.server.disable_aliasing {
                        let _ = self.tx.send(
                            b"Invalid option \"allowed-fingerprints\": aliasing is disabled\r\n"
                                .to_vec(),
                        );
                        success = false;
                        break;
                    }
                    if user_data.sni_proxy_only {
                        let _ = self.tx.send(
                            b"Invalid option \"allowed-fingerprints\": not compatible with SNI proxy\r\n".to_vec(),
                        );
                        success = false;
                        break;
                    }
                    if self.commands.contains(ExecCommand::AllowedFingerprints) {
                        let _ = self.tx.send(
                            b"Invalid option \"allowed-fingerprints\": duplicated command\r\n"
                                .to_vec(),
                        );
                        success = false;
                        break;
                    }
                    user_data.tcp_alias_only = true;
                    user_data.http_data.write().await.is_aliasing = true;
                    // Create a set from the provided list of fingerprints
                    let set: Result<BTreeSet<Fingerprint>, _> = command
                        .trim_start_matches("allowed-fingerprints=")
                        .split(',')
                        .filter(|a| !a.is_empty())
                        .map(|key| key.parse::<Fingerprint>())
                        .collect();
                    let set = match set {
                        Ok(set) => set,
                        Err(error) => {
                            let _ = self.tx.send(
                                format!("Error parsing fingerprints: {error}\r\n").into_bytes(),
                            );
                            success = false;
                            break;
                        }
                    };
                    if set.is_empty() {
                        let _ = self.tx.send(b"No fingerprints provided\r\n".to_vec());
                        success = false;
                        break;
                    }
                    // Create a validation closure that verifies that the fingerprint is in our new set
                    *user_data.allow_fingerprint.write().await =
                        Box::new(move |fingerprint| fingerprint.is_some_and(|fp| set.contains(fp)));
                    // Reject TCP ports
                    if !self.server.tcp.remove_by_address(&self.peer).is_empty() {
                        let _ = self
                            .tx
                            .send(b"Cannot convert TCP port(s) into aliases\r\n".to_vec());
                        success = false;
                        self.cancellation_token.cancel();
                        break;
                    }
                    // Change any existing HTTP handlers into TCP alias handlers.
                    let handlers = self.server.http.remove_by_address(&self.peer);
                    for (_, handler) in handlers.into_iter() {
                        let address = handler.address.clone();
                        // Ensure that the forwarding address is an alias, otherwise error.
                        if !self.server.is_alias(&address) {
                            let _ = self.tx.send(
                                format!(
                                    "Cannot listen to HTTP alias of '{address}' (must be alias, not localhost)\r\n"
                                )
                                .into_bytes(),
                            );
                            success = false;
                            self.cancellation_token.cancel();
                            break 'parse;
                        }
                        // Insert our handler into the TCP alias connections map.
                        if let Err(error) = self.server.alias.insert(
                            TcpAlias(address.clone(), 80),
                            self.peer,
                            user_data.quota_key.clone(),
                            handler,
                        ) {
                            info!(
                                peer = %self.peer, alias = %address, %error,
                                "Failed to bind HTTP alias.",
                            );
                            let _ = self.tx.send(
                                format!(
                                    "Cannot listen to HTTP alias of '{}' ({})\r\n",
                                    &address, error,
                                )
                                .into_bytes(),
                            );
                            success = false;
                            self.cancellation_token.cancel();
                            break 'parse;
                        }
                    }
                    self.commands.insert(ExecCommand::AllowedFingerprints);
                }
                // - `tcp-alias` sets this connection as alias-only.
                (
                    "tcp-alias",
                    AuthenticatedData::User { user_data, .. }
                    | AuthenticatedData::Admin { user_data, .. },
                ) => {
                    if self.server.disable_aliasing {
                        let _ = self.tx.send(
                            b"Invalid option \"tcp-alias\": aliasing is disabled\r\n".to_vec(),
                        );
                        success = false;
                        break;
                    }
                    if user_data.sni_proxy_only {
                        let _ = self.tx.send(
                            b"Invalid option \"tcp-alias\": not compatible with SNI proxy\r\n"
                                .to_vec(),
                        );
                        success = false;
                        break;
                    }
                    if self.commands.contains(ExecCommand::TcpAlias) {
                        let _ = self
                            .tx
                            .send(b"Invalid option \"tcp-alias\": duplicated command\r\n".to_vec());
                        success = false;
                        break;
                    }
                    user_data.tcp_alias_only = true;
                    user_data.http_data.write().await.is_aliasing = true;
                    // Reject TCP ports
                    if !self.server.tcp.remove_by_address(&self.peer).is_empty() {
                        let _ = self
                            .tx
                            .send(b"Cannot convert TCP port(s) into aliases\r\n".to_vec());
                        success = false;
                        self.cancellation_token.cancel();
                        break;
                    }
                    // Change any existing HTTP handlers into TCP alias handlers.
                    let handlers = self.server.http.remove_by_address(&self.peer);
                    for (_, handler) in handlers.into_iter() {
                        let address = handler.address.clone();
                        // Ensure that the forwarding address is an alias, otherwise error.
                        if !self.server.is_alias(&address) {
                            let _ = self.tx.send(
                                format!(
                                    "Cannot listen to HTTP alias of '{address}' (must be alias, not localhost)\r\n"
                                )
                                .into_bytes(),
                            );
                            success = false;
                            self.cancellation_token.cancel();
                            break 'parse;
                        }
                        // Insert our handler into the TCP alias connections map.
                        if let Err(error) = self.server.alias.insert(
                            TcpAlias(address.clone(), 80),
                            self.peer,
                            user_data.quota_key.clone(),
                            handler,
                        ) {
                            info!(
                                peer = %self.peer, alias = %address, %error,
                                "Failed to bind HTTP alias.",
                            );
                            let _ = self.tx.send(
                                format!(
                                    "Cannot listen to HTTP alias of '{}' ({})\r\n",
                                    &address, error,
                                )
                                .into_bytes(),
                            );
                            success = false;
                            self.cancellation_token.cancel();
                            break 'parse;
                        }
                    }
                    self.commands.insert(ExecCommand::TcpAlias);
                }
                // - `force-https` causes tunneled HTTP requests to be redirected to HTTPS.
                (
                    "force-https",
                    AuthenticatedData::User { user_data, .. }
                    | AuthenticatedData::Admin { user_data, .. },
                ) => {
                    if self.commands.contains(ExecCommand::ForceHttps) {
                        let _ = self.tx.send(
                            b"Invalid option \"force-https\": duplicated command\r\n".to_vec(),
                        );
                        success = false;
                        break;
                    }
                    user_data
                        .http_data
                        .write()
                        .await
                        .redirect_http_to_https_port = Some(self.server.https_port);
                    self.commands.insert(ExecCommand::ForceHttps);
                }
                // - `http2` allows serving HTTP/2 to the HTTP endpoints.
                (
                    "http2",
                    AuthenticatedData::User { user_data, .. }
                    | AuthenticatedData::Admin { user_data, .. },
                ) => {
                    if self.commands.contains(ExecCommand::Http2) {
                        let _ = self
                            .tx
                            .send(b"Invalid option \"http2\": duplicated command\r\n".to_vec());
                        success = false;
                        break;
                    }
                    user_data.http_data.write().await.http2 = true;
                    self.commands.insert(ExecCommand::Http2);
                }
                // - `sni-proxy` allows the user to handle the certificates themselves for HTTPS traffic.
                (
                    "sni-proxy",
                    AuthenticatedData::User { user_data, .. }
                    | AuthenticatedData::Admin { user_data, .. },
                ) => {
                    if self.server.disable_sni || self.server.disable_http {
                        let _ = self.tx.send(
                            b"Invalid option \"sni-proxy\": SNI proxying is disabled\r\n".to_vec(),
                        );
                        success = false;
                        break;
                    }
                    if user_data.tcp_alias_only {
                        let _ = self.tx.send(
                            b"Invalid option \"sni-proxy\": not compatible with TCP aliasing\r\n"
                                .to_vec(),
                        );
                        success = false;
                        break;
                    }
                    if self.commands.contains(ExecCommand::SniProxy) {
                        let _ = self
                            .tx
                            .send(b"Invalid option \"sni-proxy\": duplicated command\r\n".to_vec());
                        success = false;
                        break;
                    }
                    user_data.sni_proxy_only = true;
                    // Change any existing HTTP handlers into SNI proxy handlers.
                    let handlers = self.server.http.remove_by_address(&self.peer);
                    for (_, handler) in handlers.into_iter() {
                        let address = handler.address.clone();
                        // Ensure that the SNI address is an alias, otherwise error.
                        if !self.server.is_alias(&address) {
                            let _ = self.tx.send(
                                format!(
                                    "Cannot listen to SNI proxy of '{address}' (must be alias, not localhost)\r\n"
                                )
                                .into_bytes(),
                            );
                            success = false;
                            self.cancellation_token.cancel();
                            break 'parse;
                        }
                        // Insert our handler into the SNI proxy connections map.
                        if let Err(error) = self.server.sni.insert(
                            address.clone(),
                            self.peer,
                            user_data.quota_key.clone(),
                            handler,
                        ) {
                            info!(
                                peer = %self.peer, host = %address, %error,
                                "Failed to bind SNI proxy.",
                            );
                            let _ = self.tx.send(
                                format!(
                                    "Cannot listen to SNI proxy of '{}' ({})\r\n",
                                    &address, error,
                                )
                                .into_bytes(),
                            );
                            success = false;
                            self.cancellation_token.cancel();
                            break 'parse;
                        }
                    }
                    self.commands.insert(ExecCommand::SniProxy);
                }
                // - `ip-allowlist` requires tunneling/aliasing connections to come from
                //   specific IP ranges.
                (
                    command,
                    AuthenticatedData::User { user_data, .. }
                    | AuthenticatedData::Admin { user_data, .. },
                ) if command.starts_with("ip-allowlist=") => {
                    if self.commands.contains(ExecCommand::IpAllowlist)
                        || user_data.allowlist.is_some()
                    {
                        let _ = self.tx.send(
                            b"Invalid option \"ip-allowlist\": duplicated command\r\n".to_vec(),
                        );
                        success = false;
                        break;
                    }
                    let list: Result<Vec<IpNet>, _> = command
                        .trim_start_matches("ip-allowlist=")
                        .split(',')
                        .filter(|a| !a.is_empty())
                        .map(|network| network.parse::<IpNet>())
                        .collect();
                    let list = match list {
                        Ok(list) => list,
                        Err(error) => {
                            let _ = self.tx.send(
                                format!("Error parsing allowlist networks: {error}\r\n")
                                    .into_bytes(),
                            );
                            success = false;
                            break;
                        }
                    };
                    if list.is_empty() {
                        let _ = self.tx.send(b"No allowlist networks provided\r\n".to_vec());
                        success = false;
                        break;
                    }
                    user_data.allowlist = Some(list);
                    self.commands.insert(ExecCommand::IpAllowlist);
                }
                // - `ip-blocklist` requires tunneling/aliasing connections to come from
                //   specific IP ranges.
                (
                    command,
                    AuthenticatedData::User { user_data, .. }
                    | AuthenticatedData::Admin { user_data, .. },
                ) if command.starts_with("ip-blocklist=") => {
                    if self.commands.contains(ExecCommand::IpBlocklist)
                        || user_data.blocklist.is_some()
                    {
                        let _ = self.tx.send(
                            b"Invalid option \"ip-blocklist\": duplicated command\r\n".to_vec(),
                        );
                        success = false;
                        break;
                    }
                    let list: Result<Vec<IpNet>, _> = command
                        .trim_start_matches("ip-blocklist=")
                        .split(',')
                        .filter(|a| !a.is_empty())
                        .map(|network| network.parse::<IpNet>())
                        .collect();
                    let list = match list {
                        Ok(list) => list,
                        Err(error) => {
                            let _ = self.tx.send(
                                format!("Error parsing blocklist networks: {error}\r\n")
                                    .into_bytes(),
                            );
                            success = false;
                            break;
                        }
                    };
                    if list.is_empty() {
                        let _ = self.tx.send(b"No blocklist networks provided\r\n".to_vec());
                        success = false;
                        break;
                    }
                    user_data.blocklist = Some(list);
                    self.commands.insert(ExecCommand::IpBlocklist);
                }
                // - Unknown command
                (command, _) => {
                    debug!(
                        peer = %self.peer, %command, role = %self.auth_data, "Invalid SSH command received."
                    );
                    let _ = self
                        .tx
                        .send(format!("Error: invalid command {command}...").into_bytes());
                    success = false;
                    break;
                }
            }
        }
        let user_data = match self.auth_data {
            AuthenticatedData::User {
                ref mut user_data, ..
            }
            | AuthenticatedData::Admin {
                ref mut user_data, ..
            } => Some(user_data),
            _ => None,
        };
        let allowlist = user_data.as_ref().map(|data| &data.allowlist);
        let blocklist = user_data.as_ref().map(|data| &data.blocklist);
        if success && (allowlist.is_some() || blocklist.is_some()) {
            let allowlist = allowlist.unwrap().clone();
            let blocklist = blocklist.unwrap().clone();
            match &mut self.auth_data {
                AuthenticatedData::User { user_data, .. }
                | AuthenticatedData::Admin { user_data, .. } => {
                    match IpFilter::from(IpFilterConfig {
                        allowlist,
                        blocklist,
                    }) {
                        Ok(ip_filter) => {
                            *user_data.ip_filter.write().await = Some(ip_filter);
                        }
                        Err(error) => {
                            let _ = self.tx.send(
                                format!("Failed to create IP filter for connection ({error})\r\n")
                                    .into_bytes(),
                            );
                            success = false;
                        }
                    }
                }
                _ => (),
            }
        }
        if success {
            session.channel_success(channel)
        } else {
            session.channel_failure(channel)
        }
    }

    // Set up data for the pseudo-terminal in order to properly use the TUI.
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
        debug!(peer = %self.peer, "Received pty_request.");
        match &mut self.auth_data {
            AuthenticatedData::Admin { admin_data, .. } => {
                // Change the size of the pseudo-terminal.
                admin_data.col_width = Some(col_width);
                admin_data.row_height = Some(row_height);
                session.channel_success(channel)
            }
            AuthenticatedData::User { .. } | AuthenticatedData::None { .. } => {
                session.channel_failure(channel)
            }
        }
    }

    // Handle changes to the client's window size.
    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let AuthenticatedData::Admin {
            ref mut admin_data, ..
        } = self.auth_data
        {
            // Change the size of the pseudo-terminal.
            admin_data.col_width = Some(col_width);
            admin_data.row_height = Some(row_height);
            // Dynamically update the TUI if present.
            if let Some(ref mut admin_interface) = admin_data.admin_interface {
                if let Err(error) = admin_interface.resize(col_width as u16, row_height as u16) {
                    warn!(peer = %self.peer, %error, "Failed to resize terminal.");
                } else {
                    return session.channel_success(channel);
                }
            }
        }

        session.channel_failure(channel)
    }

    // Handle a remote forwarding request for the client.
    #[tracing::instrument(skip(self), fields(peer = %self.peer), level = "debug")]
    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // Reject invalid ports
        if *port > u16::MAX.into() {
            return Err(russh::Error::Disconnect);
        }
        // Only allow remote forwarding for authenticated users that aren't using the admin interface
        let user_data = match &mut self.auth_data {
            AuthenticatedData::Admin {
                admin_data,
                user_data,
            } => {
                if admin_data.admin_interface.is_some() {
                    let _ = self
                        .tx
                        .send(b"Cannot remote forward if admin interface is being used".to_vec());
                    self.cancellation_token.cancel();
                    return Ok(false);
                } else {
                    admin_data.is_forwarding = true;
                    user_data
                }
            }
            AuthenticatedData::User { user_data, .. } => user_data,
            AuthenticatedData::None { .. } => return Err(russh::Error::Disconnect),
        };

        let handle = session.handle();
        match *port {
            // Assign SSH host through config (specified by the usual SSH port)
            22 => {
                if self.server.disable_aliasing {
                    let _ = self.tx.send(b"Error: Aliasing is disabled\r\n".to_vec());
                    return Ok(false);
                }
                // SSH host must be alias (to be accessed via ProxyJump or ProxyCommand)
                if !self.server.is_alias(address) {
                    let error = anyhow!("must be alias, not localhost");
                    info!(
                        peer = %self.peer, alias = %address, %error,
                        "Failed to bind SSH alias.",
                    );
                    let _ = self
                        .tx
                        .send(b"Error: Alias is required for SSH host\r\n".to_vec());
                    return Ok(false);
                }
                // Add handler to SSH connection map
                match self.server.ssh.insert(
                    address.to_string(),
                    self.peer,
                    user_data.quota_key.clone(),
                    Arc::new(SshTunnelHandler {
                        allow_fingerprint: Arc::clone(&user_data.allow_fingerprint),
                        http_data: None,
                        ip_filter: Arc::clone(&user_data.ip_filter),
                        handle,
                        tx: self.tx.clone(),
                        peer: self.peer,
                        address: address.to_string(),
                        port: *port,
                        limiter: user_data.limiter.clone(),
                    }),
                ) {
                    Err(error) => {
                        // Adding to connection map failed.
                        info!(peer = %self.peer, alias = %address, %error, "Rejecting SSH.");
                        let _ = self.tx.send(
                            format!(
                                "Cannot listen to SSH on {}:{} ({})\r\n",
                                address, self.server.ssh_port, error,
                            )
                            .into_bytes(),
                        );
                        Ok(false)
                    }
                    _ => {
                        // Adding to connection map succeeded.
                        info!(peer = %self.peer, alias = %address, "Serving SSH connection...");
                        let _ = self.tx.send(
                            format!(
                                "Serving SSH on {}:{}\r\n\
                                \x1b[2mhint: connect with ssh -J {}{} {}{}\x1b[0m\r\n",
                                address,
                                self.server.ssh_port,
                                self.server.domain,
                                if self.server.ssh_port == 22 {
                                    "".into()
                                } else {
                                    format!(":{}", self.server.ssh_port)
                                },
                                address,
                                if self.server.ssh_port == 22 {
                                    "".into()
                                } else {
                                    format!(" -p {}", self.server.ssh_port)
                                },
                            )
                            .into_bytes(),
                        );
                        user_data.host_addressing.insert(
                            TcpAlias(address.to_string(), *port as u16),
                            address.to_string(),
                        );
                        Ok(true)
                    }
                }
            }
            // Assign HTTP host through config (specified by the usual HTTP/HTTPS ports)
            80 | 443 => {
                // Handle alias-only mode
                if user_data.tcp_alias_only {
                    // HTTP host must be alias (to be accessed via local forwarding)
                    if !self.server.is_alias(address) {
                        let error = anyhow!("must be alias, not localhost");
                        info!(
                            peer = %self.peer, alias = %address, %error,
                            "Failed to bind HTTP alias.",
                        );
                        let _ = self.tx.send(
                            format!("Failed to bind HTTP alias '{address}' ({error})\r\n")
                                .into_bytes(),
                        );
                        return Ok(false);
                    }
                    // Add handler to TCP connection map
                    match self.server.alias.insert(
                        TcpAlias(address.into(), 80),
                        self.peer,
                        user_data.quota_key.clone(),
                        Arc::new(SshTunnelHandler {
                            allow_fingerprint: Arc::clone(&user_data.allow_fingerprint),
                            http_data: Some(Arc::clone(&user_data.http_data)),
                            ip_filter: Arc::clone(&user_data.ip_filter),
                            handle,
                            tx: self.tx.clone(),
                            peer: self.peer,
                            address: address.into(),
                            port: *port,
                            limiter: user_data.limiter.clone(),
                        }),
                    ) {
                        Err(error) => {
                            // Adding to connection map failed.
                            info!(
                                peer = %self.peer, %error, alias = %address,
                                "Rejecting HTTP alias.",
                            );
                            let _ = self.tx.send(
                                format!("Failed to bind HTTP alias {address} ({error})\r\n")
                                    .into_bytes(),
                            );
                            Ok(false)
                        }
                        _ => {
                            // Adding to connection map succeeded.
                            info!(peer = %self.peer, alias = %address, "Tunneling HTTP...");
                            let _ = self.tx.send(
                                format!(
                                    "Tunneling HTTP for alias {}{}\r\n",
                                    address,
                                    match self.server.http_port {
                                        80 => "".into(),
                                        port => format!(":{port}"),
                                    }
                                )
                                .into_bytes(),
                            );
                            user_data
                                .alias_addressing
                                .insert(TcpAlias(address.into(), 80), TcpAlias(address.into(), 80));
                            Ok(true)
                        }
                    }
                // Handle SNI proxy-only mode
                } else if user_data.sni_proxy_only {
                    // Assign an HTTP address according to server policies
                    let assigned_host = self
                        .server
                        .address_delegator
                        .get_http_address(address, &self.user, &self.key_fingerprint, &self.peer)
                        .await;
                    // Add handler to TCP connection map
                    match self.server.sni.insert(
                        assigned_host.clone(),
                        self.peer,
                        user_data.quota_key.clone(),
                        Arc::new(SshTunnelHandler {
                            allow_fingerprint: Arc::clone(&user_data.allow_fingerprint),
                            http_data: Some(Arc::clone(&user_data.http_data)),
                            ip_filter: Arc::clone(&user_data.ip_filter),
                            handle,
                            tx: self.tx.clone(),
                            peer: self.peer,
                            address: address.into(),
                            port: *port,
                            limiter: user_data.limiter.clone(),
                        }),
                    ) {
                        Err(error) => {
                            // Adding to connection map failed.
                            info!(
                                peer = %self.peer, %error, host = %address,
                                "Rejecting SNI proxy.",
                            );
                            let _ = self.tx.send(
                                format!("Failed to bind SNI proxy '{address}' ({error})\r\n")
                                    .into_bytes(),
                            );
                            Ok(false)
                        }
                        _ => {
                            // Adding to connection map succeeded.
                            info!(peer = %self.peer, host = %address, "Serving SNI proxy...",);
                            let _ = self.tx.send(
                                format!(
                                    "Serving SNI proxy for https://{}{}\r\n",
                                    address,
                                    match self.server.https_port {
                                        443 => "".into(),
                                        port => format!(":{port}"),
                                    }
                                )
                                .into_bytes(),
                            );
                            user_data
                                .host_addressing
                                .insert(TcpAlias(address.into(), *port as u16), assigned_host);
                            Ok(true)
                        }
                    }
                // Reject when HTTP is disabled
                } else if self.server.disable_http {
                    let error = anyhow!("HTTP is disabled");
                    info!(
                        peer = %self.peer, host = %address, %error,
                        "Failed to bind HTTP host.",
                    );
                    let _ = self.tx.send(
                        format!("Cannot listen to HTTP host {address} ({error})\r\n",).into_bytes(),
                    );
                    Ok(false)
                // Handle regular tunneling for HTTP services
                } else {
                    // Assign an HTTP address according to server policies
                    let assigned_host = self
                        .server
                        .address_delegator
                        .get_http_address(address, &self.user, &self.key_fingerprint, &self.peer)
                        .await;
                    // Add handler to HTTP connection map
                    match self.server.http.insert(
                        assigned_host.clone(),
                        self.peer,
                        user_data.quota_key.clone(),
                        Arc::new(SshTunnelHandler {
                            allow_fingerprint: Arc::clone(&user_data.allow_fingerprint),
                            http_data: Some(Arc::clone(&user_data.http_data)),
                            ip_filter: Arc::clone(&user_data.ip_filter),
                            handle,
                            tx: self.tx.clone(),
                            peer: self.peer,
                            address: address.to_string(),
                            port: *port,
                            limiter: user_data.limiter.clone(),
                        }),
                    ) {
                        Err(error) => {
                            // Adding to connection map failed.
                            info!(
                                peer = %self.peer, host = %assigned_host, %error,
                                "Rejecting HTTP.",
                            );
                            let _ = self.tx.send(
                                format!(
                                    "Cannot listen to HTTP on http://{}{} for {} ({})\r\n",
                                    &assigned_host,
                                    match self.server.http_port {
                                        80 => "".into(),
                                        port => format!(":{port}"),
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
                            info!(peer = %self.peer, host = %assigned_host, "Serving HTTP...");
                            let _ = self.tx.send(
                                format!(
                                    "Serving HTTP on http://{}{} for {}\r\n",
                                    &assigned_host,
                                    match self.server.http_port {
                                        80 => "".into(),
                                        port => format!(":{port}"),
                                    },
                                    address,
                                )
                                .into_bytes(),
                            );
                            let _ = self.tx.send(
                                format!(
                                    "Serving HTTPS on https://{}{} for {}\r\n",
                                    &assigned_host,
                                    match self.server.https_port {
                                        443 => "".into(),
                                        port => format!(":{port}"),
                                    },
                                    address,
                                )
                                .into_bytes(),
                            );
                            user_data
                                .host_addressing
                                .insert(TcpAlias(address.to_string(), *port as u16), assigned_host);
                            Ok(true)
                        }
                    }
                }
            }
            // Assign TCP port through config (specified by non-trivial ports)
            _ if !self.server.is_alias(address) => {
                // Forbid binding TCP if disabled
                if self.server.disable_tcp {
                    let error = anyhow!("TCP is disabled");
                    info!(
                        peer = %self.peer, %port, %error,
                        "Failed to bind TCP port.",
                    );
                    let _ = self.tx.send(
                        format!(
                            "Cannot listen to TCP on port {}:{port} ({error})\r\n",
                            &self.server.domain,
                        )
                        .into_bytes(),
                    );
                    Ok(false)
                // Forbid binding TCP on alias-only mode
                } else if user_data.tcp_alias_only {
                    let error = anyhow!("session is in alias-only mode");
                    info!(
                        peer = %self.peer, %port, %error,
                        "Failed to bind TCP port.",
                    );
                    let _ = self.tx.send(
                        format!(
                            "Cannot listen to TCP on port {}:{port} ({error})\r\n",
                            &self.server.domain,
                        )
                        .into_bytes(),
                    );
                    Ok(false)
                // Forbid binding low TCP ports
                } else if (1..1024).contains(port) {
                    let error = anyhow!("port too low");
                    info!(
                        peer = %self.peer, %port, %error,
                        "Failed to bind TCP port.",
                    );
                    let _ = self.tx.send(
                        format!(
                            "Cannot listen to TCP on port {}:{port} ({error})\r\n",
                            &self.server.domain,
                        )
                        .into_bytes(),
                    );
                    Ok(false)
                } else {
                    // When port is 0, assign a random one
                    let assigned_port = if *port == 0 {
                        let assigned_port = match self.server.tcp_handler.get_free_port().await {
                            Ok(port) => port,
                            Err(error) => {
                                info!(
                                    peer = %self.peer, alias = %address, %error,
                                    "Failed to bind random TCP port for alias.",
                                );
                                let _ = self.tx.send(
                                    format!(
                                        "Cannot listen to TCP on random port of {address} ({error})\r\n",
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
                    } else if self.server.force_random_ports {
                        match self.server.tcp_handler.get_free_port().await {
                            Ok(port) => port,
                            Err(error) => {
                                info!(
                                    peer = %self.peer, alias = %address, %error,
                                    "Failed to bind random TCP port for alias.",
                                );
                                let _ = self.tx.send(
                                    format!(
                                        "Cannot listen to TCP on random port of {port} ({error})\r\n"
                                    )
                                    .into_bytes(),
                                );
                                return Ok(false);
                            }
                        }
                    // Allow user-requested port when server allows binding on any port
                    } else {
                        *port as u16
                    };
                    // Add handler to TCP connection map
                    match self.server.tcp.insert(
                        assigned_port,
                        self.peer,
                        user_data.quota_key.clone(),
                        Arc::new(SshTunnelHandler {
                            allow_fingerprint: Arc::clone(&user_data.allow_fingerprint),
                            http_data: None,
                            ip_filter: Arc::clone(&user_data.ip_filter),
                            handle,
                            tx: self.tx.clone(),
                            peer: self.peer,
                            address: address.to_string(),
                            port: *port,
                            limiter: user_data.limiter.clone(),
                        }),
                    ) {
                        Err(error) => {
                            // Adding to connection map failed.
                            info!(
                                peer = %self.peer, port = %assigned_port, %error,
                                "Rejecting TCP.",
                            );
                            let _ = self.tx.send(
                                format!(
                                    "Cannot listen to TCP on {}:{} ({})\r\n",
                                    self.server.domain, &assigned_port, error,
                                )
                                .into_bytes(),
                            );
                            Ok(false)
                        }
                        _ => {
                            // Adding to connection map succeeded.
                            user_data
                                .port_addressing
                                .insert(TcpAlias(address.to_string(), *port as u16), assigned_port);
                            info!(
                                peer = %self.peer, port = %assigned_port,
                                "Serving TCP...",
                            );
                            let _ = self.tx.send(
                                format!(
                                    "Serving TCP port on {}:{}\r\n",
                                    self.server.domain, &assigned_port,
                                )
                                .into_bytes(),
                            );
                            Ok(true)
                        }
                    }
                }
            }
            // Assign alias through config (specified by non-trivial address and port)
            _ => {
                if self.server.disable_aliasing {
                    let _ = self.tx.send(b"Error: Aliasing is disabled\r\n".to_vec());
                    return Ok(false);
                }
                // If alias, the user must provide the port number themselves
                let assigned_port = if *port == 0 {
                    let error = anyhow!("cannot assign random port to alias");
                    info!(
                        peer = %self.peer, alias = %address, %error,
                        "Failed to bind random TCP port for alias.",
                    );
                    let _ = self.tx.send(
                        format!(
                            "Cannot listen to TCP on random port of {address} ({error})\r\n\
                            Please specify the desired port.\r\n",
                        )
                        .into_bytes(),
                    );
                    return Ok(false);
                // Allow user-requested port
                } else {
                    *port as u16
                };
                // Add handler to alias connection map
                match self.server.alias.insert(
                    TcpAlias(address.to_string(), assigned_port),
                    self.peer,
                    user_data.quota_key.clone(),
                    Arc::new(SshTunnelHandler {
                        allow_fingerprint: Arc::clone(&user_data.allow_fingerprint),
                        http_data: None,
                        ip_filter: Arc::clone(&user_data.ip_filter),
                        handle,
                        tx: self.tx.clone(),
                        peer: self.peer,
                        address: address.to_string(),
                        port: *port,
                        limiter: user_data.limiter.clone(),
                    }),
                ) {
                    Err(error) => {
                        // Adding to connection map failed.
                        info!(
                            peer = %self.peer, alias = %address, port = %assigned_port, %error,
                            "Rejecting TCP port for alias.",
                        );
                        let _ = self.tx.send(
                            format!(
                                "Cannot listen to TCP on port {} for alias {} ({})\r\n",
                                &assigned_port, address, error,
                            )
                            .into_bytes(),
                        );
                        Ok(false)
                    }
                    _ => {
                        // Adding to connection map succeeded.
                        user_data.alias_addressing.insert(
                            TcpAlias(address.to_string(), *port as u16),
                            TcpAlias(address.to_string(), assigned_port),
                        );
                        info!(
                            peer = %self.peer, alias = %address, port = %assigned_port,
                            "Tunneling TCP port for alias...",
                        );
                        let _ = self.tx.send(
                            format!(
                                "Tunneling TCP port {} for alias {}\r\n",
                                &assigned_port, address,
                            )
                            .into_bytes(),
                        );
                        Ok(true)
                    }
                }
            }
        }
    }

    // Handle closure of a remote forwarding request.
    #[tracing::instrument(skip(self), fields(peer = %self.peer), level = "debug")]
    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // Reject invalid ports
        if port > u16::MAX.into() {
            return Err(russh::Error::Disconnect);
        }
        let user_data = match &mut self.auth_data {
            AuthenticatedData::User { user_data, .. }
            | AuthenticatedData::Admin { user_data, .. } => user_data,
            AuthenticatedData::None { .. } => return Err(russh::Error::Disconnect),
        };
        match port {
            // Handle SSH disconnection
            22 => {
                if let Some(assigned_host) =
                    user_data
                        .host_addressing
                        .remove(&BorrowedTcpAlias(address, &(port as u16)) as &dyn TcpAliasKey)
                {
                    info!(
                        peer = %self.peer, alias = &assigned_host,
                        "Stopped SSH forwarding.",
                    );
                    self.server.ssh.remove(&assigned_host, &self.peer);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            // Handle HTTP disconnection
            80 | 443 => {
                if user_data.tcp_alias_only {
                    // Handle TCP alias-only mode
                    if let Some(assigned_alias) = user_data
                        .alias_addressing
                        .remove(&BorrowedTcpAlias(address, &80) as &dyn TcpAliasKey)
                    {
                        info!(
                            peer = %self.peer, alias = %assigned_alias.0, port = %assigned_alias.1,
                            "Stopped TCP aliasing.",
                        );
                        let key: &dyn TcpAliasKey = assigned_alias.borrow();
                        self.server.alias.remove(key, &self.peer);
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                } else if user_data.sni_proxy_only {
                    // Handle TCP alias-only mode
                    if let Some(assigned_alias) = user_data
                        .host_addressing
                        .remove(&BorrowedTcpAlias(address, &(port as u16)) as &dyn TcpAliasKey)
                    {
                        info!(
                            peer = %self.peer, host = %assigned_alias,
                            "Stopped SNI proxying.",
                        );
                        self.server.sni.remove(&assigned_alias, &self.peer);
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                } else {
                    // Handle regular tunneling for HTTP services
                    if let Some(assigned_host) = user_data
                        .host_addressing
                        .remove(&BorrowedTcpAlias(address, &(port as u16)) as &dyn TcpAliasKey)
                    {
                        info!(
                            peer = %self.peer, host = %assigned_host,
                            "Stopped HTTP forwarding.",
                        );
                        self.server.http.remove(&assigned_host, &self.peer);
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                }
            }
            // Handle TCP disconnection
            _ if !self.server.is_alias(address) => {
                if let Some(assigned_port) =
                    user_data
                        .port_addressing
                        .remove(&BorrowedTcpAlias(address, &(port as u16)) as &dyn TcpAliasKey)
                {
                    info!(
                        peer = %self.peer, port = %port,
                        "Stopped TCP forwarding.",
                    );
                    self.server.tcp.remove(&assigned_port, &self.peer);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            // Handle alias disconnection
            _ => {
                if let Some(assigned_alias) =
                    user_data
                        .alias_addressing
                        .remove(&BorrowedTcpAlias(address, &(port as u16)) as &dyn TcpAliasKey)
                {
                    info!(
                        peer = %self.peer, alias = %assigned_alias.0, port = %assigned_alias.1,
                        "Stopped TCP aliasing.",
                    );
                    let key: &dyn TcpAliasKey = assigned_alias.borrow();
                    self.server.alias.remove(key, &self.peer);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }

    // Handle a local forwarding request (i.e. proxy tunnel for aliases).
    #[tracing::instrument(skip(self), fields(peer = %self.peer), level = "debug")]
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // Reject invalid ports
        if port_to_connect > u16::MAX.into() || originator_port > u16::MAX.into() {
            return Err(russh::Error::Disconnect);
        }
        let port_to_connect = port_to_connect as u16;
        // Only allow local forwarding if aliasing is enabled
        if self.server.disable_aliasing {
            let _ = self.tx.send(b"Error: Aliasing is disabled\r\n".to_vec());
            return Ok(false);
        }
        if let AuthenticatedData::Admin { admin_data, .. } = &mut self.auth_data {
            if admin_data.admin_interface.is_some() {
                let _ = self
                    .tx
                    .send(b"Cannot local forward if admin interface is being used".to_vec());
                self.cancellation_token.cancel();
                return Ok(false);
            } else {
                admin_data.is_forwarding = true;
            }
        }
        // Handle local forwarding for SSH
        if port_to_connect == self.server.ssh_port {
            if let Some(handler) = self.server.ssh.get(host_to_connect) {
                if let Ok(mut io) = handler
                    .aliasing_channel(
                        self.peer.ip(),
                        self.peer.port(),
                        self.key_fingerprint.as_ref(),
                    )
                    .await
                {
                    self.server
                        .telemetry
                        .add_ssh_connection(host_to_connect.into());
                    let _ = handler.log_channel().send(
                        format!(
                            "New SSH proxy from {originator_address}:{originator_port} => {host_to_connect}:{port_to_connect}\r\n"
                        )
                        .into_bytes(),
                    );
                    match self.auth_data {
                        // Serve SSH for unauthed user, then add disconnection timeout if this is the last proxy connection
                        AuthenticatedData::None { ref proxy_count } => {
                            self.timeout_handle.lock().await.take();
                            proxy_count.fetch_add(1, Ordering::Release);
                            let proxy_count = Arc::clone(proxy_count);
                            let timeout_handle = Arc::clone(&self.timeout_handle);
                            let unproxied_connection_timeout =
                                self.server.unproxied_connection_timeout;
                            let cancellation_token = self.cancellation_token.clone();
                            let tcp_connection_timeout = self.server.tcp_connection_timeout;
                            let buffer_size = self.server.buffer_size;
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
                                if proxy_count.fetch_sub(1, Ordering::AcqRel) == 1 {
                                    *timeout_handle.lock().await =
                                        Some(DroppableHandle(tokio::spawn(async move {
                                            sleep(unproxied_connection_timeout).await;
                                            cancellation_token.cancel();
                                        })));
                                }
                            });
                        }
                        // Serve SSH normally for authed user
                        _ => {
                            let tcp_connection_timeout = self.server.tcp_connection_timeout;
                            let buffer_size = self.server.buffer_size;
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
                            });
                        }
                    }
                    info!(
                        peer = %self.peer, remote = %handler.peer, alias = %host_to_connect,
                        "Accepted SSH connection.",
                    );
                    let _ = self
                        .tx
                        .send(format!("Forwarding SSH from {host_to_connect}\r\n").into_bytes());
                    return Ok(true);
                }
            }
            let _ = self
                .tx
                .send(format!("Unknown SSH alias '{host_to_connect}'\r\n").into_bytes());
        // Handle local forwarding for HTTP
        } else if port_to_connect == self.server.http_port
            || port_to_connect == self.server.https_port
        {
            if let Some(tunnel_handler) = self.server.sni.get(host_to_connect) {
                let mut stream = channel.into_stream();
                if let Ok(mut channel) = tunnel_handler
                    .tunneling_channel(self.peer.ip(), self.peer.port())
                    .await
                {
                    self.server
                        .telemetry
                        .add_sni_connection(host_to_connect.into());
                    let tcp_connection_timeout = self.server.tcp_connection_timeout;
                    let buffer_size = self.server.buffer_size;
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
                    });
                    return Ok(true);
                };
            } else if let Some(handler) = self
                .server
                .aliasing_proxy_data
                .conn_manager()
                .get_by_http_host(host_to_connect)
            {
                if handler
                    .can_alias(
                        self.peer.ip(),
                        self.peer.port(),
                        self.key_fingerprint.as_ref(),
                    )
                    .await
                {
                    let peer = self.peer;
                    let fingerprint = self.key_fingerprint;
                    let proxy_data = Arc::clone(&self.server.aliasing_proxy_data);
                    let host_to_connect = host_to_connect.to_string();
                    let service = service_fn(move |mut req: Request<Incoming>| {
                        // Set HTTP host via header
                        req.headers_mut()
                            .insert("host", host_to_connect.clone().try_into().unwrap());
                        proxy_handler(req, peer, fingerprint, Arc::clone(&proxy_data))
                    });
                    let io = TokioIo::new(channel.into_stream());
                    let tcp_connection_timeout = self.server.tcp_connection_timeout;
                    match self.auth_data {
                        // Serve HTTP for unauthed user, then add disconnection timeout if this is the last proxy connection
                        AuthenticatedData::None { ref proxy_count } => {
                            self.timeout_handle.lock().await.take();
                            proxy_count.fetch_add(1, Ordering::Release);
                            let proxy_count = Arc::clone(proxy_count);
                            let timeout_handle = Arc::clone(&self.timeout_handle);
                            let unproxied_connection_timeout =
                                self.server.unproxied_connection_timeout;
                            let cancellation_token = self.cancellation_token.clone();
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
                                if proxy_count.fetch_sub(1, Ordering::AcqRel) == 1 {
                                    *timeout_handle.lock().await =
                                        Some(DroppableHandle(tokio::spawn(async move {
                                            sleep(unproxied_connection_timeout).await;
                                            cancellation_token.cancel();
                                        })));
                                }
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
            }
            let _ = self
                .tx
                .send(format!("Unknown HTTP alias '{host_to_connect}'\r\n").into_bytes());
        // Handle local forwarding for TCP
        } else if !self.server.is_alias(host_to_connect) {
            if let Some(handler) = self.server.tcp.get(&port_to_connect) {
                if let Ok(mut io) = handler
                    .aliasing_channel(
                        self.peer.ip(),
                        self.peer.port(),
                        self.key_fingerprint.as_ref(),
                    )
                    .await
                {
                    self.server.telemetry.add_tcp_connection(port_to_connect);
                    let _ = handler.log_channel().send(
                        format!(
                            "New TCP proxy from {originator_address}:{originator_port} => {host_to_connect}:{port_to_connect}\r\n"
                        )
                        .into_bytes(),
                    );
                    match self.auth_data {
                        // Serve TCP for unauthed user, then add disconnection timeout if this is the last proxy connection
                        AuthenticatedData::None { ref proxy_count } => {
                            self.timeout_handle.lock().await.take();
                            proxy_count.fetch_add(1, Ordering::Release);
                            let proxy_count = Arc::clone(proxy_count);
                            let timeout_handle = Arc::clone(&self.timeout_handle);
                            let unproxied_connection_timeout =
                                self.server.unproxied_connection_timeout;
                            let cancellation_token = self.cancellation_token.clone();
                            let tcp_connection_timeout = self.server.tcp_connection_timeout;
                            let buffer_size = self.server.buffer_size;
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
                                if proxy_count.fetch_sub(1, Ordering::AcqRel) == 1 {
                                    *timeout_handle.lock().await =
                                        Some(DroppableHandle(tokio::spawn(async move {
                                            sleep(unproxied_connection_timeout).await;
                                            cancellation_token.cancel();
                                        })));
                                }
                            });
                        }
                        // Serve TCP normally for authed user
                        _ => {
                            let tcp_connection_timeout = self.server.tcp_connection_timeout;
                            let buffer_size = self.server.buffer_size;
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
                            });
                        }
                    }
                    info!(
                        peer = %self.peer, remote = %handler.peer, port = %port_to_connect,
                        "Accepted TCP connection.",
                    );
                    let _ = self
                        .tx
                        .send(format!("Forwarding TCP from {host_to_connect}\r\n").into_bytes());
                    return Ok(true);
                }
            }
            let _ = self
                .tx
                .send(format!("Unknown TCP port '{port_to_connect}'\r\n").into_bytes());
        // Handle local forwarding for alias
        } else {
            if let Some(handler) = self
                .server
                .alias
                .get(&BorrowedTcpAlias(host_to_connect, &port_to_connect) as &dyn TcpAliasKey)
            {
                if let Ok(mut io) = handler
                    .aliasing_channel(
                        self.peer.ip(),
                        self.peer.port(),
                        self.key_fingerprint.as_ref(),
                    )
                    .await
                {
                    self.server
                        .telemetry
                        .add_alias_connection(TcpAlias(host_to_connect.into(), port_to_connect));
                    let _ = handler.log_channel().send(
                        format!(
                            "New TCP proxy from {originator_address}:{originator_port} => {host_to_connect}:{port_to_connect}\r\n"
                        )
                        .into_bytes(),
                    );
                    match self.auth_data {
                        // Serve TCP for unauthed user, then add disconnection timeout if this is the last proxy connection
                        AuthenticatedData::None { ref proxy_count } => {
                            self.timeout_handle.lock().await.take();
                            proxy_count.fetch_add(1, Ordering::Release);
                            let proxy_count = Arc::clone(proxy_count);
                            let timeout_handle = Arc::clone(&self.timeout_handle);
                            let unproxied_connection_timeout =
                                self.server.unproxied_connection_timeout;
                            let cancellation_token = self.cancellation_token.clone();
                            let tcp_connection_timeout = self.server.tcp_connection_timeout;
                            let buffer_size = self.server.buffer_size;
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
                                if proxy_count.fetch_sub(1, Ordering::AcqRel) == 1 {
                                    *timeout_handle.lock().await =
                                        Some(DroppableHandle(tokio::spawn(async move {
                                            sleep(unproxied_connection_timeout).await;
                                            cancellation_token.cancel();
                                        })));
                                }
                            });
                        }
                        // Serve TCP normally for authed user
                        _ => {
                            let tcp_connection_timeout = self.server.tcp_connection_timeout;
                            let buffer_size = self.server.buffer_size;
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
                            });
                        }
                    }
                    info!(
                        peer = %self.peer, remote = %handler.peer, alias = %host_to_connect, port = %port_to_connect,
                        "Accepted alias connection.",
                    );
                    let _ = self
                        .tx
                        .send(format!("Forwarding TCP from {host_to_connect}\r\n").into_bytes());
                    return Ok(true);
                }
            }
            let _ = self.tx.send(
                format!("Unknown alias '{host_to_connect}:{port_to_connect}'\r\n").into_bytes(),
            );
        }
        if let AuthenticatedData::None { ref proxy_count } = self.auth_data {
            if proxy_count.load(Ordering::Acquire) == 0 {
                return Err(russh::Error::Disconnect);
            }
        }
        Ok(false)
    }
}

// Clean up session data on drop (i.e. disconnected from server)
impl Drop for ServerHandler {
    fn drop(&mut self) {
        let user = self.user.as_ref().map(String::as_ref).unwrap_or("unknown");
        info!(peer = %self.peer, %user, "SSH client disconnected.");
        match self.auth_data {
            AuthenticatedData::User { .. } | AuthenticatedData::Admin { .. } => {
                let server = Arc::clone(&self.server);
                let id = self.id;
                let peer = self.peer;
                tokio::task::spawn_blocking(move || {
                    // Remove all proxy connections from this session
                    server.http.remove_by_address(&peer);
                    server.sni.remove_by_address(&peer);
                    server.ssh.remove_by_address(&peer);
                    server.tcp.remove_by_address(&peer);
                    server.alias.remove_by_address(&peer);
                    // Remove any references to this session
                    server
                        .sessions_password
                        .lock()
                        .unwrap()
                        .retain(|_, (_, session)| {
                            session.remove(&id);
                            !session.is_empty()
                        });
                    server
                        .sessions_publickey
                        .lock()
                        .unwrap()
                        .retain(|_, (_, session)| {
                            session.remove(&id);
                            !session.is_empty()
                        });
                });
            }
            AuthenticatedData::None { .. } => (),
        }
    }
}
