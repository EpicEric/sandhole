use std::{
    borrow::Borrow,
    collections::{BTreeSet, HashMap, HashSet},
    fmt::Display,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use crate::{
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
    SandholeServer,
};

use http::Request;
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use ipnet::IpNet;
use log::{debug, info, warn};
use russh::{
    keys::{ssh_key::Fingerprint, HashAlg, PublicKey},
    server::{Auth, Handler, Msg, Session},
    Channel, ChannelId, ChannelStream, MethodKind, MethodSet,
};
use tokio::{
    io::{copy_bidirectional, AsyncWriteExt},
    sync::{mpsc, Mutex, RwLock},
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;

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
    // Sender to the opened data session, if any, for logging.
    tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    // IP and port of the SSH connection, for logging.
    peer: SocketAddr,
    // Address used for the remote forwarding, required for the client to open the correct session channels.
    address: String,
    // Port used for the remote forwarding, required for the client to open the correct session channels.
    port: u32,
}

impl Drop for SshTunnelHandler {
    fn drop(&mut self) {
        // Notify user of their handler being dropped, i.e. when using LoadBalancing::Replace.
        self.tx.as_ref().inspect(|tx| {
            let _ = tx.send(
                format!(
                    "\x1b[1;33mWARNING:\x1b[0m The handler for {}:{} has been dropped. \
                No new connections will be accepted.\r\n",
                    self.address, self.port
                )
                .into_bytes(),
            );
        });
    }
}

impl ConnectionHandler<ChannelStream<Msg>> for SshTunnelHandler {
    fn log_channel(&self) -> Option<mpsc::UnboundedSender<Vec<u8>>> {
        self.tx.clone()
    }

    async fn tunneling_channel(&self, ip: IpAddr, port: u16) -> anyhow::Result<ChannelStream<Msg>> {
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
            Ok(channel)
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
    ) -> anyhow::Result<ChannelStream<Msg>> {
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
            Ok(channel)
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
    // Whether this session only has aliases, from the `tcp-alias`` or `allowed-fingerprints`` option(s).
    tcp_alias_only: bool,
    // Identifier for the user, used for creating quota tokens.
    quota_key: TokenHolder,
    // Map to keep track of opened host-based connections (HTTP and SSH), to clean up when the forwarding is canceled.
    host_addressing: HashMap<TcpAlias, String>,
    // Map to keep track of opened port-based connections (TCP), to clean up when the forwarding is canceled.
    port_addressing: HashMap<TcpAlias, u16>,
    // Map to keep track of opened alias-based connections (aliases), to clean up when the forwarding is canceled.
    alias_addressing: HashMap<TcpAlias, TcpAlias>,
}

impl UserData {
    fn new(quota_key: TokenHolder) -> Self {
        Self {
            allow_fingerprint: Arc::new(RwLock::new(Box::new(|_| true))),
            http_data: Arc::new(RwLock::new(ConnectionHttpData {
                redirect_http_to_https_port: None,
                is_aliasing: false,
            })),
            ip_filter: Arc::new(RwLock::new(None)),
            tcp_alias_only: false,
            quota_key,
            host_addressing: Default::default(),
            port_addressing: Default::default(),
            alias_addressing: Default::default(),
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
            AuthenticatedData::None { .. } => f.write_str("no authentication"),
            AuthenticatedData::User { .. } => f.write_str("user authentication"),
            AuthenticatedData::Admin { .. } => f.write_str("admin authentication"),
        }
    }
}

struct OptionalSender(Option<mpsc::UnboundedSender<Vec<u8>>>);

impl OptionalSender {
    fn send(&self, data: Vec<u8>) {
        let _ = self.0.as_ref().map(|tx| tx.send(data));
    }

    fn is_some(&self) -> bool {
        self.0.is_some()
    }

    fn clone_inner(&self) -> Option<mpsc::UnboundedSender<Vec<u8>>> {
        self.0.clone()
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
    // Sender for data session messages, used for sending logs and TUI state to the client.
    tx: OptionalSender,
    // Handle for the opened data session task. Initially None.
    open_session_join_handle: Option<DroppableHandle<()>>,
    // Reference to the Sandhole data, for accessing configuration and services.
    server: Arc<SandholeServer>,
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
        info!("{} connected", peer_address);
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
            tx: OptionalSender(None),
            open_session_join_handle: None,
            server: Arc::clone(self),
        }
    }
}

impl Handler for ServerHandler {
    type Error = russh::Error;

    // Handle creation of a channel for sending and receiving logs or TUI updates to the client.
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // Only the first session will receive data. Others are rejected.
        if self.tx.is_some() {
            if matches!(self.auth_data, AuthenticatedData::None { .. }) {
                return Err(russh::Error::Disconnect);
            }
            return Ok(false);
        };
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut stream = channel.into_stream();
        let join_handle = tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                if stream.write_all(&message).await.is_err() {
                    break;
                }
            }
        });
        self.tx = OptionalSender(Some(tx));
        self.open_session_join_handle = Some(DroppableHandle(join_handle));
        Ok(true)
    }

    // Return the default authentication method.
    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::from([MethodKind::PublicKey].as_slice())),
        })
    }

    // Authenticate users with a password if the API login service is available.
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
                Ok(is_authenticated) => {
                    // Check if authentication succeeded.
                    if is_authenticated {
                        // Add this session to the password sessions, allowing it to be canceled via the admin TUI.
                        self.server
                            .sessions_password
                            .lock()
                            .unwrap()
                            .entry(user.into())
                            .or_default()
                            .insert(self.id, self.cancellation_token.clone());
                        self.user = Some(user.into());
                        // Add user data, identifying its tokens by the username.
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
                }
                _ => {
                    warn!("Authentication request timed out");
                }
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
                self.server
                    .sessions_publickey
                    .lock()
                    .unwrap()
                    .entry(fingerprint)
                    .or_default()
                    .insert(self.id, self.cancellation_token.clone());
                // Add user data, identifying its tokens by the public key.
                self.auth_data = AuthenticatedData::User {
                    user_data: Box::new(UserData::new(TokenHolder::User(
                        UserIdentification::PublicKey(fingerprint),
                    ))),
                };
            }
            AuthenticationType::Admin => {
                // Add admin data, identifying its tokens by the public key.
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
        // Ctrl+C (0x03) ends the session and disconnects the client
        if data == b"\x03" {
            self.cancellation_token.cancel();
            return Ok(());
        }
        debug!("received data {:?}", data);
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
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!("exec_request data {:?}", data);
        let mut success = true;
        let cmd = String::from_utf8_lossy(data);
        // Split commands by whitespace and handle each.
        let mut commands = HashSet::<String>::new();
        let mut allowlist = None;
        let mut blocklist = None;
        for command in cmd.split_whitespace() {
            match (command, &mut self.auth_data) {
                // - `admin` command creates an admin interface if the user is an admin
                ("admin", AuthenticatedData::Admin { admin_data, .. }) => {
                    if commands.contains("admin") {
                        self.tx
                            .send(b"Invalid option \"admin\": duplicated command\r\n".to_vec());
                        success = false;
                        break;
                    }
                    commands.insert("admin".into());
                    if admin_data.is_forwarding {
                        self.tx.send(
                            b"Invalid option \"admin\": cannot open admin interface while forwarding\r\n"
                                .to_vec(),
                        );
                        success = false;
                        break;
                    }
                    let Some(tx) = self.tx.clone_inner() else {
                        unreachable!();
                    };
                    let mut admin_interface = AdminInterface::new(tx, Arc::clone(&self.server));
                    // Resize if we already have data about the PTY
                    if let (Some(col_width), Some(row_height)) =
                        (admin_data.col_width, admin_data.row_height)
                    {
                        let _ = admin_interface.resize(col_width as u16, row_height as u16);
                    }
                    admin_data.admin_interface = Some(admin_interface);
                }
                // - `allowed-fingerprints` sets this connection as alias-only,
                //   and requires local forwardings to have one of the specified key fingerprints.
                (
                    command,
                    AuthenticatedData::User { user_data, .. }
                    | AuthenticatedData::Admin { user_data, .. },
                ) if command.starts_with("allowed-fingerprints=") => {
                    if self.server.disable_aliasing {
                        self.tx.send(
                            b"Invalid option \"allowed-fingerprints\": aliasing is disabled\r\n"
                                .to_vec(),
                        );
                        success = false;
                        break;
                    }
                    if commands.contains("allowed-fingerprints") {
                        self.tx.send(
                            b"Invalid option \"allowed-fingerprints\": duplicated command\r\n"
                                .to_vec(),
                        );
                        success = false;
                        break;
                    }
                    commands.insert("allowed-fingerprints".into());
                    user_data.tcp_alias_only = true;
                    user_data.http_data.write().await.is_aliasing = true;
                    // Create a set from the provided list of fingerprints
                    let set: BTreeSet<Fingerprint> = command
                        .trim_start_matches("allowed-fingerprints=")
                        .split(',')
                        .filter_map(|key| match key.parse::<Fingerprint>() {
                            Ok(fingerprint) => Some(fingerprint),
                            Err(err) => {
                                self.tx.send(
                                    format!(
                                        "Failed to parse fingerprint {}, ignoring ({})\r\n",
                                        key, err
                                    )
                                    .into_bytes(),
                                );
                                None
                            }
                        })
                        .collect();
                    // Create a validation closure that verifies that the fingerprint is in our new set
                    *user_data.allow_fingerprint.write().await =
                        Box::new(move |fingerprint| fingerprint.is_some_and(|fp| set.contains(fp)));
                    // Reject TCP ports
                    if !self.server.tcp.remove_by_address(&self.peer).is_empty() {
                        self.tx
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
                            self.tx.send(
                                format!(
                                    "Cannot listen to HTTP alias of {} (must be alias, not localhost)\r\n",
                                    address
                                )
                                .into_bytes(),
                            );
                            success = false;
                            self.cancellation_token.cancel();
                            break;
                        }
                        // Insert our handler into the TCP alias connections map.
                        if let Err(err) = self.server.alias.insert(
                            TcpAlias(address.clone(), 80),
                            self.peer,
                            user_data.quota_key.clone(),
                            handler,
                        ) {
                            info!(
                                "Failed to bind HTTP alias {} ({}) - {}",
                                &address, self.peer, err,
                            );
                            self.tx.send(
                                format!(
                                    "Cannot listen to HTTP alias of {} ({})\r\n",
                                    &address, err,
                                )
                                .into_bytes(),
                            );
                            success = false;
                            self.cancellation_token.cancel();
                            break;
                        }
                    }
                }
                // - `tcp-alias` sets this connection as alias-only.
                (
                    "tcp-alias",
                    AuthenticatedData::User { user_data, .. }
                    | AuthenticatedData::Admin { user_data, .. },
                ) => {
                    if self.server.disable_aliasing {
                        self.tx.send(
                            b"Invalid option \"tcp-alias\": aliasing is disabled\r\n".to_vec(),
                        );
                        success = false;
                        break;
                    }
                    if commands.contains("tcp-alias") {
                        self.tx
                            .send(b"Invalid option \"tcp-alias\": duplicated command\r\n".to_vec());
                        success = false;
                        break;
                    }
                    commands.insert("tcp-alias".into());
                    user_data.tcp_alias_only = true;
                    user_data.http_data.write().await.is_aliasing = true;
                    // Reject TCP ports
                    if !self.server.tcp.remove_by_address(&self.peer).is_empty() {
                        self.tx
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
                            self.tx.send(
                                format!(
                                    "Cannot listen to HTTP alias of {} (must be alias, not localhost)\r\n",
                                    address
                                )
                                .into_bytes(),
                            );
                            success = false;
                            self.cancellation_token.cancel();
                            break;
                        }
                        // Insert our handler into the TCP alias connections map.
                        if let Err(err) = self.server.alias.insert(
                            TcpAlias(address.clone(), 80),
                            self.peer,
                            user_data.quota_key.clone(),
                            handler,
                        ) {
                            info!(
                                "Failed to bind HTTP alias {} ({}) - {}",
                                &address, self.peer, err,
                            );
                            self.tx.send(
                                format!(
                                    "Cannot listen to HTTP alias of {} ({})\r\n",
                                    &address, err,
                                )
                                .into_bytes(),
                            );
                            success = false;
                            self.cancellation_token.cancel();
                            break;
                        }
                    }
                }
                // - `force-https` causes tunneled HTTP requests to be redirected to HTTPS.
                (
                    "force-https",
                    AuthenticatedData::User { user_data, .. }
                    | AuthenticatedData::Admin { user_data, .. },
                ) => {
                    if commands.contains("force-https") {
                        self.tx.send(
                            b"Invalid option \"force-https\": duplicated command\r\n".to_vec(),
                        );
                        success = false;
                        break;
                    }
                    commands.insert("force-https".into());
                    user_data
                        .http_data
                        .write()
                        .await
                        .redirect_http_to_https_port = Some(self.server.https_port);
                }
                // - `ip-allowlist` requires tunneling/aliasing connections to come from
                //   specific IP ranges.
                (command, AuthenticatedData::User { .. } | AuthenticatedData::Admin { .. })
                    if command.starts_with("ip-allowlist=") =>
                {
                    if commands.contains("ip-allowlist") {
                        self.tx.send(
                            b"Invalid option \"ip-allowlist\": duplicated command\r\n".to_vec(),
                        );
                        success = false;
                        break;
                    }
                    commands.insert("ip-allowlist".into());
                    allowlist = Some(
                        command
                            .trim_start_matches("ip-allowlist=")
                            .split(',')
                            .filter_map(|network| match network.parse::<IpNet>() {
                                Ok(ip_net) => Some(ip_net),
                                Err(err) => {
                                    self.tx.send(
                                        format!(
                                            "Failed to parse IP network {}, ignoring ({})\r\n",
                                            network, err
                                        )
                                        .into_bytes(),
                                    );
                                    None
                                }
                            })
                            .collect(),
                    );
                }
                // - `ip-blocklist` requires tunneling/aliasing connections to come from
                //   specific IP ranges.
                (command, AuthenticatedData::User { .. } | AuthenticatedData::Admin { .. })
                    if command.starts_with("ip-blocklist=") =>
                {
                    if commands.contains("ip-blocklist") {
                        self.tx.send(
                            b"Invalid option \"ip-blocklist\": duplicated command\r\n".to_vec(),
                        );
                        success = false;
                        break;
                    }
                    commands.insert("ip-blocklist".into());
                    blocklist = Some(
                        command
                            .trim_start_matches("ip-blocklist=")
                            .split(',')
                            .filter_map(|network| match network.parse::<IpNet>() {
                                Ok(ip_net) => Some(ip_net),
                                Err(err) => {
                                    self.tx.send(
                                        format!(
                                            "Failed to parse IP network {}, ignoring ({})\r\n",
                                            network, err
                                        )
                                        .into_bytes(),
                                    );
                                    None
                                }
                            })
                            .collect(),
                    );
                }
                // - Unknown command
                (command, _) => {
                    debug!(
                        "Invalid command {} received for {} ({})",
                        command, self.auth_data, self.peer
                    );
                    self.tx
                        .send(format!("Ignoring unknown command {}...", command).into_bytes());
                    success = false;
                }
            }
        }
        if success && (allowlist.is_some() || blocklist.is_some()) {
            match &mut self.auth_data {
                AuthenticatedData::User { user_data, .. }
                | AuthenticatedData::Admin { user_data, .. } => {
                    match IpFilter::new(IpFilterConfig {
                        allowlist,
                        blocklist,
                    }) {
                        Ok(ip_filter) => {
                            let mut guard = user_data.ip_filter.write().await;
                            if guard.is_none() {
                                *guard = Some(ip_filter);
                            } else {
                                self.tx.send(
                                    b"Failed to create IP filter for connection (already created)\r\n"
                                        .to_vec(),
                                );
                                success = false;
                            }
                        }
                        Err(err) => {
                            self.tx.send(
                                format!("Failed to create IP filter for connection ({})\r\n", err)
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
        debug!("pty_request");
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
                if admin_interface
                    .resize(col_width as u16, row_height as u16)
                    .is_ok()
                {
                    return session.channel_success(channel);
                } else {
                    warn!("Failed to resize terminal for {}", self.peer);
                }
            }
        }

        session.channel_failure(channel)
    }

    // Handle a remote forwarding request for the client.
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
                    self.tx
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
                    self.tx.send(b"Error: Aliasing is disabled\r\n".to_vec());
                    return Ok(false);
                }
                // SSH host must be alias (to be accessed via ProxyJump or ProxyCommand)
                if !self.server.is_alias(address) {
                    info!(
                        "Failed to bind SSH for {}: must be alias, not localhost",
                        self.peer
                    );
                    self.tx
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
                        tx: self.tx.clone_inner(),
                        peer: self.peer,
                        address: address.to_string(),
                        port: *port,
                    }),
                ) {
                    Err(err) => {
                        // Adding to connection map failed.
                        info!("Rejecting SSH for {} ({}) - {}", address, self.peer, err);
                        self.tx.send(
                            format!(
                                "Cannot listen to SSH on {}:{} ({})\r\n",
                                address, self.server.ssh_port, err,
                            )
                            .into_bytes(),
                        );
                        Ok(false)
                    }
                    _ => {
                        // Adding to connection map succeeded.
                        info!("Serving SSH for {} ({})", address, self.peer);
                        self.tx.send(
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
                        self.tx.send(
                            format!(
                                "Failed to bind HTTP alias {} (must be alias, not localhost)\r\n",
                                address
                            )
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
                            tx: self.tx.clone_inner(),
                            peer: self.peer,
                            address: address.into(),
                            port: *port,
                        }),
                    ) {
                        Err(err) => {
                            // Adding to connection map failed.
                            info!(
                                "Rejecting HTTP alias for {} ({}) - {}",
                                address, self.peer, err
                            );
                            self.tx.send(
                                format!("Failed to bind HTTP alias {} ({})\r\n", address, err)
                                    .into_bytes(),
                            );
                            Ok(false)
                        }
                        _ => {
                            // Adding to connection map succeeded.
                            info!("Tunneling HTTP for {} ({})", address, self.peer);
                            self.tx.send(
                                format!(
                                    "Tunneling HTTP for alias {}{}\r\n",
                                    address,
                                    match self.server.http_port {
                                        80 => "".into(),
                                        port => format!(":{}", port),
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
                // Reject when HTTP is disabled
                } else if self.server.disable_http {
                    info!(
                        "Failed to bind HTTP host {} ({}): HTTP is disabled",
                        address, self.peer
                    );
                    self.tx.send(
                        format!(
                            "Cannot listen to HTTP host {} (HTTP is disabled)\r\n",
                            address,
                        )
                        .into_bytes(),
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
                            tx: self.tx.clone_inner(),
                            peer: self.peer,
                            address: address.to_string(),
                            port: *port,
                        }),
                    ) {
                        Err(err) => {
                            // Adding to connection map failed.
                            info!(
                                "Rejecting HTTP for {} ({}) - {}",
                                &assigned_host, self.peer, err
                            );
                            self.tx.send(
                                format!(
                                    "Cannot listen to HTTP on http://{}{} for {} ({})\r\n",
                                    &assigned_host,
                                    match self.server.http_port {
                                        80 => "".into(),
                                        port => format!(":{}", port),
                                    },
                                    address,
                                    err,
                                )
                                .into_bytes(),
                            );
                            Ok(false)
                        }
                        _ => {
                            // Adding to connection map succeeded.
                            info!("Serving HTTP for {} ({})", &assigned_host, self.peer);
                            self.tx.send(
                                format!(
                                    "Serving HTTP on http://{}{} for {}\r\n",
                                    &assigned_host,
                                    match self.server.http_port {
                                        80 => "".into(),
                                        port => format!(":{}", port),
                                    },
                                    address,
                                )
                                .into_bytes(),
                            );
                            self.tx.send(
                                format!(
                                    "Serving HTTPS on https://{}{} for {}\r\n",
                                    &assigned_host,
                                    match self.server.https_port {
                                        443 => "".into(),
                                        port => format!(":{}", port),
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
                    info!(
                        "Failed to bind TCP port {} ({}): TCP is disabled",
                        port, self.peer
                    );
                    self.tx.send(
                        format!(
                            "Cannot listen to TCP on port {}:{} (TCP is disabled)\r\n",
                            &self.server.domain, port,
                        )
                        .into_bytes(),
                    );
                    Ok(false)
                // Forbid binding TCP on alias-only mode
                } else if user_data.tcp_alias_only {
                    info!(
                        "Failed to bind TCP port {} ({}): session is in alias-only mode",
                        port, self.peer
                    );
                    self.tx
                    .send(format!("Cannot listen to TCP on port {}:{} (session is in alias-only mode)\r\n", &self.server.domain, port,).into_bytes());
                    Ok(false)
                // Forbid binding low TCP ports
                } else if (1..1024).contains(port) {
                    info!(
                        "Failed to bind TCP port {} ({}): port too low",
                        port, self.peer
                    );
                    self.tx.send(
                        format!(
                            "Cannot listen to TCP on port {}:{} (port too low)\r\n",
                            &self.server.domain, port,
                        )
                        .into_bytes(),
                    );
                    Ok(false)
                } else {
                    // When port is 0, assign a random one
                    let assigned_port = if *port == 0 {
                        let assigned_port = match self.server.tcp_handler.get_free_port().await {
                            Ok(port) => port,
                            Err(err) => {
                                info!(
                                    "Failed to bind random TCP port for alias {} ({}) - {}",
                                    address, self.peer, err,
                                );
                                self.tx.send(
                                    format!(
                                        "Cannot listen to TCP on random port of {} ({})\r\n",
                                        address, err,
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
                            Err(err) => {
                                info!(
                                    "Failed to bind random TCP port for alias {} ({}) - {}",
                                    address, self.peer, err,
                                );
                                self.tx.send(
                                    format!(
                                        "Cannot listen to TCP on random port of {} ({})\r\n",
                                        port, err
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
                            tx: self.tx.clone_inner(),
                            peer: self.peer,
                            address: address.to_string(),
                            port: *port,
                        }),
                    ) {
                        Err(err) => {
                            // Adding to connection map failed.
                            info!(
                                "Rejecting TCP for localhost:{} ({}) - {}",
                                &assigned_port, self.peer, err,
                            );
                            self.tx.send(
                                format!(
                                    "Cannot listen to TCP on {}:{} ({})\r\n",
                                    self.server.domain, &assigned_port, err,
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
                                "Serving TCP for localhost:{} ({})",
                                &assigned_port, self.peer
                            );
                            self.tx.send(
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
                    self.tx.send(b"Error: Aliasing is disabled\r\n".to_vec());
                    return Ok(false);
                }
                // If alias, the user must provide the port number themselves
                let assigned_port = if *port == 0 {
                    info!(
                        "Failed to bind random TCP port for alias {} ({}) - cannot assign random port to alias",
                        address, self.peer,
                    );
                    self.tx.send(
                        format!(
                            "Cannot listen to TCP on random port of {} (cannot assign random port to alias)\r\n\
                            Please specify the desired port.\r\n",
                            address,
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
                        tx: self.tx.clone_inner(),
                        peer: self.peer,
                        address: address.to_string(),
                        port: *port,
                    }),
                ) {
                    Err(err) => {
                        // Adding to connection map failed.
                        info!(
                            "Rejecting TCP port {} for alias {} ({}) - {}",
                            &assigned_port, address, self.peer, err,
                        );
                        self.tx.send(
                            format!(
                                "Cannot listen to TCP on port {} for alias {} ({})\r\n",
                                &assigned_port, address, err,
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
                            "Tunneling TCP port {} for alias {} ({})",
                            &assigned_port, address, self.peer
                        );
                        self.tx.send(
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
                        "Stopped SSH forwarding for {} ({})",
                        &assigned_host, self.peer
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
                            "Stopped TCP aliasing for {}:{} ({})",
                            &assigned_alias.0, assigned_alias.1, self.peer
                        );
                        let key: &dyn TcpAliasKey = assigned_alias.borrow();
                        self.server.alias.remove(key, &self.peer);
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
                            "Stopped HTTP forwarding for {} ({})",
                            &assigned_host, self.peer
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
                        "Stopped TCP forwarding for port {} ({})",
                        &assigned_port, self.peer
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
                        "Stopped TCP aliasing for {}:{} ({})",
                        &assigned_alias.0, assigned_alias.1, self.peer
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
            self.tx.send(b"Error: Aliasing is disabled\r\n".to_vec());
            return Ok(false);
        }
        if let AuthenticatedData::Admin { admin_data, .. } = &mut self.auth_data {
            if admin_data.admin_interface.is_some() {
                self.tx
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
                    handler.log_channel().inspect(|tx| {
                        let _ = tx.send(
                            format!(
                                "New SSH proxy from {}:{} => {}:{}\r\n",
                                originator_address,
                                originator_port,
                                host_to_connect,
                                port_to_connect
                            )
                            .into_bytes(),
                        );
                    });
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
                                            sleep(unproxied_connection_timeout).await;
                                            cancellation_token.cancel();
                                        })));
                                }
                            });
                        }
                        // Serve SSH normally for authed user
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
                    self.tx
                        .send(format!("Forwarding SSH from {}\r\n", host_to_connect).into_bytes());
                    return Ok(true);
                }
            }
            self.tx
                .send(format!("Unknown SSH alias {}\r\n", host_to_connect).into_bytes());
        // Handle local forwarding for HTTP
        } else if port_to_connect == self.server.http_port
            || port_to_connect == self.server.https_port
        {
            if let Some(handler) = self
                .server
                .aliasing_proxy_data
                .conn_manager
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
                                let _ = conn.await;
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
                                let _ = conn.await;
                            });
                        }
                    }

                    return Ok(true);
                }
            }
            self.tx
                .send(format!("Unknown HTTP alias {}\r\n", host_to_connect).into_bytes());
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
                    handler.log_channel().inspect(|tx| {
                        let _ = tx.send(
                            format!(
                                "New TCP proxy from {}:{} => {}:{}\r\n",
                                originator_address,
                                originator_port,
                                host_to_connect,
                                port_to_connect
                            )
                            .into_bytes(),
                        );
                    });
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
                                            sleep(unproxied_connection_timeout).await;
                                            cancellation_token.cancel();
                                        })));
                                }
                            });
                        }
                        // Serve TCP normally for authed user
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
                    self.tx
                        .send(format!("Forwarding TCP from {}\r\n", host_to_connect).into_bytes());
                    return Ok(true);
                }
            }
            self.tx
                .send(format!("Unknown TCP port {}\r\n", port_to_connect).into_bytes());
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
                    handler.log_channel().inspect(|tx| {
                        let _ = tx.send(
                            format!(
                                "New TCP proxy from {}:{} => {}:{}\r\n",
                                originator_address,
                                originator_port,
                                host_to_connect,
                                port_to_connect
                            )
                            .into_bytes(),
                        );
                    });
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
                                            sleep(unproxied_connection_timeout).await;
                                            cancellation_token.cancel();
                                        })));
                                }
                            });
                        }
                        // Serve TCP normally for authed user
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
                    self.tx
                        .send(format!("Forwarding TCP from {}\r\n", host_to_connect).into_bytes());
                    return Ok(true);
                }
            }
            self.tx.send(
                format!("Unknown alias {}:{}\r\n", host_to_connect, port_to_connect).into_bytes(),
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
        info!("{} ({}) disconnected", user, self.peer);
        match self.auth_data {
            AuthenticatedData::User { .. } | AuthenticatedData::Admin { .. } => {
                let server = Arc::clone(&self.server);
                let id = self.id;
                let peer = self.peer;
                tokio::task::spawn_blocking(move || {
                    // Remove all proxy connections from this session
                    server.http.remove_by_address(&peer);
                    server.ssh.remove_by_address(&peer);
                    server.tcp.remove_by_address(&peer);
                    server.alias.remove_by_address(&peer);
                    // Remove any references to this session
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
