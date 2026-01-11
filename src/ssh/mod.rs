use std::{
    collections::HashMap,
    mem,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicIsize, Ordering},
    },
    time::Duration,
};

mod auth;
pub(crate) mod connection_handler;
mod exec;
mod forwarding;

use crate::{
    SandholeServer,
    droppable_handle::DroppableHandle,
    fingerprints::AuthenticationType,
    ip::{IpFilter, IpFilterConfig},
    quota::{TokenHolder, UserIdentification},
    ssh::{
        auth::{AdminData, AuthenticatedData, ProxyAutoCancellation, UserData},
        exec::{
            AdminCommand, AllowedFingerprintsCommand, ExecCommandFlag, ForceHttpsCommand,
            Http2Command, IpAllowlistCommand, IpBlocklistCommand, SniProxyCommand, SshCommand,
            SshCommandContext, TcpAliasCommand,
        },
        forwarding::{Forwarder, LocalForwardingContext, RemoteForwardingContext},
    },
};

#[cfg(feature = "login")]
use crate::login::AuthenticationRequest;

use async_speed_limit::Limiter;
use chrono::Utc;
use enumflags2::BitFlags;
use ipnet::IpNet;
use owo_colors::OwoColorize;
use russh::{
    Channel, ChannelId, MethodKind, MethodSet,
    keys::{HashAlg, PublicKey, ssh_key::Fingerprint},
    server::{Auth, Handler, Msg, Session},
};
#[cfg_attr(not(feature = "login"), expect(unused_imports))]
use tokio::time::timeout;
use tokio::{
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
    time::sleep,
};
use tokio_util::sync::CancellationToken;

type FingerprintFn = dyn Fn(Option<&Fingerprint>) -> bool + Send + Sync;

#[derive(Debug, Clone)]
pub(crate) struct ServerHandlerSender(pub(crate) Option<UnboundedSender<Vec<u8>>>);

impl ServerHandlerSender {
    pub(crate) fn send(&self, message: Vec<u8>) -> Result<(), std::io::Error> {
        if let Some(sender) = self.0.as_ref() {
            sender
                .send(message)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::BrokenPipe, error))?;
        }
        Ok(())
    }
}

// Shared data for each SSH connection.
pub(crate) struct ServerHandler {
    // The unique ID of this connection.
    id: usize,
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
    commands: BitFlags<ExecCommandFlag>,
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
        #[cfg(not(coverage_nightly))]
        tracing::info!(peer = %peer_address, "SSH client connected.");
        let (tx, rx) = mpsc::unbounded_channel();
        let unproxied_connection_timeout = self.unproxied_connection_timeout;
        ServerHandler {
            id,
            peer: peer_address,
            user: None,
            key_fingerprint: None,
            cancellation_token: cancellation_token.clone(),
            auth_data: AuthenticatedData::None {
                proxy_data: Box::new(ProxyAutoCancellation {
                    cancellation_token: cancellation_token.clone(),
                    unproxied_connection_timeout,
                    proxy_count: Arc::new(AtomicIsize::new(0)),
                    timeout_handle: Arc::new(Mutex::new(None)),
                }),
            },
            commands: Default::default(),
            channel_id: None,
            tx: ServerHandlerSender(Some(tx)),
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
    #[cfg_attr(
        not(coverage_nightly),
        tracing::instrument(skip(self), fields(peer = %self.peer), level = "debug")
    )]
    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        // Check if the API login service has been initialized.
        #[cfg(feature = "login")]
        {
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
                                let mut user_sessions =
                                    self.server.sessions_password.lock().unwrap();
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
                            #[cfg(not(coverage_nightly))]
                            tracing::info!(
                                peer = %self.peer, %user, role = %self.auth_data, "SSH client authenticated with password.",
                            );
                            return Ok(Auth::Accept);
                        } else {
                            #[cfg(not(coverage_nightly))]
                            tracing::warn!(peer = %self.peer, %user, "Failed password authentication.");
                        }
                    }
                    Ok(Err(error)) => {
                        #[cfg(not(coverage_nightly))]
                        tracing::error!(peer = %self.peer, %user, %error, "SSH authentication error.");
                    }
                    _ => {
                        #[cfg(not(coverage_nightly))]
                        tracing::warn!(peer = %self.peer, "Authentication request timed out.");
                    }
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
    #[cfg_attr(
        not(coverage_nightly),
        tracing::instrument(skip(self), fields(peer = %self.peer), level = "debug")
    )]
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
                    if let AuthenticatedData::None { ref mut proxy_data } = self.auth_data {
                        proxy_data.start_timeout(self.server.idle_connection_timeout);
                    }
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
        #[cfg(not(coverage_nightly))]
        tracing::info!(
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
            #[cfg(not(coverage_nightly))]
            tracing::debug!(peer = %self.peer, ?data, "Received channel data.");
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
    #[cfg_attr(
        not(coverage_nightly),
        tracing::instrument(skip(self, session), fields(peer = %self.peer), level = "debug")
    )]
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let AuthenticatedData::None { .. } = self.auth_data {
            return Err(russh::Error::Disconnect);
        };
        #[cfg(not(coverage_nightly))]
        tracing::debug!(peer = %self.peer, ?data, "Received exec_request data.");
        let mut success = true;
        let cmd = String::from_utf8_lossy(data);
        // Split commands by whitespace and handle each.
        for command in cmd.split_whitespace() {
            match command {
                // - `admin` command creates an admin interface if the user is an admin
                "admin" => {
                    let mut command = AdminCommand;
                    match command
                        .execute(&mut SshCommandContext {
                            server: &self.server,
                            auth_data: &mut self.auth_data,
                            peer: &self.peer,
                            commands: &mut self.commands,
                            tx: &self.tx,
                        })
                        .await
                    {
                        Ok(_) => {}
                        Err(error) => {
                            #[cfg(not(coverage_nightly))]
                            tracing::debug!(peer = %self.peer, %error, "'admin' command failed.");
                            let _ = self
                                .tx
                                .send(format!("'admin' command failed: {error}\r\n").into());
                            success = false;
                            self.cancellation_token.cancel();
                            break;
                        }
                    }
                }
                // - `allowed-fingerprints` sets this connection as alias-only,
                //   and requires local forwardings to have one of the specified key fingerprints.
                command if command.starts_with("allowed-fingerprints=") => {
                    let set = command
                        .trim_start_matches("allowed-fingerprints=")
                        .split(',')
                        .filter(|a| !a.is_empty())
                        .map(|key| key.parse::<Fingerprint>())
                        .collect();
                    let mut command = AllowedFingerprintsCommand(set);
                    match command
                        .execute(&mut SshCommandContext {
                            server: &self.server,
                            auth_data: &mut self.auth_data,
                            peer: &self.peer,
                            commands: &mut self.commands,
                            tx: &self.tx,
                        })
                        .await
                    {
                        Ok(_) => {}
                        Err(error) => {
                            #[cfg(not(coverage_nightly))]
                            tracing::debug!(peer = %self.peer, %error, "'allowed-fingerprints' command failed.");
                            let _ = self.tx.send(
                                format!("'allowed-fingerprints' command failed: {error}\r\n")
                                    .into(),
                            );
                            success = false;
                            self.cancellation_token.cancel();
                            break;
                        }
                    }
                }
                // - `tcp-alias` sets this connection as alias-only.
                "tcp-alias" => {
                    let mut command = TcpAliasCommand;
                    match command
                        .execute(&mut SshCommandContext {
                            server: &self.server,
                            auth_data: &mut self.auth_data,
                            peer: &self.peer,
                            commands: &mut self.commands,
                            tx: &self.tx,
                        })
                        .await
                    {
                        Ok(_) => {}
                        Err(error) => {
                            #[cfg(not(coverage_nightly))]
                            tracing::debug!(peer = %self.peer, %error, "'tcp-alias' command failed.");
                            let _ = self
                                .tx
                                .send(format!("'tcp-alias' command failed: {error}\r\n").into());
                            success = false;
                            self.cancellation_token.cancel();
                            break;
                        }
                    }
                }
                // - `force-https` causes tunneled HTTP requests to be redirected to HTTPS.
                "force-https" => {
                    let mut command = ForceHttpsCommand;
                    match command
                        .execute(&mut SshCommandContext {
                            server: &self.server,
                            auth_data: &mut self.auth_data,
                            peer: &self.peer,
                            commands: &mut self.commands,
                            tx: &self.tx,
                        })
                        .await
                    {
                        Ok(_) => {}
                        Err(error) => {
                            #[cfg(not(coverage_nightly))]
                            tracing::debug!(peer = %self.peer, %error, "'force-https' command failed.");
                            let _ = self
                                .tx
                                .send(format!("'force-https' command failed: {error}\r\n").into());
                            success = false;
                            self.cancellation_token.cancel();
                            break;
                        }
                    }
                }
                // - `http2` allows serving HTTP/2 to the HTTP endpoints.
                "http2" => {
                    let mut command = Http2Command;
                    match command
                        .execute(&mut SshCommandContext {
                            server: &self.server,
                            auth_data: &mut self.auth_data,
                            peer: &self.peer,
                            commands: &mut self.commands,
                            tx: &self.tx,
                        })
                        .await
                    {
                        Ok(_) => {}
                        Err(error) => {
                            #[cfg(not(coverage_nightly))]
                            tracing::debug!(peer = %self.peer, %error, "'http2' command failed.");
                            let _ = self
                                .tx
                                .send(format!("'http2' command failed: {error}\r\n").into());
                            success = false;
                            self.cancellation_token.cancel();
                            break;
                        }
                    }
                }
                // - `sni-proxy` allows the user to handle the certificates themselves for HTTPS traffic.
                "sni-proxy" => {
                    let mut command = SniProxyCommand;
                    match command
                        .execute(&mut SshCommandContext {
                            server: &self.server,
                            auth_data: &mut self.auth_data,
                            peer: &self.peer,
                            commands: &mut self.commands,
                            tx: &self.tx,
                        })
                        .await
                    {
                        Ok(_) => {}
                        Err(error) => {
                            #[cfg(not(coverage_nightly))]
                            tracing::debug!(peer = %self.peer, %error, "'sni-proxy' command failed.");
                            let _ = self
                                .tx
                                .send(format!("'sni-proxy' command failed: {error}\r\n").into());
                            success = false;
                            self.cancellation_token.cancel();
                            break;
                        }
                    }
                }
                // - `ip-allowlist` requires tunneling/aliasing connections to come from
                //   specific IP ranges.
                command if command.starts_with("ip-allowlist=") => {
                    let list: Result<Vec<IpNet>, _> = command
                        .trim_start_matches("ip-allowlist=")
                        .split(',')
                        .filter(|a| !a.is_empty())
                        .map(|network| network.parse::<IpNet>())
                        .collect();
                    let mut command = IpAllowlistCommand(list);
                    match command
                        .execute(&mut SshCommandContext {
                            server: &self.server,
                            auth_data: &mut self.auth_data,
                            peer: &self.peer,
                            commands: &mut self.commands,
                            tx: &self.tx,
                        })
                        .await
                    {
                        Ok(_) => {}
                        Err(error) => {
                            #[cfg(not(coverage_nightly))]
                            tracing::debug!(peer = %self.peer, %error, "'ip-allowlist' command failed.");
                            let _ = self
                                .tx
                                .send(format!("'ip-allowlist' command failed: {error}\r\n").into());
                            success = false;
                            self.cancellation_token.cancel();
                            break;
                        }
                    }
                }
                // - `ip-blocklist` requires tunneling/aliasing connections to come from
                //   specific IP ranges.
                command if command.starts_with("ip-blocklist=") => {
                    let list: Result<Vec<IpNet>, _> = command
                        .trim_start_matches("ip-blocklist=")
                        .split(',')
                        .filter(|a| !a.is_empty())
                        .map(|network| network.parse::<IpNet>())
                        .collect();
                    let mut command = IpBlocklistCommand(list);
                    match command
                        .execute(&mut SshCommandContext {
                            server: &self.server,
                            auth_data: &mut self.auth_data,
                            peer: &self.peer,
                            commands: &mut self.commands,
                            tx: &self.tx,
                        })
                        .await
                    {
                        Ok(_) => {}
                        Err(error) => {
                            #[cfg(not(coverage_nightly))]
                            tracing::debug!(peer = %self.peer, %error, "'ip-blocklist' command failed.");
                            let _ = self
                                .tx
                                .send(format!("'ip-blocklist' command failed: {error}\r\n").into());
                            success = false;
                            self.cancellation_token.cancel();
                            break;
                        }
                    }
                }
                // - Unknown command
                command => {
                    #[cfg(not(coverage_nightly))]
                    tracing::debug!(
                        peer = %self.peer, %command, role = %self.auth_data, "Invalid SSH command received."
                    );
                    let _ = self
                        .tx
                        .send(format!("Error: invalid command {command}...").into_bytes());
                    success = false;
                    self.cancellation_token.cancel();
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
                            *user_data.ip_filter.write().unwrap() = Some(ip_filter);
                        }
                        Err(error) => {
                            let _ = self.tx.send(
                                format!("Failed to create IP filter for connection ({error})\r\n")
                                    .into_bytes(),
                            );
                            success = false;
                            self.cancellation_token.cancel();
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
        #[cfg(not(coverage_nightly))]
        tracing::debug!(peer = %self.peer, "Received pty_request.");
        if let AuthenticatedData::Admin { admin_data, .. } = &mut self.auth_data {
            // Change the size of the pseudo-terminal.
            admin_data.col_width = Some(col_width);
            admin_data.row_height = Some(row_height);
        }
        session.channel_success(channel)
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
            if let Some(ref mut admin_interface) = admin_data.admin_interface
                && let Err(error) = admin_interface.resize(col_width as u16, row_height as u16)
            {
                #[cfg(not(coverage_nightly))]
                tracing::warn!(peer = %self.peer, %error, "Failed to resize terminal.");
                return session.channel_failure(channel);
            }
        }

        session.channel_success(channel)
    }

    // Handle a remote forwarding request for the client.
    #[cfg_attr(
        not(coverage_nightly),
        tracing::instrument(skip(self, session), fields(peer = %self.peer), level = "debug")
    )]
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
                    let _ = self.tx.send(
                        format!(
                            "{} {} Cannot remote forward if admin interface is being used",
                            Utc::now().to_rfc3339().dimmed(),
                            " Error ".black().on_red().bold(),
                        )
                        .into_bytes(),
                    );
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
        let ssh_port = self.server.ssh_port;
        let http_port = if self.server.disable_http {
            None
        } else {
            Some(self.server.http_port)
        };
        let https_port = if self.server.disable_https {
            None
        } else {
            Some(self.server.https_port)
        };
        Forwarder::remote_forwarding(
            &mut RemoteForwardingContext {
                server: &mut self.server,
                user_data,
                peer: &mut self.peer,
                user: &mut self.user,
                key_fingerprint: &mut self.key_fingerprint,
                tx: &mut self.tx,
            },
            address.trim(),
            port,
            ssh_port,
            http_port,
            https_port,
            handle,
        )
        .await
    }

    // Handle closure of a remote forwarding request.
    #[cfg_attr(
        not(coverage_nightly),
        tracing::instrument(skip(self, _session), fields(peer = %self.peer), level = "debug")
    )]
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
        Forwarder::cancel_remote_forwarding(
            &mut RemoteForwardingContext {
                server: &mut self.server,
                user_data,
                peer: &mut self.peer,
                user: &mut self.user,
                key_fingerprint: &mut self.key_fingerprint,
                tx: &mut self.tx,
            },
            address.trim(),
            port as u16,
        )
        .await
    }

    // Handle a local forwarding request (i.e. proxy tunnel for aliases).
    #[cfg_attr(
        not(coverage_nightly),
        tracing::instrument(skip(self, _session), fields(peer = %self.peer), level = "debug")
    )]
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
            let _ = self.tx.send(
                format!(
                    "{} {} Aliasing is disabled\r\n",
                    Utc::now().to_rfc3339().dimmed(),
                    " Error ".black().on_red().bold(),
                )
                .into_bytes(),
            );
            return Ok(false);
        }
        if let AuthenticatedData::Admin { admin_data, .. } = &mut self.auth_data {
            if admin_data.admin_interface.is_some() {
                let _ = self.tx.send(
                    format!(
                        "{} {} Cannot local forward if admin interface is being used\r\n",
                        Utc::now().to_rfc3339().dimmed(),
                        " Error ".black().on_red().bold(),
                    )
                    .into_bytes(),
                );
                self.cancellation_token.cancel();
                return Ok(false);
            } else {
                admin_data.is_forwarding = true;
            }
        }
        // Handle local forwarding
        if Forwarder::local_forwarding(
            &mut LocalForwardingContext {
                server: &mut self.server,
                auth_data: &mut self.auth_data,
                peer: &mut self.peer,
                key_fingerprint: &mut self.key_fingerprint,
                tx: &mut self.tx,
            },
            host_to_connect.trim(),
            port_to_connect,
            originator_address.trim(),
            originator_port as u16,
            channel,
        )
        .await?
        {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

// Clean up session data on drop (i.e. disconnected from server)
impl Drop for ServerHandler {
    fn drop(&mut self) {
        let user = self.user.as_ref().map(String::as_ref).unwrap_or("unknown");
        #[cfg(not(coverage_nightly))]
        tracing::info!(peer = %self.peer, %user, "SSH client disconnected.");
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
