use std::{collections::BTreeSet, mem, net::SocketAddr, sync::Arc};

use color_eyre::eyre::eyre;
use enumflags2::{BitFlags, bitflags};
use russh::keys::ssh_key;

use crate::{
    SandholeServer,
    admin::AdminInterface,
    ssh::{AuthenticatedData, ServerHandlerSender, UserSessionRestriction},
    tcp_alias::TcpAlias,
};

#[bitflags]
#[repr(u16)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecCommandFlag {
    Admin,
    AllowedFingerprints,
    TcpAlias,
    ForceHttps,
    Http2,
    SniProxy,
    IpAllowlist,
    IpBlocklist,
}

pub(crate) struct SshCommandContext<'a> {
    pub(crate) server: &'a Arc<SandholeServer>,
    pub(crate) auth_data: &'a mut AuthenticatedData,
    pub(crate) peer: &'a SocketAddr,
    pub(crate) commands: &'a mut BitFlags<ExecCommandFlag>,
    pub(crate) tx: &'a ServerHandlerSender,
}

pub(crate) trait SshCommand {
    fn flag(&self) -> ExecCommandFlag;
    async fn execute(&mut self, context: &mut SshCommandContext) -> color_eyre::Result<()>;
}

pub(crate) struct AdminCommand;

impl SshCommand for AdminCommand {
    fn flag(&self) -> ExecCommandFlag {
        ExecCommandFlag::Admin
    }

    async fn execute(&mut self, context: &mut SshCommandContext<'_>) -> color_eyre::Result<()> {
        if context.commands.contains(self.flag()) {
            return Err(eyre!("duplicated command"));
        }
        match context.auth_data {
            AuthenticatedData::Admin { admin_data, .. } => {
                if admin_data.is_forwarding {
                    return Err(eyre!("cannot open admin interface while forwarding"));
                }
                let tx = context.tx.clone();
                let mut admin_interface = AdminInterface::new(tx, Arc::clone(context.server));
                // Resize if we already have data about the PTY
                if let (Some(col_width), Some(row_height)) =
                    (admin_data.col_width, admin_data.row_height)
                {
                    let _ = admin_interface.resize(col_width as u16, row_height as u16);
                }
                admin_data.admin_interface = Some(admin_interface);
                context.commands.insert(self.flag());
                Ok(())
            }
            _ => Err(eyre!("not authenticated as admin")),
        }
    }
}

pub(crate) struct AllowedFingerprintsCommand(
    pub(crate) Result<BTreeSet<ssh_key::Fingerprint>, ssh_key::Error>,
);

impl SshCommand for AllowedFingerprintsCommand {
    fn flag(&self) -> ExecCommandFlag {
        ExecCommandFlag::AllowedFingerprints
    }

    async fn execute(&mut self, context: &mut SshCommandContext<'_>) -> color_eyre::Result<()> {
        if context.server.disable_aliasing {
            return Err(eyre!("aliasing is disabled"));
        }
        if context.commands.contains(self.flag()) {
            return Err(eyre!("duplicated command"));
        }
        match context.auth_data {
            AuthenticatedData::User { user_data } | AuthenticatedData::Admin { user_data, .. } => {
                if matches!(
                    user_data.session_restriction,
                    UserSessionRestriction::SniProxyOnly
                ) {
                    return Err(eyre!("not compatible with SNI proxy"));
                }
                user_data.session_restriction = UserSessionRestriction::TcpAliasOnly;
                user_data.http_data.write().unwrap().is_aliasing = true;
                // Create a set from the provided list of fingerprints
                let set = mem::replace(&mut self.0, Ok(Default::default()))?;
                if set.is_empty() {
                    return Err(eyre!("no fingerprints provided"));
                }
                // Create a validation closure that verifies that the fingerprint is in our new set
                *user_data.allow_fingerprint.write().unwrap() =
                    Box::new(move |fingerprint| fingerprint.is_some_and(|fp| set.contains(fp)));
                // Reject TCP ports
                if !context
                    .server
                    .tcp
                    .remove_by_address(context.peer)
                    .is_empty()
                {
                    return Err(eyre!("cannot convert TCP port(s) into aliases"));
                }
                // Change any existing HTTP handlers into TCP alias handlers.
                let handlers = context.server.http.remove_by_address(context.peer);
                for (_, handler) in handlers.into_iter() {
                    let address = handler.address.clone();
                    // Ensure that the forwarding address is an alias, otherwise error.
                    if !context.server.is_alias(&address) {
                        return Err(eyre!(
                            "cannot listen to HTTP alias of '{address}' (must be alias, not localhost)"
                        ));
                    }
                    // Insert our handler into the TCP alias connections map.
                    context.server.alias.insert(
                        TcpAlias(address.clone(), 80),
                        *context.peer,
                        user_data.quota_key.clone(),
                        handler,
                    )?;
                }
                context
                    .commands
                    .insert(ExecCommandFlag::AllowedFingerprints);
                Ok(())
            }
            _ => Err(eyre!("not authenticated as user")),
        }
    }
}

pub(crate) struct TcpAliasCommand;

impl SshCommand for TcpAliasCommand {
    fn flag(&self) -> ExecCommandFlag {
        ExecCommandFlag::TcpAlias
    }

    async fn execute(&mut self, context: &mut SshCommandContext<'_>) -> color_eyre::Result<()> {
        if context.commands.contains(self.flag()) {
            return Err(eyre!("duplicated command"));
        }
        match context.auth_data {
            AuthenticatedData::User { user_data } | AuthenticatedData::Admin { user_data, .. } => {
                if context.server.disable_aliasing {
                    return Err(eyre!("aliasing is disabled"));
                }
                if matches!(
                    user_data.session_restriction,
                    UserSessionRestriction::SniProxyOnly
                ) {
                    return Err(eyre!("not compatible with SNI proxy"));
                }
                user_data.session_restriction = UserSessionRestriction::TcpAliasOnly;
                user_data.http_data.write().unwrap().is_aliasing = true;
                // Reject TCP ports
                if !context
                    .server
                    .tcp
                    .remove_by_address(context.peer)
                    .is_empty()
                {
                    return Err(eyre!("cannot convert TCP port(s) into aliases"));
                }
                // Change any existing HTTP handlers into TCP alias handlers.
                let handlers = context.server.http.remove_by_address(context.peer);
                for (_, handler) in handlers.into_iter() {
                    let address = handler.address.clone();
                    // Ensure that the forwarding address is an alias, otherwise error.
                    if !context.server.is_alias(&address) {
                        return Err(eyre!(
                            "cannot listen to HTTP alias of '{address}' (must be alias, not localhost)\r\n"
                        ));
                    }
                    // Insert our handler into the TCP alias connections map.
                    context.server.alias.insert(
                        TcpAlias(address.clone(), 80),
                        *context.peer,
                        user_data.quota_key.clone(),
                        handler,
                    )?;
                }
                context.commands.insert(self.flag());
                Ok(())
            }
            _ => Err(eyre!("not authenticated as user")),
        }
    }
}

pub(crate) struct ForceHttpsCommand;

impl SshCommand for ForceHttpsCommand {
    fn flag(&self) -> ExecCommandFlag {
        ExecCommandFlag::ForceHttps
    }

    async fn execute(&mut self, context: &mut SshCommandContext<'_>) -> color_eyre::Result<()> {
        if context.commands.contains(self.flag()) {
            return Err(eyre!("duplicated command"));
        }
        match context.auth_data {
            AuthenticatedData::User { user_data } | AuthenticatedData::Admin { user_data, .. } => {
                user_data
                    .http_data
                    .write()
                    .unwrap()
                    .redirect_http_to_https_port = Some(context.server.https_port);
                context.commands.insert(self.flag());
                Ok(())
            }
            _ => Err(eyre!("not authenticated as user")),
        }
    }
}

pub(crate) struct Http2Command;

impl SshCommand for Http2Command {
    fn flag(&self) -> ExecCommandFlag {
        ExecCommandFlag::Http2
    }

    async fn execute(&mut self, context: &mut SshCommandContext<'_>) -> color_eyre::Result<()> {
        if context.commands.contains(self.flag()) {
            return Err(eyre!("duplicated command"));
        }
        match context.auth_data {
            AuthenticatedData::User { user_data } | AuthenticatedData::Admin { user_data, .. } => {
                user_data.http_data.write().unwrap().http2 = true;
                context.commands.insert(self.flag());
                Ok(())
            }
            _ => Err(eyre!("not authenticated as user")),
        }
    }
}

pub(crate) struct SniProxyCommand;

impl SshCommand for SniProxyCommand {
    fn flag(&self) -> ExecCommandFlag {
        ExecCommandFlag::SniProxy
    }

    async fn execute(&mut self, context: &mut SshCommandContext<'_>) -> color_eyre::Result<()> {
        if context.commands.contains(self.flag()) {
            return Err(eyre!("duplicated command"));
        }
        match context.auth_data {
            AuthenticatedData::User { user_data } | AuthenticatedData::Admin { user_data, .. } => {
                if context.server.disable_sni {
                    return Err(eyre!("SNI proxying is disabled"));
                }
                if matches!(
                    user_data.session_restriction,
                    UserSessionRestriction::TcpAliasOnly
                ) {
                    return Err(eyre!("not compatible with TCP aliasing"));
                }
                user_data.session_restriction = UserSessionRestriction::SniProxyOnly;
                // Change any existing HTTP handlers into SNI proxy handlers.
                let handlers = context.server.http.remove_by_address(context.peer);
                for (_, handler) in handlers.into_iter() {
                    let address = handler.address.clone();
                    // Ensure that the SNI address is an alias, otherwise error.
                    if !context.server.is_alias(&address) {
                        return Err(eyre!(
                            "cannot listen to SNI proxy of '{address}' (must be alias, not localhost)"
                        ));
                    }
                    // Insert our handler into the SNI proxy connections map.
                    context.server.sni.insert(
                        address.clone(),
                        *context.peer,
                        user_data.quota_key.clone(),
                        handler,
                    )?;
                }
                context.commands.insert(self.flag());
                Ok(())
            }
            _ => Err(eyre!("not authenticated as user")),
        }
    }
}

pub(crate) struct IpAllowlistCommand(pub(crate) Result<Vec<ipnet::IpNet>, ipnet::AddrParseError>);

impl SshCommand for IpAllowlistCommand {
    fn flag(&self) -> ExecCommandFlag {
        ExecCommandFlag::IpAllowlist
    }

    async fn execute(&mut self, context: &mut SshCommandContext<'_>) -> color_eyre::Result<()> {
        if context.commands.contains(self.flag()) {
            return Err(eyre!("duplicated command"));
        }
        match context.auth_data {
            AuthenticatedData::User { user_data } | AuthenticatedData::Admin { user_data, .. } => {
                let list = mem::replace(&mut self.0, Ok(vec![]))?;
                if list.is_empty() {
                    return Err(eyre!("no allowlist networks provided"));
                }
                user_data.allowlist = Some(list);
                context.commands.insert(self.flag());
                Ok(())
            }
            _ => Err(eyre!("not authenticated as user")),
        }
    }
}

pub(crate) struct IpBlocklistCommand(pub(crate) Result<Vec<ipnet::IpNet>, ipnet::AddrParseError>);

impl SshCommand for IpBlocklistCommand {
    fn flag(&self) -> ExecCommandFlag {
        ExecCommandFlag::IpBlocklist
    }

    async fn execute(&mut self, context: &mut SshCommandContext<'_>) -> color_eyre::Result<()> {
        if context.commands.contains(self.flag()) {
            return Err(eyre!("duplicated command"));
        }
        match context.auth_data {
            AuthenticatedData::User { user_data } | AuthenticatedData::Admin { user_data, .. } => {
                let list = mem::replace(&mut self.0, Ok(vec![]))?;
                if list.is_empty() {
                    return Err(eyre!("no blocklist networks provided"));
                }
                user_data.blocklist = Some(list);
                context.commands.insert(self.flag());
                Ok(())
            }
            _ => Err(eyre!("not authenticated as user")),
        }
    }
}
