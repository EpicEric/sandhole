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

use std::net::IpAddr;

use russh::keys::ssh_key::Fingerprint;

use crate::{error::ServerError, ssh::ServerHandlerSender};

// Extra data available for HTTP tunneling/aliasing connections.
#[derive(Clone)]
pub(crate) struct ConnectionHttpData {
    // Port to redirect HTTP requests to. If missing, do not redirect.
    pub(crate) redirect_http_to_https_port: Option<u16>,
    // Whether this is an aliasing connection.
    pub(crate) is_aliasing: bool,
    // Whether this connection accepts HTTP/2.
    pub(crate) http2: bool,
    // Optional host to replace in proxied requests.
    pub(crate) host: Option<String>,
}

// Trait for creating tunneling or aliasing channels (via an underlying SSH session).
#[cfg_attr(test, mockall::automock)]
pub(crate) trait ConnectionHandler<T: Sync> {
    // Return a copy of the logging channel associated with this handler.
    fn log_channel(&self) -> ServerHandlerSender;

    // Return a tunneling channel for this handler.
    async fn tunneling_channel(&self, ip: IpAddr, port: u16) -> Result<T, ServerError>;

    // Whether the given credentials can create an aliasing channel to this handler.
    #[expect(clippy::needless_lifetimes)]
    fn can_alias<'a>(&self, ip: IpAddr, port: u16, fingerprint: Option<&'a Fingerprint>) -> bool;

    // Return an aliasing channel for this handler.
    #[expect(clippy::needless_lifetimes)]
    async fn aliasing_channel<'a>(
        &self,
        ip: IpAddr,
        port: u16,
        fingerprint: Option<&'a Fingerprint>,
    ) -> Result<T, ServerError>;

    // Returns HTTP-specific data for this handler.
    fn http_data(&self) -> Option<ConnectionHttpData>;
}
