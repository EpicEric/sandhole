use std::net::IpAddr;

#[cfg(test)]
use mockall::automock;
use russh::keys::ssh_key::Fingerprint;
use tokio::sync::mpsc;

// Extra data available for HTTP tunneling/aliasing connections.
#[derive(Clone)]
pub(crate) struct ConnectionHttpData {
    // Port to redirect HTTP requests to. If missing, do not redirect.
    pub(crate) redirect_http_to_https_port: Option<u16>,
    pub(crate) is_aliasing: bool,
    pub(crate) http2: bool,
}

// Trait for creating tunneling or aliasing channels (via an underlying SSH session).
#[cfg_attr(test, automock)]
pub(crate) trait ConnectionHandler<T: Sync> {
    // Return a copy of the logging channel associated with this handler.
    fn log_channel(&self) -> Option<mpsc::UnboundedSender<Vec<u8>>>;

    // Return a tunneling channel for this handler.
    async fn tunneling_channel(&self, ip: IpAddr, port: u16) -> anyhow::Result<T>;

    // Whether the given credentials can create an aliasing channel to this handler.
    #[expect(clippy::needless_lifetimes)]
    async fn can_alias<'a>(
        &self,
        ip: IpAddr,
        port: u16,
        fingerprint: Option<&'a Fingerprint>,
    ) -> bool;

    // Return an aliasing channel for this handler.
    #[expect(clippy::needless_lifetimes)]
    async fn aliasing_channel<'a>(
        &self,
        ip: IpAddr,
        port: u16,
        fingerprint: Option<&'a Fingerprint>,
    ) -> anyhow::Result<T>;

    // Returns HTTP-specific data for this handler.
    async fn http_data(&self) -> Option<ConnectionHttpData>;
}
