use std::net::IpAddr;

use async_trait::async_trait;
#[cfg(test)]
use mockall::automock;
use ssh_key::Fingerprint;
use tokio::sync::mpsc;

// Extra data available for HTTP tunneling/aliasing connections.
#[derive(Clone)]
pub(crate) struct ConnectionHttpData {
    // Port to redirect HTTP requests to. If missing, do not redirect.
    pub(crate) redirect_http_to_https_port: Option<u16>,
}

// Trait for creating tunneling or aliasing channels (via an underlying SSH session).
#[cfg_attr(test, automock)]
#[async_trait]
pub(crate) trait ConnectionHandler<T: Sync> {
    // Return a copy of the logging channel associated with this connection.
    fn log_channel(&self) -> Option<mpsc::UnboundedSender<Vec<u8>>>;

    // Return the tunneling channel for this connection.
    async fn tunneling_channel(&self, ip: IpAddr, port: u16) -> anyhow::Result<T>;

    // Return the aliasing channel for this connection.
    async fn aliasing_channel<'a>(
        &self,
        ip: IpAddr,
        port: u16,
        fingerprint: Option<&'a Fingerprint>,
    ) -> anyhow::Result<T>;

    async fn http_data(&self) -> Option<ConnectionHttpData>;
}
