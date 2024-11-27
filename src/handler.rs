use async_trait::async_trait;
#[cfg(test)]
use mockall::automock;
use tokio::sync::mpsc;

#[cfg_attr(test, automock)]
#[async_trait]
pub(crate) trait ConnectionHandler<T: Sync> {
    fn log_channel(&self) -> mpsc::UnboundedSender<Vec<u8>>;

    async fn tunneling_channel(&self, ip: &str, port: u16) -> anyhow::Result<T>;

    async fn aliasing_channel<'a>(
        &self,
        ip: &str,
        port: u16,
        fingerprint: Option<&'a str>,
    ) -> anyhow::Result<T>;
}
