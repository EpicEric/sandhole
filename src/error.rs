#[derive(thiserror::Error, Debug)]
pub(crate) enum ServerError {
    #[error("Missing Host header")]
    MissingHostHeader,
    #[error("Invalid Host header")]
    InvalidHostHeader,
    #[error("Missing Upgrade header")]
    MissingUpgradeHeader,
}
