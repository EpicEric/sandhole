#[derive(thiserror::Error, Debug)]
pub(crate) enum ServerError {
    #[error("Missing Host header")]
    MissingHostHeader,
    #[error("Invalid Host header")]
    InvalidHostHeader,
    #[error("Missing Upgrade header")]
    MissingUpgradeHeader,
    #[error("Request timed out")]
    RequestTimeout,
    #[error("Invalid file path")]
    InvalidFilePath,
}
