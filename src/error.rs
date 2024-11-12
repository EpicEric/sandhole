use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("Missing Host header")]
    MissingHostHeader,
    #[error("Invalid Host header")]
    InvalidHostHeader,
    #[error("Missing Upgrade header")]
    MissingUpgradeHeader,
}
