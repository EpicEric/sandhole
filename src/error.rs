use std::path::PathBuf;

#[derive(thiserror::Error, Debug)]
pub(crate) enum ServerError {
    #[error("Invalid config: {0}")]
    InvalidConfig(String),
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
    #[error("Fingerprint denied")]
    FingerprintDenied,
    #[error("Already bound by another service")]
    LoadBalancingAlreadyBound,
    #[error("Quota reached for user")]
    QuotaReached,
    #[error("No matching user key")]
    NoMatchingUserKey,
    #[error("Unknown scheme (must be set to either http:// or https://)")]
    UnknownHttpScheme,
    #[error("Missing directory {0}")]
    MissingDirectory(PathBuf),
}
