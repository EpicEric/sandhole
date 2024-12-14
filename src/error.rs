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
    #[error("Fingerprint denied")]
    FingerprintDenied,
    #[error("Already bound by another service")]
    LoadBalancingAlreadyBound,
    #[error("Quota reached for user")]
    QuotaReached,
}
