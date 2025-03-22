use std::path::PathBuf;

use http::Version;
use ipnet::IpNet;

#[derive(thiserror::Error, Debug)]
pub(crate) enum ServerError {
    #[error("Invalid config: {0}")]
    InvalidConfig(String),
    #[error("Missing URI host")]
    MissingUriHost,
    #[error("Missing Host header")]
    MissingHostHeader,
    #[error("Invalid Host header")]
    InvalidHostHeader,
    #[error("Invalid HTTP version {0:?}")]
    InvalidHttpVersion(Version),
    #[error("Missing Upgrade header")]
    MissingUpgradeHeader,
    #[error("Invalid file path")]
    InvalidFilePath,
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
    #[error("Duplicate network CIDR {0}")]
    DuplicateNetworkCidr(IpNet),
    #[error("Tunneling not allowed")]
    TunnelingNotAllowed,
    #[error("Aliasing not allowed")]
    AliasingNotAllowed,
}
