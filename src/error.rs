use std::path::PathBuf;

use ipnet::IpNet;

#[derive(thiserror::Error, Debug)]
pub(crate) enum ServerError {
    #[error("Invalid config: {0}")]
    InvalidConfig(String),
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
    #[error("Tunneling unavailable")]
    TunnelingUnavailable,
    #[error("Tunneling not allowed")]
    TunnelingNotAllowed,
    #[error("Aliasing not allowed")]
    AliasingNotAllowed,
}
