// sandhole: Expose HTTP/SSH/TCP services through SSH port forwarding
// Copyright (C) 2024-2026 Eric Rodrigues Pires
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for
// more details.
//
// You should have received a copy of the GNU Affero General Public License along
// with this program. If not, see <https://www.gnu.org/licenses/>.

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
    #[cfg_attr(not(feature = "login"), expect(dead_code))]
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
    #[error("Pool limit reached")]
    PoolLimitReached,
    #[error("Timed out opening tunneling channel")]
    TunnelingChannelTimeout,
    #[error("IP connection limit reached")]
    IpConnectionLimitReached,
    #[error("SSH error: {0}")]
    Ssh(#[from] russh::Error),
}
