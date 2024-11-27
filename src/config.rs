use std::{path::PathBuf, time::Duration};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RandomSubdomainSeed {
    User,
    IpAndUser,
    KeyFingerprint,
    SocketAddress,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum BindHostnames {
    All,
    Cname,
    Txt,
    None,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum LoadBalancing {
    Allow,
    Replace,
    Deny,
}

/// List of user-defined configurations for Sandhole.
///
/// Instead of constructing this directly, you should use the Sandhole CLI.
#[derive(Debug)]
pub struct ApplicationConfig {
    pub domain: String,
    pub domain_redirect: String,
    pub user_keys_directory: PathBuf,
    pub admin_keys_directory: PathBuf,
    pub certificates_directory: PathBuf,
    pub acme_cache_directory: PathBuf,
    pub private_key_file: PathBuf,
    pub disable_directory_creation: bool,
    pub listen_address: String,
    pub ssh_port: u16,
    pub http_port: u16,
    pub https_port: u16,
    pub force_https: bool,
    pub disable_http_logs: bool,
    pub disable_tcp_logs: bool,
    pub acme_contact_email: Option<String>,
    pub acme_use_staging: bool,
    pub password_authentication_url: Option<String>,
    pub bind_hostnames: BindHostnames,
    pub load_balancing: LoadBalancing,
    pub txt_record_prefix: String,
    pub allow_provided_subdomains: bool,
    pub allow_requested_ports: bool,
    pub random_subdomain_seed: Option<RandomSubdomainSeed>,
    pub idle_connection_timeout: Duration,
    pub authentication_request_timeout: Duration,
    pub http_request_timeout: Duration,
    pub tcp_connection_timeout: Option<Duration>,
}
