use std::{path::PathBuf, time::Duration};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RandomSubdomainSeed {
    User,
    KeyFingerprint,
    SocketAddress,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum BindHostnames {
    All,
    Valid,
    Txt,
    None,
}

#[derive(Debug)]
pub struct ApplicationConfig {
    pub domain: String,
    pub domain_redirect: String,
    pub user_keys_directory: PathBuf,
    pub admin_keys_directory: PathBuf,
    pub certificates_directory: PathBuf,
    pub private_key_file: PathBuf,
    pub listen_address: String,
    pub ssh_port: u16,
    pub http_port: u16,
    pub https_port: u16,
    pub force_https: bool,
    pub acme_contact_email: Option<String>,
    pub acme_cache_directory: PathBuf,
    pub acme_use_staging: bool,
    pub bind_hostnames: BindHostnames,
    pub txt_record_prefix: String,
    pub allow_provided_subdomains: bool,
    pub allow_requested_ports: bool,
    pub idle_connection_timeout: Duration,
    pub random_subdomain_seed: Option<RandomSubdomainSeed>,
    pub request_timeout: Duration,
}
