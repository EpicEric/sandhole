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
    pub public_keys_directory: PathBuf,
    pub certificates_directory: PathBuf,
    pub private_key_file: PathBuf,
    pub private_key_password: Option<String>,
    pub listen_address: String,
    pub ssh_port: u16,
    pub http_port: u16,
    pub https_port: u16,
    pub force_https: bool,
    pub bind_hostnames: BindHostnames,
    pub txt_record_prefix: String,
    pub force_random_subdomains: bool,
    pub random_subdomain_seed: Option<RandomSubdomainSeed>,
    pub request_timeout: Duration,
}
