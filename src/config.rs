use std::{path::PathBuf, sync::OnceLock};

#[derive(Debug)]
pub struct ApplicationConfig {
    pub public_keys_directory: PathBuf,
    pub private_key_file: PathBuf,
    pub private_key_password: Option<String>,
    pub listen_address: String,
    pub ssh_port: u16,
    pub http_port: u16,
    pub https_port: u16,
}

pub static CONFIG: OnceLock<ApplicationConfig> = OnceLock::new();
