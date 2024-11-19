use std::{path::PathBuf, time::Duration};

use clap::{command, Parser, ValueEnum};
use sandhole::{
    config::{ApplicationConfig, BindHostnames as BHConfig, RandomSubdomainSeed as RSSConfig},
    entrypoint,
};
use webpki::types::DnsName;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum RandomSubdomainSeed {
    /// From SSH user and requested address.
    User,
    /// From SSH key fingerprint and requested address.
    Fingerprint,
    /// From SSH connection socket (address + port) and requested address.
    Address,
}

impl From<RandomSubdomainSeed> for RSSConfig {
    fn from(value: RandomSubdomainSeed) -> Self {
        match value {
            RandomSubdomainSeed::User => RSSConfig::User,
            RandomSubdomainSeed::Fingerprint => RSSConfig::KeyFingerprint,
            RandomSubdomainSeed::Address => RSSConfig::SocketAddress,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum BindHostnames {
    /// Allow any hostnames unconditionally, including the domain.
    All,
    /// Allow any hostnames with valid DNS records, not including the domain.
    Valid,
    /// Allow any hostnames with a TXT record containing a fingerprint, including the domain.
    Txt,
    /// Don't allow user-provided hostnames, force subdomains.
    None,
}

impl From<BindHostnames> for BHConfig {
    fn from(value: BindHostnames) -> Self {
        match value {
            BindHostnames::All => BHConfig::All,
            BindHostnames::Valid => BHConfig::Valid,
            BindHostnames::Txt => BHConfig::Txt,
            BindHostnames::None => BHConfig::None,
        }
    }
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// The root domain of the application.
    #[arg(long, value_parser = validate_domain)]
    domain: String,

    /// Where to redirect requests to the root domain.
    #[arg(long, default_value_t = String::from(env!("CARGO_PKG_REPOSITORY")))]
    domain_redirect: String,

    /// Directory containing authorized public keys.
    /// Each file must contain exactly one key.
    #[arg(long, default_value_os = "./deploy/public_keys/")]
    public_keys_directory: PathBuf,

    /// Directory containing SSL certificates and keys.
    /// Each sub-directory inside of this one must contain a certificate chain in a
    /// `fullchain.pem` file and its private key in a `privkey.pem` file.
    #[arg(long, default_value_os = "./deploy/certificates/")]
    certificates_directory: PathBuf,

    /// File path to the server's secret key.
    #[arg(long, default_value_os = "./deploy/server_keys/ssh")]
    private_key_file: PathBuf,

    /// Password to use for the server's secret key, if any.
    #[arg(long)]
    private_key_password: Option<String>,

    /// Whether to create a private key file if missing.
    // #[arg(long, default_value_t = true)]
    // create_private_key_file: bool,

    /// Address to listen for all client connections.
    #[arg(long, default_value_t = String::from("0.0.0.0"))]
    listen_address: String,

    /// Port to listen for SSH connections.
    #[arg(long, default_value_t = 2222)]
    ssh_port: u16,

    /// Port to listen for HTTP connections.
    #[arg(long, default_value_t = 80)]
    http_port: u16,

    /// Port to listen for HTTPS connections.
    #[arg(long, default_value_t = 443)]
    https_port: u16,

    /// Always redirect HTTP requests to HTTPS.
    #[arg(long, default_value_t = false)]
    force_https: bool,

    /// Policy on whether to allow binding specific hostnames.
    #[arg(long, value_enum, default_value_t = BindHostnames::Txt)]
    bind_hostnames: BindHostnames,

    /// Prefix for TXT DNS records containing key fingerprints, for authorization to bind under a specific domain.
    ///
    /// In other words, valid records will be of the form: `TXT prefix.custom-domain SHA256:...`
    #[arg(long, default_value_t = String::from("_sandhole"), value_parser = validate_txt_record_prefix)]
    txt_record_prefix: String,

    /// Always use random subdomains instead of user-provided ones.
    #[arg(long, default_value_t = true)]
    force_random_subdomains: bool,

    /// Which value to seed with when generating random subdomains, for determinism. This allows binding to the same
    /// random address until Sandhole is restarted.
    ///
    /// Beware that this can lead to collisions if misused!
    ///
    /// If unset, defaults to a random seed.
    #[arg(long, value_enum)]
    random_subdomain_seed: Option<RandomSubdomainSeed>,

    /// Time in seconds until an outgoing request is automatically canceled.
    #[arg(long, default_value_t = 10)]
    request_timeout: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config = ApplicationConfig {
        domain: args.domain,
        domain_redirect: args.domain_redirect,
        public_keys_directory: args.public_keys_directory,
        certificates_directory: args.certificates_directory,
        private_key_file: args.private_key_file,
        private_key_password: args.private_key_password,
        listen_address: args.listen_address,
        ssh_port: args.ssh_port,
        http_port: args.http_port,
        https_port: args.https_port,
        force_https: args.force_https,
        bind_hostnames: args.bind_hostnames.into(),
        txt_record_prefix: args.txt_record_prefix,
        force_random_subdomains: args.force_random_subdomains,
        random_subdomain_seed: args.random_subdomain_seed.map(Into::into),
        request_timeout: Duration::from_secs(args.request_timeout),
    };
    entrypoint(config).await
}

fn validate_domain(domain: &str) -> Result<String, String> {
    DnsName::try_from(domain).map_err(|_| "invalid domain")?;
    Ok(domain.to_string())
}

fn validate_txt_record_prefix(prefix: &str) -> Result<String, String> {
    DnsName::try_from(prefix).map_err(|_| "invalid prefix")?;
    if prefix.find('.').is_some() {
        Err("prefix cannot contain period".into())
    } else {
        Ok(prefix.to_string())
    }
}
