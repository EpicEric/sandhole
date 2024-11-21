use std::path::PathBuf;

use clap::{command, Parser, ValueEnum};
use humantime::Duration;
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
    /// Allow any hostnames unconditionally, including the main domain.
    All,
    /// Allow any hostnames with valid DNS records, not including the main domain.
    Valid,
    /// Allow any hostnames with a TXT record containing a fingerprint, including the main domain.
    Txt,
    /// Don't allow user-provided hostnames, enforce subdomains.
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

    /// Directory containing public keys of authorized users.
    /// Each file must contain exactly one key.
    #[arg(long, default_value_os = "./deploy/user_keys/")]
    user_keys_directory: PathBuf,

    /// Directory containing public keys of admin users.
    /// Each file must contain exactly one key.
    #[arg(long, default_value_os = "./deploy/admin_keys/")]
    admin_keys_directory: PathBuf,

    /// If set, defines a URL against which password authentication requests will
    /// be validated. This is done by sending the following JSON payload:
    ///
    /// `{"user": "...", "password": "..."}`
    ///
    /// Any 2xx response indicates that the credentials are authorized.
    #[arg(long)]
    password_authentication_url: Option<String>,

    /// Directory containing SSL certificates and keys.
    /// Each sub-directory inside of this one must contain a certificate chain in a
    /// `fullchain.pem` file and its private key in a `privkey.pem` file.
    #[arg(long, default_value_os = "./deploy/certificates/")]
    certificates_directory: PathBuf,

    /// File path to the server's secret key. If missing, it will be created for you.
    #[arg(long, default_value_os = "./deploy/server_keys/ssh")]
    private_key_file: PathBuf,

    /// Address to listen for all client connections.
    #[arg(long, default_value_t = String::from("::"))]
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

    /// Contact e-mail to use with Let's Encrypt. If set, enables ACME for HTTPS certificates.
    ///
    /// By providing your e-mail, you agree to Let's Encrypt's Terms of Service.
    #[arg(long)]
    acme_contact_email: Option<String>,

    /// Directory to use as a cache for Let's Encrypt's account and certificates.
    #[arg(long, default_value_os = "./deploy/acme_cache")]
    acme_cache_directory: PathBuf,

    /// Controls whether to use the staging directory for Let's Encrypt certificates (default is production).
    ///
    /// Only use this option for testing.
    #[arg(long, default_value_t = false)]
    acme_use_staging: bool,

    /// Policy on whether to allow binding specific hostnames.
    ///
    /// Beware that this can lead to domain takeovers if misused!
    #[arg(long, value_enum, default_value_t = BindHostnames::Txt)]
    bind_hostnames: BindHostnames,

    /// Prefix for TXT DNS records containing key fingerprints, for authorization to bind under a specific domain.
    ///
    /// In other words, valid records will be of the form: `TXT prefix.custom-domain SHA256:...`
    #[arg(long, default_value_t = String::from("_sandhole"), value_parser = validate_txt_record_prefix)]
    txt_record_prefix: String,

    /// Allow user-provided subdomains. By default, subdomains are always random.
    #[arg(long, default_value_t = false)]
    allow_provided_subdomains: bool,

    /// Allow user-requested ports. By default, ports are always random.
    #[arg(long, default_value_t = false)]
    allow_requested_ports: bool,

    /// Which value to seed with when generating random subdomains, for determinism. This allows binding to the same
    /// random address until Sandhole is restarted.
    ///
    /// Beware that this can lead to collisions if misused!
    ///
    /// If unset, defaults to a random seed.
    #[arg(long, value_enum)]
    random_subdomain_seed: Option<RandomSubdomainSeed>,

    /// Grace period for dangling/unauthenticated SSH connections before they are forcefully disconnected.
    ///
    /// A low value may cause valid proxy/tunnel connections to be erroneously removed.
    #[arg(long, default_value = "2s")]
    idle_connection_timeout: Duration,

    /// Time until a user+password authentication request is canceled.
    /// Any timed out requests will not authenticate the user.
    #[arg(long, default_value = "5s")]
    authentication_request_timeout: Duration,

    /// Time until an outgoing HTTP request is automatically canceled.
    #[arg(long, default_value = "10s")]
    request_timeout: Duration,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = ApplicationConfig {
        domain: args.domain,
        domain_redirect: args.domain_redirect,
        user_keys_directory: args.user_keys_directory,
        admin_keys_directory: args.admin_keys_directory,
        password_authentication_url: args.password_authentication_url,
        certificates_directory: args.certificates_directory,
        private_key_file: args.private_key_file,
        listen_address: args.listen_address,
        ssh_port: args.ssh_port,
        http_port: args.http_port,
        https_port: args.https_port,
        force_https: args.force_https,
        acme_contact_email: args.acme_contact_email,
        acme_cache_directory: args.acme_cache_directory,
        acme_use_staging: args.acme_use_staging,
        bind_hostnames: args.bind_hostnames.into(),
        txt_record_prefix: args.txt_record_prefix,
        allow_provided_subdomains: args.allow_provided_subdomains,
        allow_requested_ports: args.allow_requested_ports,
        random_subdomain_seed: args.random_subdomain_seed.map(Into::into),
        idle_connection_timeout: args.idle_connection_timeout.into(),
        authentication_request_timeout: args.authentication_request_timeout.into(),
        request_timeout: args.request_timeout.into(),
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
