use std::{num::NonZero, path::PathBuf};

use clap::{command, Parser, ValueEnum};
use humantime::Duration;
use sandhole::{
    entrypoint, ApplicationConfig, BindHostnames as BHConfig, LoadBalancing as LBConfig,
    RandomSubdomainSeed as RSSConfig,
};
use webpki::types::DnsName;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum RandomSubdomainSeed {
    /// From IP address, SSH user, and requested address. Recommended if unsure
    IpAndUser,
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
            RandomSubdomainSeed::IpAndUser => RSSConfig::IpAndUser,
            RandomSubdomainSeed::Fingerprint => RSSConfig::KeyFingerprint,
            RandomSubdomainSeed::Address => RSSConfig::SocketAddress,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum BindHostnames {
    /// Allow any hostnames unconditionally, including the main domain.
    All,
    /// Allow any hostnames with a CNAME record pointing to the main domain.
    Cname,
    /// Allow any hostnames with a TXT record containing a fingerprint, including the main domain.
    Txt,
    /// Don't allow user-provided hostnames, enforce subdomains.
    None,
}

impl From<BindHostnames> for BHConfig {
    fn from(value: BindHostnames) -> Self {
        match value {
            BindHostnames::All => BHConfig::All,
            BindHostnames::Cname => BHConfig::Cname,
            BindHostnames::Txt => BHConfig::Txt,
            BindHostnames::None => BHConfig::None,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum LoadBalancing {
    /// Load-balance with all available handlers.
    Allow,
    /// Don't load-balance; When adding a new handler, replace the existing one.
    Replace,
    /// Don't load-balance; Deny the new handler if there's an existing one.
    Deny,
}

impl From<LoadBalancing> for LBConfig {
    fn from(value: LoadBalancing) -> Self {
        match value {
            LoadBalancing::Allow => LBConfig::Allow,
            LoadBalancing::Replace => LBConfig::Replace,
            LoadBalancing::Deny => LBConfig::Deny,
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
    #[arg(long, default_value_t = String::from(env!("CARGO_PKG_REPOSITORY")), value_name = "URL")]
    domain_redirect: String,

    /// Directory containing public keys of authorized users.
    /// Each file must contain at least one key.
    #[arg(
        long,
        default_value_os = "./deploy/user_keys/",
        value_name = "DIRECTORY"
    )]
    user_keys_directory: PathBuf,

    /// Directory containing public keys of admin users.
    /// Each file must contain at least one key.
    #[arg(
        long,
        default_value_os = "./deploy/admin_keys/",
        value_name = "DIRECTORY"
    )]
    admin_keys_directory: PathBuf,

    /// Directory containing SSL certificates and keys.
    /// Each sub-directory inside of this one must contain a certificate chain in a
    /// fullchain.pem file and its private key in a privkey.pem file.
    #[arg(
        long,
        default_value_os = "./deploy/certificates/",
        value_name = "DIRECTORY"
    )]
    certificates_directory: PathBuf,

    /// Directory to use as a cache for Let's Encrypt's account and certificates.
    /// This will automatically be created for you.
    ///
    /// Note that this setting ignores the --disable-directory-creation flag.
    #[arg(
        long,
        default_value_os = "./deploy/acme_cache",
        value_name = "DIRECTORY"
    )]
    acme_cache_directory: PathBuf,

    /// File path to the server's secret key. If missing, it will be created for you.
    #[arg(
        long,
        default_value_os = "./deploy/server_keys/ssh",
        value_name = "FILE"
    )]
    private_key_file: PathBuf,

    /// If set, disables automatic creation of the directories expected by the application.
    /// This may result in application errors if the directories are missing.
    #[arg(long, default_value_t = false)]
    disable_directory_creation: bool,

    /// Address to listen for all client connections.
    #[arg(long, default_value_t = String::from("::"), value_name = "ADDRESS")]
    listen_address: String,

    /// Port to listen for SSH connections.
    #[arg(long, default_value_t = 2222, value_parser = validate_port, value_name = "PORT")]
    ssh_port: u16,

    /// Port to listen for HTTP connections.
    #[arg(long, default_value_t = 80, value_parser = validate_port, value_name = "PORT")]
    http_port: u16,

    /// Port to listen for HTTPS connections.
    #[arg(long, default_value_t = 443, value_parser = validate_port, value_name = "PORT")]
    https_port: u16,

    /// Always redirect HTTP requests to HTTPS.
    #[arg(long, default_value_t = false)]
    force_https: bool,

    /// Disable sending HTTP logs to clients.
    #[arg(long, default_value_t = false)]
    disable_http_logs: bool,

    /// Disable sending TCP/proxy logs to clients.
    #[arg(long, default_value_t = false)]
    disable_tcp_logs: bool,

    /// Contact e-mail to use with Let's Encrypt. If set, enables ACME for HTTPS certificates.
    ///
    /// By providing your e-mail, you agree to the Let's Encrypt Subscriber Agreement.
    #[arg(long, value_name = "EMAIL")]
    acme_contact_email: Option<String>,

    /// Controls whether to use the staging directory for Let's Encrypt certificates (default is production).
    /// Only set this option for testing.
    #[arg(long, default_value_t = false)]
    acme_use_staging: bool,

    /// If set, defines a URL against which password authentication requests will
    /// be validated. This is done by sending the following JSON payload:
    ///
    /// {"user": "...", "password": "...", "remote_address": "..."}
    ///
    /// Any 2xx response indicates that the credentials are authorized.
    #[arg(long, value_name = "URL")]
    password_authentication_url: Option<String>,

    /// Policy on whether to allow binding specific hostnames.
    ///
    /// Beware that this can lead to domain takeovers if misused!
    #[arg(long, value_enum, default_value_t = BindHostnames::Txt, value_name = "POLICY")]
    bind_hostnames: BindHostnames,

    /// Strategy for load-balancing when multiple services request the same hostname/port.
    ///
    /// By default, traffic towards matching hostnames/ports will be load-balanced.
    #[arg(long, value_enum, default_value_t = LoadBalancing::Allow, value_name = "STRATEGY")]
    load_balancing: LoadBalancing,

    /// Prefix for TXT DNS records containing key fingerprints, for authorization to bind under a specific domain.
    ///
    /// In other words, valid records will be of the form:
    ///
    /// TXT prefix.custom-domain SHA256:...
    #[arg(long, default_value_t = String::from("_sandhole"), value_parser = validate_txt_record_prefix, value_name = "PREFIX")]
    txt_record_prefix: String,

    /// Allow user-provided subdomains. By default, subdomains are always random.
    #[arg(long, default_value_t = false)]
    allow_provided_subdomains: bool,

    /// Allow user-requested ports. By default, ports are always random.
    #[arg(long, default_value_t = false)]
    allow_requested_ports: bool,

    /// How many services can be exposed for a single user at once. Doesn't apply to admin users.
    ///
    /// Each user is distinguished by their key fingerprint or, in the case of API logins, by their username.
    ///
    /// By default, no limit is set.
    #[arg(long, value_name = "MAX")]
    quota_per_user: Option<NonZero<usize>>,

    /// Which value to seed with when generating random subdomains, for determinism. This allows binding to the same
    /// random address until Sandhole is restarted.
    ///
    /// Beware that this can lead to collisions if misused!
    ///
    /// If unset, defaults to a random seed.
    #[arg(long, value_enum, value_name = "SEED")]
    random_subdomain_seed: Option<RandomSubdomainSeed>,

    /// Grace period for dangling/unauthenticated SSH connections before they are forcefully disconnected.
    ///
    /// A low value may cause valid proxy/tunnel connections to be erroneously removed.
    #[arg(long, default_value = "2s", value_name = "DURATION")]
    idle_connection_timeout: Duration,

    /// Time until a user+password authentication request is canceled.
    /// Any timed out requests will not authenticate the user.
    #[arg(long, default_value = "5s", value_name = "DURATION")]
    authentication_request_timeout: Duration,

    /// Time until an outgoing HTTP request is automatically canceled.
    #[arg(long, default_value = "10s", value_name = "DURATION")]
    http_request_timeout: Duration,

    /// How long until TCP connections (including Websockets) are automatically garbage-collected.
    ///
    /// By default, these connections are not terminated by Sandhole.
    #[arg(long, value_name = "DURATION")]
    tcp_connection_timeout: Option<Duration>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();
    let config = ApplicationConfig {
        domain: args.domain,
        domain_redirect: args.domain_redirect,
        user_keys_directory: args.user_keys_directory,
        admin_keys_directory: args.admin_keys_directory,
        certificates_directory: args.certificates_directory,
        acme_cache_directory: args.acme_cache_directory,
        private_key_file: args.private_key_file,
        disable_directory_creation: args.disable_directory_creation,
        listen_address: args.listen_address,
        ssh_port: args.ssh_port,
        http_port: args.http_port,
        https_port: args.https_port,
        force_https: args.force_https,
        disable_http_logs: args.disable_http_logs,
        disable_tcp_logs: args.disable_tcp_logs,
        acme_contact_email: args.acme_contact_email,
        acme_use_staging: args.acme_use_staging,
        password_authentication_url: args.password_authentication_url,
        bind_hostnames: args.bind_hostnames.into(),
        load_balancing: args.load_balancing.into(),
        txt_record_prefix: args.txt_record_prefix,
        allow_provided_subdomains: args.allow_provided_subdomains,
        allow_requested_ports: args.allow_requested_ports,
        quota_per_user: args.quota_per_user,
        random_subdomain_seed: args.random_subdomain_seed.map(Into::into),
        idle_connection_timeout: args.idle_connection_timeout.into(),
        authentication_request_timeout: args.authentication_request_timeout.into(),
        http_request_timeout: args.http_request_timeout.into(),
        tcp_connection_timeout: args.tcp_connection_timeout.map(Into::into),
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

fn validate_port(port: &str) -> Result<u16, String> {
    match port.parse::<u16>() {
        Err(err) => Err(format!("{}", err)),
        Ok(0) => Err("port cannot be zero".into()),
        Ok(port) => Ok(port),
    }
}
