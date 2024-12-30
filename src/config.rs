use std::{num::NonZero, path::PathBuf};

use clap::{command, Parser, ValueEnum};
use humantime::Duration;
use webpki::types::DnsName;

// Which value to seed with when generating random subdomains, for determinism.
// This allows binding to the same random address until Sandhole is restarted.
#[doc(hidden)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum RandomSubdomainSeed {
    /// From IP address, SSH user, and requested address. Recommended if unsure
    IpAndUser,
    /// From SSH user and requested address.
    User,
    /// From SSH user, key fingerprint, and requested address.
    Fingerprint,
    /// From SSH connection socket (address + port) and requested address.
    Address,
}

// Policy on whether to allow binding specific hostnames.
#[doc(hidden)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum BindHostnames {
    /// Allow any hostnames unconditionally, including the main domain.
    All,
    /// Allow any hostnames with a CNAME record pointing to the main domain.
    Cname,
    /// Allow any hostnames with a TXT record containing a fingerprint, including the main domain.
    Txt,
    /// Don't allow user-provided hostnames, enforce subdomains.
    None,
}

// Strategy for load-balancing when multiple services request the same hostname/port.
#[doc(hidden)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum LoadBalancing {
    /// Load-balance with all available handlers.
    Allow,
    /// Don't load-balance; When adding a new handler, replace the existing one.
    Replace,
    /// Don't load-balance; Deny the new handler if there's an existing one.
    Deny,
}

// CLI configuration for Sandhole.
#[doc(hidden)]
#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
pub struct ApplicationConfig {
    /// The root domain of the application.
    #[arg(
        long,
        value_parser = validate_domain
    )]
    pub domain: String,

    /// Where to redirect requests to the root domain.
    #[arg(
        long,
        default_value_t = String::from(env!("CARGO_PKG_REPOSITORY")),
        value_name = "URL"
    )]
    pub domain_redirect: String,

    /// Directory containing public keys of authorized users.
    /// Each file must contain at least one key.
    #[arg(
        long,
        default_value_os = "./deploy/user_keys/",
        value_name = "DIRECTORY"
    )]
    pub user_keys_directory: PathBuf,

    /// Directory containing public keys of admin users.
    /// Each file must contain at least one key.
    #[arg(
        long,
        default_value_os = "./deploy/admin_keys/",
        value_name = "DIRECTORY"
    )]
    pub admin_keys_directory: PathBuf,

    /// Directory containing SSL certificates and keys.
    /// Each sub-directory inside of this one must contain a certificate chain in a
    /// fullchain.pem file and its private key in a privkey.pem file.
    #[arg(
        long,
        default_value_os = "./deploy/certificates/",
        value_name = "DIRECTORY"
    )]
    pub certificates_directory: PathBuf,

    /// Directory to use as a cache for Let's Encrypt's account and certificates.
    /// This will automatically be created for you.
    ///
    /// Note that this setting ignores the --disable-directory-creation flag.
    #[arg(
        long,
        default_value_os = "./deploy/acme_cache",
        value_name = "DIRECTORY"
    )]
    pub acme_cache_directory: PathBuf,

    /// File path to the server's secret key. If missing, it will be created for you.
    #[arg(
        long,
        default_value_os = "./deploy/server_keys/ssh",
        value_name = "FILE"
    )]
    pub private_key_file: PathBuf,

    /// If set, disables automatic creation of the directories expected by the application.
    /// This may result in application errors if the directories are missing.
    #[arg(long, default_value_t = false)]
    pub disable_directory_creation: bool,

    /// Address to listen for all client connections.
    #[arg(
        long,
        default_value_t = String::from("::"),
        value_name = "ADDRESS"
    )]
    pub listen_address: String,

    /// Port to listen for SSH connections.
    #[arg(
        long,
        default_value_t = 2222,
        value_parser = validate_port,
        value_name = "PORT"
    )]
    pub ssh_port: u16,

    /// Port to listen for HTTP connections.
    #[arg(
        long,
        default_value_t = 80,
        value_parser = validate_port,
        value_name = "PORT"
    )]
    pub http_port: u16,

    /// Port to listen for HTTPS connections.
    #[arg(
        long,
        default_value_t = 443,
        value_parser = validate_port,
        value_name = "PORT"
    )]
    pub https_port: u16,

    /// Allow connecting to SSH via the HTTPS port as well.
    /// This can be useful in networks that block binding to other ports.
    #[arg(long, default_value_t = false)]
    pub connect_ssh_on_https_port: bool,

    /// Always redirect HTTP requests to HTTPS.
    #[arg(long, default_value_t = false)]
    pub force_https: bool,

    /// Disable sending HTTP logs to clients.
    #[arg(long, default_value_t = false)]
    pub disable_http_logs: bool,

    /// Disable sending TCP/proxy logs to clients.
    #[arg(long, default_value_t = false)]
    pub disable_tcp_logs: bool,

    /// Contact e-mail to use with Let's Encrypt. If set, enables ACME for HTTPS certificates.
    ///
    /// By providing your e-mail, you agree to the Let's Encrypt Subscriber Agreement.
    #[arg(long, value_name = "EMAIL")]
    pub acme_contact_email: Option<String>,

    /// Controls whether to use the staging directory for Let's Encrypt certificates (default is production).
    /// Only set this option for testing.
    #[arg(long, default_value_t = false)]
    pub acme_use_staging: bool,

    /// If set, defines a URL which password authentication requests will be validated against.
    /// This is done by sending the following JSON payload via a POST request:
    ///
    /// {"user": "...", "password": "...", "remote_address": "..."}
    ///
    /// Any 2xx response indicates that the credentials are authorized.
    #[arg(long, value_name = "URL")]
    pub password_authentication_url: Option<String>,

    /// Policy on whether to allow binding specific hostnames.
    ///
    /// Beware that this can lead to domain takeovers if misused!
    #[arg(
        long,
        value_enum,
        default_value_t = BindHostnames::Txt,
        value_name = "POLICY"
    )]
    pub bind_hostnames: BindHostnames,

    /// Strategy for load-balancing when multiple services request the same hostname/port.
    ///
    /// By default, traffic towards matching hostnames/ports will be load-balanced.
    #[arg(
        long,
        value_enum,
        default_value_t = LoadBalancing::Allow,
        value_name = "STRATEGY"
    )]
    pub load_balancing: LoadBalancing,

    /// Prefix for TXT DNS records containing key fingerprints, for authorization to bind under a specific domain.
    ///
    /// In other words, valid records will be of the form:
    ///
    /// TXT prefix.custom-domain SHA256:...
    #[arg(
        long,
        default_value_t = String::from("_sandhole"),
        value_parser = validate_txt_record_prefix,
        value_name = "PREFIX"
    )]
    pub txt_record_prefix: String,

    /// Allow user-requested subdomains. By default, subdomains are always random.
    #[arg(long, default_value_t = false)]
    pub allow_requested_subdomains: bool,

    /// Allow user-requested ports. By default, ports are always random.
    #[arg(long, default_value_t = false)]
    pub allow_requested_ports: bool,

    /// Disable all HTTP tunneling. By default, this is enabled globally.
    #[arg(long, default_value_t = false)]
    pub disable_http: bool,

    /// Disable all TCP port tunneling except HTTP. By default, this is enabled globally.
    #[arg(long, default_value_t = false)]
    pub disable_tcp: bool,

    /// Disable all aliasing (i.e. local forwarding). By default, this is enabled globally.
    #[arg(long, default_value_t = false)]
    pub disable_aliasing: bool,

    /// How many services can be exposed for a single user at once. Doesn't apply to admin users.
    ///
    /// Each user is distinguished by their key fingerprint or, in the case of API logins, by their username.
    ///
    /// By default, no limit is set.
    #[arg(long, value_name = "MAX")]
    pub quota_per_user: Option<NonZero<u16>>,

    /// Which value to seed with when generating random subdomains, for determinism. This allows binding to the same
    /// random address until Sandhole is restarted.
    ///
    /// Beware that this can lead to collisions if misused!
    ///
    /// If unset, defaults to a random seed.
    #[arg(long, value_enum, value_name = "SEED")]
    pub random_subdomain_seed: Option<RandomSubdomainSeed>,

    /// The length of the string appended to the start of random subdomains.
    #[arg(
        long,
        value_name = "LENGTH",
        default_value_t = NonZero::new(6).unwrap()
    )]
    pub random_subdomain_length: NonZero<u8>,

    /// Grace period for dangling/unauthenticated SSH connections before they are forcefully disconnected.
    ///
    /// A low value may cause valid proxy/tunnel connections to be erroneously removed.
    #[arg(long, default_value = "2s", value_name = "DURATION")]
    pub idle_connection_timeout: Duration,

    /// Grace period for unauthenticated SSH connections after closing the last proxy tunnel before they are forcefully disconnected.
    ///
    /// A low value may cause valid proxy/tunnel connections to be erroneously removed.
    ///
    /// If unset, this defaults to the value set by --idle-connection-timeout
    #[arg(long, value_name = "DURATION")]
    pub unproxied_connection_timeout: Option<Duration>,

    /// Time until a user+password authentication request is canceled.
    /// Any timed out requests will not authenticate the user.
    #[arg(long, default_value = "5s", value_name = "DURATION")]
    pub authentication_request_timeout: Duration,

    /// Time until an outgoing HTTP request is automatically canceled.
    #[arg(long, default_value = "10s", value_name = "DURATION")]
    pub http_request_timeout: Duration,

    /// How long until TCP connections (including Websockets and local forwardings) are automatically garbage-collected.
    ///
    /// By default, these connections are not terminated by Sandhole.
    #[arg(long, value_name = "DURATION")]
    pub tcp_connection_timeout: Option<Duration>,
}

fn validate_domain(value: &str) -> Result<String, String> {
    DnsName::try_from(value).map_err(|_| "invalid domain")?;
    Ok(value.to_string())
}

fn validate_txt_record_prefix(value: &str) -> Result<String, String> {
    DnsName::try_from(value).map_err(|_| "invalid prefix")?;
    if value.find('.').is_some() {
        Err("prefix cannot contain period".into())
    } else {
        Ok(value.to_string())
    }
}

fn validate_port(value: &str) -> Result<u16, String> {
    match value.parse::<u16>() {
        Err(err) => Err(err.to_string()),
        Ok(0) => Err("port cannot be zero".into()),
        Ok(port) => Ok(port),
    }
}
