use std::{
    net::{IpAddr, Ipv6Addr},
    num::NonZero,
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

use clap::{Parser, ValueEnum};
use color_eyre::eyre::{Context, eyre};
use ipnet::IpNet;
use rustls_pki_types::DnsName;

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
pub enum LoadBalancingStrategy {
    /// Load-balance with all available handlers.
    Allow,
    /// Don't load-balance; When adding a new handler, replace the existing one.
    Replace,
    /// Don't load-balance; Deny the new handler if there's an existing one.
    Deny,
}

// Algorithm to use for service selection when load-balancing.
#[doc(hidden)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum LoadBalancingAlgorithm {
    /// Choose randomly.
    Random,
    /// Round robin.
    RoundRobin,
    /// Choose based on IP hash.
    IpHash,
}

// CLI configuration for Sandhole.
#[doc(hidden)]
#[derive(Debug, Parser, PartialEq)]
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
    #[cfg(feature = "acme")]
    #[arg(
        long,
        default_value_os = "./deploy/acme_cache/",
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
        default_value_t = IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        value_name = "ADDRESS"
    )]
    pub listen_address: IpAddr,

    /// Port to listen for SSH connections.
    #[arg(long, default_value_t = NonZero::new(2222).unwrap(), value_name = "PORT")]
    pub ssh_port: NonZero<u16>,

    /// Port to listen for HTTP connections.
    #[arg(long, default_value_t = NonZero::new(80).unwrap(), value_name = "PORT")]
    pub http_port: NonZero<u16>,

    /// Port to listen for HTTPS connections.
    #[arg(long, default_value_t = NonZero::new(443).unwrap(), value_name = "PORT")]
    pub https_port: NonZero<u16>,

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
    #[cfg(feature = "acme")]
    #[arg(long, value_name = "EMAIL")]
    pub acme_contact_email: Option<String>,

    /// Controls whether to use the staging directory for Let's Encrypt certificates (default is production).
    /// Only set this option for testing.
    #[cfg(feature = "acme")]
    #[arg(long, default_value_t = false)]
    pub acme_use_staging: bool,

    /// If set, defines a URL which password authentication requests will be validated against.
    /// This is done by sending the following JSON payload via a POST request:
    ///
    /// {"user": "...", "password": "...", "remote_address": "..."}
    ///
    /// Any 2xx response indicates that the credentials are authorized.
    #[cfg(feature = "login")]
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
        default_value_t = LoadBalancingStrategy::Allow,
        value_name = "STRATEGY"
    )]
    pub load_balancing: LoadBalancingStrategy,

    /// Algorithm to use for service selection when load-balancing.
    ///
    /// By default, traffic will be randomly distributed between services.
    #[arg(
        long,
        value_enum,
        default_value_t = LoadBalancingAlgorithm::Random,
        value_name = "ALGORITHM"
    )]
    pub load_balancing_algorithm: LoadBalancingAlgorithm,

    /// Prefix for TXT DNS records containing key fingerprints, for authorization to bind under a specific domain.
    ///
    /// In other words, valid records will be of the form:
    ///
    /// TXT <PREFIX>.<DOMAIN> SHA256:...
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

    /// Disable all HTTPS tunneling. By default, this is enabled globally.
    #[arg(long, default_value_t = false)]
    pub disable_https: bool,

    /// Disable SNI proxy tunneling. By default, this is enabled globally.
    #[arg(long, default_value_t = false)]
    pub disable_sni: bool,

    /// Disable all TCP port tunneling except HTTP. By default, this is enabled globally.
    #[arg(long, default_value_t = false)]
    pub disable_tcp: bool,

    /// Disable all aliasing (i.e. local forwarding). By default, this is enabled globally.
    #[arg(long, default_value_t = false)]
    pub disable_aliasing: bool,

    /// Disable the admin-only alias for the Prometheus exporter. By default, it is enabled.
    #[cfg(feature = "prometheus")]
    #[arg(long, default_value_t = false)]
    pub disable_prometheus: bool,

    /// How many services can be exposed for a single user at once. Doesn't apply to admin users.
    ///
    /// Each user is distinguished by their key fingerprint or, in the case of API logins, by their username.
    ///
    /// By default, no limit is set.
    #[arg(long, value_name = "MAX")]
    pub quota_per_user: Option<NonZero<u16>>,

    /// How many bytes per second a single user's services can transmit at once. Doesn't apply to admin users.
    ///
    /// Each user is distinguished by their key fingerprint or, in the case of API logins, by their username.
    ///
    /// By default, no rate limit is set. For better results, this should be a multiple of `--buffer-size`.
    #[arg(long, value_name = "RATE", value_parser = validate_byte_size_usize)]
    pub rate_limit_per_user: Option<usize>,

    /// Set a value for random subdomains for use in conjunction with `--random-subdomain-seed` to allow binding to
    /// the same random address between Sandhole restarts.
    ///
    /// Beware that this can lead to collisions if misused!
    ///
    /// If unset, defaults to a random value.
    #[arg(long, value_name = "VALUE")]
    pub random_subdomain_value: Option<u64>,

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

    /// Prevents random subdomains from containing profanities.
    #[cfg(feature = "rustrict")]
    #[arg(long, default_value_t = false)]
    pub random_subdomain_filter_profanities: bool,

    /// Prevents user-requested domains from containing profanities.
    ///
    /// Beware that this can lead to false positives being blocked!
    #[cfg(feature = "rustrict")]
    #[arg(long, default_value_t = false)]
    pub requested_domain_filter_profanities: bool,

    /// Prevents user-requested subdomains from containing profanities.
    ///
    /// Beware that this can lead to false positives being blocked!
    #[cfg(feature = "rustrict")]
    #[arg(long, default_value_t = false)]
    pub requested_subdomain_filter_profanities: bool,

    /// Comma-separated list of IP networks to allow.
    /// Setting this will block unknown IPs from connecting.
    #[arg(long, value_delimiter = ',', value_name = "CIDR")]
    pub ip_allowlist: Option<Vec<IpNet>>,

    /// Comma-separated list of IP networks to block.
    /// Setting this will allow unknown IPs to connect, unless --ip-allowlist is set.
    #[arg(long, value_delimiter = ',', value_name = "CIDR")]
    pub ip_blocklist: Option<Vec<IpNet>>,

    /// Size to use for bidirectional buffers.
    ///
    /// A higher value will lead to higher memory consumption.
    #[arg(
        long,
        default_value = "32768B",
        value_parser = validate_byte_size_u32,
        value_name = "SIZE"
    )]
    pub buffer_size: u32,

    /// How long to wait between each keepalive message that is sent to an unresponsive SSH connection.
    #[arg(long, default_value = "15s", value_parser = validate_duration, value_name = "DURATION")]
    pub ssh_keepalive_interval: Duration,

    /// How many keepalive messages are sent to an unresponsive SSH connection before it is dropped.
    ///
    /// A value of zero disables timeouts.
    ///
    /// The timeout is equal to this value plus one, times `--ssh-keepalive-interval`.
    #[arg(long, default_value_t = 3, value_name = "VALUE")]
    pub ssh_keepalive_max: usize,

    /// Grace period for dangling/unauthenticated connections before they are forcefully disconnected.
    ///
    /// A low value may cause valid connections to be erroneously removed.
    #[arg(
        long,
        default_value = "2s",
        value_parser = validate_duration,
        value_name = "DURATION"
    )]
    pub idle_connection_timeout: Duration,

    /// Grace period for unauthenticated SSH connections after closing the last proxy tunnel before they are forcefully disconnected.
    ///
    /// A low value may cause valid proxy/tunnel connections to be erroneously removed.
    ///
    /// If unset, this defaults to the value set by --idle-connection-timeout
    #[arg(long, value_parser = validate_duration, value_name = "DURATION")]
    pub unproxied_connection_timeout: Option<Duration>,

    /// Time until a user+password authentication request is canceled.
    /// Any timed out requests will not authenticate the user.
    #[cfg(feature = "login")]
    #[arg(
        long,
        default_value = "5s",
        value_parser = validate_duration,
        value_name = "DURATION"
    )]
    pub authentication_request_timeout: Duration,

    /// Time until an outgoing HTTP request is automatically canceled.
    ///
    /// By default, outgoing requests are not terminated by Sandhole.
    #[arg(long, value_parser = validate_duration, value_name = "DURATION")]
    pub http_request_timeout: Option<Duration>,

    /// How long until TCP connections (including Websockets and local forwardings) are automatically garbage-collected.
    ///
    /// By default, these connections are not terminated by Sandhole.
    #[arg(long, value_parser = validate_duration, value_name = "DURATION")]
    pub tcp_connection_timeout: Option<Duration>,
}

fn validate_domain(value: &str) -> color_eyre::Result<String> {
    DnsName::try_from(value).with_context(|| "invalid domain")?;
    Ok(value.to_string())
}

fn validate_txt_record_prefix(value: &str) -> color_eyre::Result<String> {
    DnsName::try_from(value).with_context(|| "invalid prefix")?;
    if value.find('.').is_some() {
        Err(eyre!("prefix cannot contain period"))
    } else {
        Ok(value.to_string())
    }
}

fn validate_duration(value: &str) -> color_eyre::Result<Duration> {
    Ok(humantime::Duration::from_str(value)
        .with_context(|| "invalid duration")?
        .into())
}

fn validate_byte_size_usize(value: &str) -> color_eyre::Result<usize> {
    bytesize::ByteSize::from_str(value)
        .map_err(|s| eyre!("invalid byte size {s}"))?
        .as_u64()
        .try_into()
        .with_context(|| "cannot convert to usize")
}

fn validate_byte_size_u32(value: &str) -> color_eyre::Result<u32> {
    bytesize::ByteSize::from_str(value)
        .map_err(|s| eyre!("invalid byte size {s}"))?
        .as_u64()
        .try_into()
        .with_context(|| "cannot convert to u32")
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod application_config_tests {
    use std::{str::FromStr, time::Duration};

    use clap::Parser;
    use ipnet::IpNet;

    use crate::config::LoadBalancingAlgorithm;

    use super::{ApplicationConfig, BindHostnames, LoadBalancingStrategy, RandomSubdomainSeed};

    #[test_log::test]
    fn parses_minimal_args() {
        let config = ApplicationConfig::parse_from(["sandhole", "--domain=foobar.tld"]);
        assert_eq!(
            config,
            ApplicationConfig {
                domain: "foobar.tld".into(),
                domain_redirect: "https://github.com/EpicEric/sandhole".into(),
                user_keys_directory: "./deploy/user_keys/".into(),
                admin_keys_directory: "./deploy/admin_keys/".into(),
                certificates_directory: "./deploy/certificates/".into(),
                acme_cache_directory: "./deploy/acme_cache/".into(),
                private_key_file: "./deploy/server_keys/ssh".into(),
                disable_directory_creation: false,
                listen_address: "::".parse().unwrap(),
                ssh_port: 2222.try_into().unwrap(),
                http_port: 80.try_into().unwrap(),
                https_port: 443.try_into().unwrap(),
                connect_ssh_on_https_port: false,
                force_https: false,
                disable_http_logs: false,
                disable_tcp_logs: false,
                acme_contact_email: None,
                acme_use_staging: false,
                password_authentication_url: None,
                bind_hostnames: BindHostnames::Txt,
                load_balancing: LoadBalancingStrategy::Allow,
                load_balancing_algorithm: LoadBalancingAlgorithm::Random,
                txt_record_prefix: "_sandhole".into(),
                allow_requested_subdomains: false,
                allow_requested_ports: false,
                disable_http: false,
                disable_https: false,
                disable_sni: false,
                disable_tcp: false,
                disable_aliasing: false,
                disable_prometheus: false,
                quota_per_user: None,
                rate_limit_per_user: None,
                random_subdomain_value: None,
                random_subdomain_seed: None,
                random_subdomain_length: 6.try_into().unwrap(),
                random_subdomain_filter_profanities: false,
                requested_domain_filter_profanities: false,
                requested_subdomain_filter_profanities: false,
                ip_allowlist: None,
                ip_blocklist: None,
                buffer_size: 32_768,
                ssh_keepalive_interval: Duration::from_secs(15),
                ssh_keepalive_max: 3,
                idle_connection_timeout: Duration::from_secs(2),
                unproxied_connection_timeout: None,
                authentication_request_timeout: Duration::from_secs(5),
                http_request_timeout: None,
                tcp_connection_timeout: None
            }
        )
    }

    #[test_log::test]
    fn parses_full_args() {
        let config = ApplicationConfig::parse_from([
            "sandhole",
            "--domain=server.com",
            "--domain-redirect=https://sandhole.eric.dev.br",
            "--user-keys-directory=/etc/user_keys/",
            "--admin-keys-directory=/etc/admin_keys/",
            "--certificates-directory=/etc/certificates/",
            "--acme-cache-directory=/etc/acme_cache/",
            "--private-key-file=/etc/private_key.pem",
            "--disable-directory-creation",
            "--listen-address=127.0.0.1",
            "--ssh-port=18022",
            "--http-port=18080",
            "--https-port=18443",
            "--connect-ssh-on-https-port",
            "--force-https",
            "--disable-http-logs",
            "--disable-tcp-logs",
            "--acme-contact-email=admin@server.com",
            "--acme-use-staging",
            "--password-authentication-url=https://auth.server.com/validate",
            "--bind-hostnames=cname",
            "--load-balancing=replace",
            "--load-balancing-algorithm=ip-hash",
            "--txt-record-prefix=_prefix",
            "--allow-requested-subdomains",
            "--allow-requested-ports",
            "--disable-http",
            "--disable-https",
            "--disable-sni",
            "--disable-tcp",
            "--disable-aliasing",
            "--disable-prometheus",
            "--quota-per-user=10",
            "--rate-limit-per-user=1MB",
            "--random-subdomain-value=1337",
            "--random-subdomain-seed=ip-and-user",
            "--random-subdomain-length=8",
            "--random-subdomain-filter-profanities",
            "--requested-domain-filter-profanities",
            "--requested-subdomain-filter-profanities",
            "--ip-allowlist=10.0.0.0/8",
            "--ip-blocklist=10.1.0.0/16,10.2.0.0/16",
            "--buffer-size=4KB",
            "--ssh-keepalive-interval=10s",
            "--ssh-keepalive-max=2",
            "--idle-connection-timeout=3s",
            "--unproxied-connection-timeout=4s",
            "--authentication-request-timeout=6s",
            "--http-request-timeout=15s",
            "--tcp-connection-timeout=30s",
        ]);
        assert_eq!(
            config,
            ApplicationConfig {
                domain: "server.com".into(),
                domain_redirect: "https://sandhole.eric.dev.br".into(),
                user_keys_directory: "/etc/user_keys/".into(),
                admin_keys_directory: "/etc/admin_keys/".into(),
                certificates_directory: "/etc/certificates/".into(),
                acme_cache_directory: "/etc/acme_cache/".into(),
                private_key_file: "/etc/private_key.pem".into(),
                disable_directory_creation: true,
                listen_address: "127.0.0.1".parse().unwrap(),
                ssh_port: 18022.try_into().unwrap(),
                http_port: 18080.try_into().unwrap(),
                https_port: 18443.try_into().unwrap(),
                connect_ssh_on_https_port: true,
                force_https: true,
                disable_http_logs: true,
                disable_tcp_logs: true,
                acme_contact_email: Some("admin@server.com".into()),
                acme_use_staging: true,
                password_authentication_url: Some("https://auth.server.com/validate".into()),
                bind_hostnames: BindHostnames::Cname,
                load_balancing: LoadBalancingStrategy::Replace,
                load_balancing_algorithm: LoadBalancingAlgorithm::IpHash,
                txt_record_prefix: "_prefix".into(),
                allow_requested_subdomains: true,
                allow_requested_ports: true,
                disable_http: true,
                disable_https: true,
                disable_sni: true,
                disable_tcp: true,
                disable_aliasing: true,
                disable_prometheus: true,
                quota_per_user: Some(10.try_into().unwrap()),
                rate_limit_per_user: Some(1_000_000),
                random_subdomain_value: Some(1337),
                random_subdomain_seed: Some(RandomSubdomainSeed::IpAndUser),
                random_subdomain_length: 8.try_into().unwrap(),
                random_subdomain_filter_profanities: true,
                requested_domain_filter_profanities: true,
                requested_subdomain_filter_profanities: true,
                ip_allowlist: Some(vec![IpNet::from_str("10.0.0.0/8").unwrap()]),
                ip_blocklist: Some(vec![
                    IpNet::from_str("10.1.0.0/16").unwrap(),
                    IpNet::from_str("10.2.0.0/16").unwrap()
                ]),
                buffer_size: 4_000,
                ssh_keepalive_interval: Duration::from_secs(10),
                ssh_keepalive_max: 2,
                idle_connection_timeout: Duration::from_secs(3),
                unproxied_connection_timeout: Some(Duration::from_secs(4)),
                authentication_request_timeout: Duration::from_secs(6),
                http_request_timeout: Some(Duration::from_secs(15)),
                tcp_connection_timeout: Some(Duration::from_secs(30))
            }
        )
    }

    #[test_log::test]
    #[should_panic(expected = "invalid dns name")]
    fn fails_to_parse_if_invalid_domain() {
        ApplicationConfig::try_parse_from(["sandhole", "--domain=.foobar.tld"]).unwrap();
    }

    #[test_log::test]
    #[should_panic(expected = "prefix cannot contain period")]
    fn fails_to_parse_if_invalid_txt_record_prefix() {
        ApplicationConfig::try_parse_from([
            "sandhole",
            "--domain=foobar.tld",
            "--txt-record-prefix=hello.world",
        ])
        .unwrap();
    }

    #[test_log::test]
    #[should_panic(expected = "time unit needed, for example 42sec or 42ms")]
    fn fails_to_parse_if_invalid_duration() {
        ApplicationConfig::try_parse_from([
            "sandhole",
            "--domain=foobar.tld",
            "--idle-connection-timeout=42",
        ])
        .unwrap();
    }

    #[test_log::test]
    #[should_panic(expected = "couldn't parse \"abc\" into a ByteSize")]
    fn fails_to_parse_if_invalid_byte_size() {
        ApplicationConfig::try_parse_from(["sandhole", "--domain=foobar.tld", "--buffer-size=abc"])
            .unwrap();
    }
}
