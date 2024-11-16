use std::path::PathBuf;

use clap::{command, Parser, ValueEnum};
use sandhole::{
    config::{ApplicationConfig, RandomSubdomainSeed as Seed, CONFIG},
    entrypoint,
};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum RandomSubdomainSeed {
    /// From SSH user.
    User,
    /// From SSH key fingerprint.
    Fingerprint,
    /// From SSH connection socket (address + port).
    Address,
}

impl From<RandomSubdomainSeed> for Seed {
    fn from(value: RandomSubdomainSeed) -> Self {
        match value {
            RandomSubdomainSeed::User => Seed::User,
            RandomSubdomainSeed::Fingerprint => Seed::KeyFingerprint,
            RandomSubdomainSeed::Address => Seed::SocketAddress,
        }
    }
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// The root domain of the application.
    #[arg(long)]
    domain: String,

    /// Directory containing authorized public keys.
    #[arg(long, default_value_os = "./deploy/public_keys/")]
    public_keys_directory: PathBuf,

    /// Directory containing SSL certificates and keys.
    /// Each sub-directory inside of this one must contain a certificate in a
    /// `fullchain.pem` file and its private key in a `privkey.pem` file.
    #[arg(long, default_value_os = "./deploy/certificates/")]
    certificates_directory: PathBuf,

    /// File path to the server's secret key.
    #[arg(long, default_value_os = "./deploy/server_keys/ssh_key")]
    private_key_file: PathBuf,

    /// Password to use for the server's secret key, if any.
    #[arg(long)]
    private_key_password: Option<String>,

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

    /// Allow binding any HTTP host, without checking DNS records.
    #[arg(long, default_value_t = false)]
    bind_any_host: bool,

    /// Use random subdomains instead of user-provided ones.
    #[arg(long, default_value_t = true)]
    force_random_subdomains: bool,

    /// Which value to seed with when generating random subdomains, for determinism. This allows binding to the same
    /// random address, as long as Sandhole isn't restarted, but can lead to collisions if misused.
    ///
    /// If unset, defaults to a random seed.
    #[arg(long, value_enum)]
    random_subdomain_seed: Option<RandomSubdomainSeed>,

    /// Prefix for TXT DNS records containing key fingerprints, for authorization to bind under a specific domain.
    /// In other words, valid records will be of the form: `TXT PREFIX.CUSTOM_DOMAIN SHA256:...`
    #[arg(long, default_value_t = String::from("_sandhole"))]
    txt_record_prefix: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    CONFIG
        .set(ApplicationConfig {
            domain: args.domain,
            public_keys_directory: args.public_keys_directory,
            certificates_directory: args.certificates_directory,
            private_key_file: args.private_key_file,
            private_key_password: args.private_key_password,
            listen_address: args.listen_address,
            ssh_port: args.ssh_port,
            http_port: args.http_port,
            https_port: args.https_port,
            bind_any_host: args.bind_any_host,
            force_random_subdomains: args.force_random_subdomains,
            random_subdomain_seed: args.random_subdomain_seed.map(Into::into),
            txt_record_prefix: args.txt_record_prefix,
        })
        .unwrap();
    entrypoint().await
}
