use std::path::PathBuf;

use clap::{command, Parser};
use sandhole::{
    config::{ApplicationConfig, CONFIG},
    entrypoint,
};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    CONFIG
        .set(ApplicationConfig {
            public_keys_directory: args.public_keys_directory,
            certificates_directory: args.certificates_directory,
            private_key_file: args.private_key_file,
            private_key_password: args.private_key_password,
            listen_address: args.listen_address,
            ssh_port: args.ssh_port,
            http_port: args.http_port,
            https_port: args.https_port,
        })
        .unwrap();
    entrypoint().await
}
