use std::path::PathBuf;

use clap::{command, Parser};
use sandhole::{entrypoint, ApplicationConfig, CONFIG};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    private_key_file: Option<PathBuf>,

    #[arg(long)]
    private_key_password: Option<String>,

    #[arg(long)]
    listen_address: Option<String>,

    #[arg(long, default_value_t = 2222)]
    ssh_port: u16,

    #[arg(long, default_value_t = 80)]
    http_port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let address = args.listen_address.unwrap_or_else(|| "0.0.0.0".into());
    let private_key_location = args
        .private_key_file
        .unwrap_or_else(|| PathBuf::from("./deploy/keys/ssh_key"));
    CONFIG
        .set(ApplicationConfig {
            private_key_file: private_key_location,
            private_key_password: args.private_key_password,
            listen_address: address,
            ssh_port: args.ssh_port,
            http_port: args.http_port,
        })
        .unwrap();
    entrypoint().await
}
