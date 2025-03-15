use clap::Parser;
use sandhole::{ApplicationConfig, entrypoint};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let config = ApplicationConfig::parse();
    entrypoint(config).await
}
