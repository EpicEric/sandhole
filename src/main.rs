use clap::Parser;
use log::error;
use sandhole::{ApplicationConfig, entrypoint};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let config = ApplicationConfig::parse();
    if let Err(err) = entrypoint(config).await {
        error!("Unable to start Sandhole: {err}");
        Err(err)
    } else {
        Ok(())
    }
}
