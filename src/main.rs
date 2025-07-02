use clap::Parser;
use sandhole::{ApplicationConfig, entrypoint};
use tracing::error;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with(
            tracing_subscriber::fmt::Layer::default()
                .compact()
                .with_timer(tracing_subscriber::fmt::time::ChronoUtc::rfc_3339()),
        )
        .with(tracing_error::ErrorLayer::default())
        .init();
    color_eyre::install()?;
    let config = ApplicationConfig::parse();
    if let Err(error) = entrypoint(config).await {
        error!(%error, "Unable to start Sandhole.");
        Err(error)
    } else {
        Ok(())
    }
}
