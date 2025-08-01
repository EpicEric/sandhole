use clap::Parser;
use sandhole::{ApplicationConfig, entrypoint};
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let config = ApplicationConfig::parse();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::Layer::default()
                .compact()
                .with_timer(tracing_subscriber::fmt::time::ChronoUtc::rfc_3339())
                .with_filter(
                    tracing_subscriber::EnvFilter::builder()
                        .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
                        .from_env_lossy(),
                ),
        )
        .with(tracing_error::ErrorLayer::default())
        .try_init()?;

    if let Err(error) = entrypoint(config).await {
        #[cfg(not(coverage_nightly))]
        tracing::error!(%error, "Unable to start Sandhole.");
        Err(error)
    } else {
        Ok(())
    }
}
