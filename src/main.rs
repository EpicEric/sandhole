use clap::Parser;
use sandhole::{ApplicationConfig, LogFormat, entrypoint};
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let config = ApplicationConfig::parse();

    let env_filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
        .from_env_lossy();
    let log_layer = match config.log_format {
        LogFormat::Default => tracing_subscriber::fmt::Layer::default()
            .compact()
            .with_timer(tracing_subscriber::fmt::time::ChronoUtc::rfc_3339())
            .with_ansi_sanitization(false)
            .with_filter(env_filter)
            .boxed(),
        #[cfg(feature = "duper")]
        LogFormat::Duper => tracing_duper::DuperLayer::new()
            .with_filter(env_filter)
            .boxed(),
        LogFormat::Json => tracing_subscriber::fmt::Layer::default()
            .json()
            .with_filter(env_filter)
            .boxed(),
    };

    tracing_subscriber::registry()
        .with(log_layer)
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
