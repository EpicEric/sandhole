// sandhole: Expose HTTP/SSH/TCP services through SSH port forwarding
// Copyright (C) 2024-2026 Eric Rodrigues Pires
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for
// more details.
//
// You should have received a copy of the GNU Affero General Public License along
// with this program. If not, see <https://www.gnu.org/licenses/>.

use clap::{CommandFactory, Parser};
use sandhole::{ApplicationConfig, LogFormat, entrypoint};
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let config = ApplicationConfig::parse();

    if let Some(shell) = config.mode.completions {
        clap_complete::generate(
            shell,
            &mut ApplicationConfig::command(),
            env!("CARGO_BIN_NAME"),
            &mut std::io::stdout(),
        );
        return Ok(());
    }

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
