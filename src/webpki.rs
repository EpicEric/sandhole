use std::sync::Arc;

use color_eyre::eyre::eyre;
use rustls::{ClientConfig, RootCertStore, client::WebPkiServerVerifier, crypto::CryptoProvider};
use webpki_roots::TLS_SERVER_ROOTS;

// Trait for TLS configuration setup.
#[cfg_attr(test, mockall::automock)]
pub(crate) trait Configurer {
    // Returns the TLS client configuration.
    fn get_client_config(
        &self,
        provider: CryptoProvider,
        use_system_ca: bool,
    ) -> color_eyre::Result<ClientConfig>;
}

pub(crate) struct WebpkiVerifierConfigurer;

impl Configurer for WebpkiVerifierConfigurer {
    // Returns the CA certificate chain from the operating system.
    fn get_client_config(
        &self,
        provider: CryptoProvider,
        use_system_ca: bool,
    ) -> color_eyre::Result<ClientConfig> {
        let mut store = RootCertStore::empty();
        if use_system_ca {
            let native = rustls_native_certs::load_native_certs();
            if !native.errors.is_empty() {
                let errors = native
                    .errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(eyre!("unable to load system CA certificates: {errors}"));
            }
            let (added, ignored) = store.add_parsable_certificates(native.certs);
            if added == 0 {
                return Err(eyre!("no system CA certificates were loaded"));
            }
            if ignored != 0 {
                tracing::warn!(ignored, "Ignored unparsable system CA certificates.");
            }
        } else {
            store.extend(TLS_SERVER_ROOTS.iter().map(|ta| ta.to_owned()));
        };
        Ok(ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()?
            .with_webpki_verifier(WebPkiServerVerifier::builder(Arc::new(store)).build()?)
            .with_no_client_auth())
    }
}
