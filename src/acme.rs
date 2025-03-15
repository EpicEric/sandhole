use std::{path::PathBuf, sync::Arc};

use log::{info, warn};
use rustls::{
    ServerConfig,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use rustls_acme::{AcmeConfig, ResolvesServerCertAcme, UseChallenge, caches::DirCache};
use tokio_stream::StreamExt;

use crate::{certificates::AlpnChallengeResolver, droppable_handle::DroppableHandle};

// Service that resolves ACME TLS-ALPN-01 challenges and the certificates they generate.
#[derive(Debug)]
pub(crate) struct AcmeResolver {
    // Path where the cache is stored.
    cache_dir: PathBuf,
    // E-mail address for the Let's Encrypt account.
    contact: String,
    // Whether to use the staging server of Let's Encrypt or not.
    use_staging: bool,
    // Task that listens for connections.
    join_handle: Option<DroppableHandle<()>>,
    // Configuration used for TLS-ALPN-01 challenges.
    config: Option<Arc<ServerConfig>>,
    // TLS certificate resolver.
    resolver: Option<Arc<ResolvesServerCertAcme>>,
}

impl AcmeResolver {
    pub(crate) fn new(cache_dir: PathBuf, contact: String, use_staging: bool) -> Self {
        AcmeResolver {
            cache_dir,
            contact,
            use_staging,
            join_handle: None,
            config: None,
            resolver: None,
        }
    }
}

impl AlpnChallengeResolver for AcmeResolver {
    // Handle the new list of domains to manage certificates for with TLS-ALPN-01 challenges.
    fn update_domains(&mut self, domains: Vec<String>) {
        // Clear config variables if the list is empty.
        if domains.is_empty() {
            self.config = None;
            self.resolver = None;
            self.join_handle = None;
            return;
        }
        info!(
            "Generating ACME certificates for the following domains: {:?}",
            &domains
        );
        // Create a new ACME config state.
        let mut new_state = AcmeConfig::new(domains)
            .contact_push(format!("mailto:{}", self.contact))
            .cache(DirCache::new(self.cache_dir.clone()))
            .directory_lets_encrypt(!self.use_staging)
            .challenge_type(UseChallenge::TlsAlpn01)
            .state();
        self.config = Some(new_state.challenge_rustls_config());
        self.resolver = Some(new_state.resolver());
        // Spawn the new background task.
        self.join_handle = Some(DroppableHandle(tokio::spawn(async move {
            loop {
                match new_state.next().await.unwrap() {
                    Ok(_) => (),
                    Err(err) => warn!("ACME listener error: {:?}", err),
                }
            }
        })));
    }

    // Return the appropriate certificate for the given TLS ClientHello.
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.resolver
            .as_ref()
            .and_then(|resolver| resolver.resolve(client_hello))
    }

    // Return the config used for TLS-ALPN-01 challenges.
    fn challenge_rustls_config(&self) -> Option<Arc<ServerConfig>> {
        self.config.clone()
    }
}
