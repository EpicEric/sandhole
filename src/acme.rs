use std::{path::PathBuf, sync::Arc};

use log::{info, warn};
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
    ServerConfig,
};
use rustls_acme::{caches::DirCache, AcmeConfig, ResolvesServerCertAcme};
use tokio_stream::StreamExt;

use crate::{certificates::AlpnChallengeResolver, droppable_handle::DroppableHandle};

#[derive(Debug)]
pub(crate) struct AcmeResolver {
    cache_dir: PathBuf,
    contact: String,
    use_staging: bool,
    join_handle: Option<DroppableHandle<()>>,
    config: Option<Arc<ServerConfig>>,
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
        if domains.is_empty() {
            return;
        }
        self.join_handle.take();
        info!(
            "Generating ACME certificates for the following domains: {:?}",
            &domains
        );
        let mut new_state = AcmeConfig::new(domains)
            .contact_push(format!("mailto:{}", self.contact))
            .cache(DirCache::new(self.cache_dir.clone()))
            .directory_lets_encrypt(!self.use_staging)
            .state();
        self.config = Some(new_state.challenge_rustls_config());
        self.resolver = Some(new_state.resolver());
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

    fn challenge_rustls_config(&self) -> Option<Arc<ServerConfig>> {
        self.config.clone()
    }
}
