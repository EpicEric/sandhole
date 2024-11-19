use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
    ServerConfig,
};
use rustls_acme::{caches::DirCache, AcmeConfig, AcmeState, ResolvesServerCertAcme};

use crate::certificates::AlpnChallengeResolver;

#[derive(Debug)]
pub(crate) struct AcmeResolver {
    cache_dir: PathBuf,
    contact: String,
    use_production: bool,
    state: Arc<Mutex<Option<AcmeState<std::io::Error, std::io::Error>>>>,
    resolver: Option<Arc<ResolvesServerCertAcme>>,
}

impl AcmeResolver {
    pub(crate) fn new(cache_dir: PathBuf, contact: String, use_production: bool) -> Self {
        AcmeResolver {
            cache_dir,
            contact,
            use_production,
            state: Arc::new(Mutex::new(None)),
            resolver: None,
        }
    }
}

impl AlpnChallengeResolver for AcmeResolver {
    fn update_domains(&mut self, domains: Vec<String>) {
        let new_state = AcmeConfig::new(domains)
            .contact_push(format!("mailto:{}", self.contact))
            .cache(DirCache::new(self.cache_dir.clone()))
            .directory_lets_encrypt(self.use_production)
            .state();
        self.resolver = Some(new_state.resolver());
        *self.state.lock().unwrap() = Some(new_state);
    }

    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.resolver
            .as_ref()
            .and_then(|resolver| resolver.resolve(client_hello))
    }

    fn challenge_rustls_config(&self) -> Option<Arc<ServerConfig>> {
        self.state
            .lock()
            .unwrap()
            .as_ref()
            .map(|state| state.challenge_rustls_config())
    }
}
