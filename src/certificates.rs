use std::{
    fmt::Debug,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};

use crate::{
    connections::ConnectionMapReactor, directory::watch_directory,
    droppable_handle::DroppableHandle,
};
use log::{error, warn};
#[cfg(test)]
use mockall::automock;
use notify::RecommendedWatcher;
use rustls::{
    client::verify_server_name,
    crypto::aws_lc_rs::sign::any_supported_type,
    pki_types::{pem::PemObject, DnsName, PrivateKeyDer, ServerName},
    server::{ClientHello, ParsedCertificate, ResolvesServerCert},
    sign::CertifiedKey,
    ServerConfig,
};
use tokio::{fs::read_dir, sync::oneshot};
use trie_rs::map::{Trie, TrieBuilder};
use webpki::{types::CertificateDer, EndEntityCert};

#[derive(Debug)]
pub(crate) struct DummyAlpnChallengeResolver;

#[cfg_attr(test, automock)]
pub(crate) trait AlpnChallengeResolver: Debug + Send + Sync {
    fn update_domains(&mut self, domains: Vec<String>);
    #[expect(clippy::needless_lifetimes)]
    fn resolve<'a>(&self, client: ClientHello<'a>) -> Option<Arc<CertifiedKey>>;
    fn challenge_rustls_config(&self) -> Option<Arc<ServerConfig>>;
}

impl AlpnChallengeResolver for DummyAlpnChallengeResolver {
    fn update_domains(&mut self, _domains: Vec<String>) {}

    fn resolve(&self, _client: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        None
    }

    fn challenge_rustls_config(&self) -> Option<Arc<ServerConfig>> {
        None
    }
}

#[derive(Debug)]
pub(crate) struct CertificateResolver {
    certificates: Arc<RwLock<Trie<String, Arc<CertifiedKey>>>>,
    alpn_resolver: RwLock<Box<dyn AlpnChallengeResolver>>,
    _join_handle: DroppableHandle<()>,
    _watcher: RecommendedWatcher,
}

impl CertificateResolver {
    // Start watching on the directory, waiting for certificates that get added or removed.
    pub(crate) async fn watch(
        directory: PathBuf,
        alpn_resolver: RwLock<Box<dyn AlpnChallengeResolver>>,
    ) -> anyhow::Result<Self> {
        let certificates: Arc<RwLock<Trie<String, Arc<CertifiedKey>>>> =
            Arc::new(RwLock::new(TrieBuilder::new().build()));
        let (watcher, mut certificates_rx) =
            watch_directory::<RecommendedWatcher>(directory.as_path())?;
        certificates_rx.mark_changed();
        let certs_clone = Arc::clone(&certificates);
        let (init_tx, init_rx) = oneshot::channel::<()>();
        let join_handle = DroppableHandle(tokio::spawn(async move {
            let mut init_tx = Some(init_tx);
            while certificates_rx.changed().await.is_ok() {
                let mut builder = TrieBuilder::new();
                match read_dir(directory.as_path()).await {
                    Ok(mut read_dir) => {
                        while let Ok(Some(entry)) = read_dir.next_entry().await {
                            if entry
                                .file_type()
                                .await
                                .is_ok_and(|filetype| filetype.is_dir())
                            {
                                let cert = match CertificateDer::pem_file_iter(
                                    entry.path().join("fullchain.pem"),
                                )
                                .and_then(|iter| iter.collect::<Result<Vec<_>, _>>())
                                {
                                    Ok(cert) => cert,
                                    Err(err) => {
                                        warn!(
                                            "Unable to load certificate chain in {:?}: {}",
                                            entry.path().join("fullchain.pem"),
                                            err
                                        );
                                        continue;
                                    }
                                };
                                let key = match PrivateKeyDer::from_pem_file(
                                    entry.path().join("privkey.pem"),
                                ) {
                                    Ok(key) => key,
                                    Err(err) => {
                                        warn!(
                                            "Unable to load certficate key in {:?}: {}",
                                            entry.path().join("privkey.pem"),
                                            err
                                        );
                                        continue;
                                    }
                                };
                                let Ok(key) = any_supported_type(&key) else {
                                    warn!(
                                        "Invalid key in {:?}: no supported type",
                                        entry.path().join("privkey.pem")
                                    );
                                    continue;
                                };
                                let ck = Arc::new(CertifiedKey::new(cert, key));
                                for eec in ck
                                    .end_entity_cert()
                                    .iter()
                                    .filter_map(|&cert| EndEntityCert::try_from(cert).ok())
                                {
                                    for name in eec.valid_dns_names() {
                                        let path = name
                                            .trim_start_matches("*.")
                                            .split('.')
                                            .rev()
                                            .map(String::from)
                                            .collect::<Vec<_>>();
                                        builder.push(path, ck.clone());
                                    }
                                }
                            }
                        }
                        let trie = builder.build();
                        *certs_clone.write().unwrap() = trie;
                    }
                    Err(err) => {
                        error!(
                            "Unable to read certificates directory {:?}: {}",
                            &directory, err
                        );
                    }
                }
                if let Some(tx) = init_tx.take() {
                    let _ = tx.send(());
                }
                tokio::time::sleep(Duration::from_secs(2)).await
            }
        }));
        init_rx.await.unwrap();
        Ok(CertificateResolver {
            certificates,
            alpn_resolver,
            _join_handle: join_handle,
            _watcher: watcher,
        })
    }

    // Find the certificate that matches the given server name
    fn resolve_server_name(&self, server_name: &str) -> Option<Arc<CertifiedKey>> {
        let Ok(dns_server_name) = DnsName::try_from(server_name).map(ServerName::DnsName) else {
            return None;
        };
        self.certificates
            .read()
            .unwrap()
            .common_prefix_search(
                server_name
                    .split('.')
                    .rev()
                    .map(String::from)
                    .collect::<Vec<_>>(),
            )
            .find(|(_, ck): &(String, &Arc<CertifiedKey>)| {
                ck.end_entity_cert().is_ok_and(|eec| {
                    ParsedCertificate::try_from(eec)
                        .is_ok_and(|cert| verify_server_name(&cert, &dns_server_name).is_ok())
                })
            })
            .map(|(_, ck)| Arc::clone(ck))
    }

    pub(crate) fn challenge_rustls_config(&self) -> Option<Arc<ServerConfig>> {
        self.alpn_resolver.read().unwrap().challenge_rustls_config()
    }
}

impl ResolvesServerCert for CertificateResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        match client_hello
            .server_name()
            .and_then(|server_name| self.resolve_server_name(server_name))
        {
            Some(cert) => Some(cert),
            None => self.alpn_resolver.read().unwrap().resolve(client_hello),
        }
    }
}

impl ConnectionMapReactor<String> for Arc<CertificateResolver> {
    fn call(&self, hostnames: Vec<String>) {
        let domains = hostnames
            .into_iter()
            .filter(|domain| self.resolve_server_name(domain.as_ref()).is_none())
            .collect();
        self.alpn_resolver.write().unwrap().update_domains(domains);
    }
}

#[cfg(test)]
mod certificate_resolver_tests {
    use std::sync::{Arc, RwLock};

    use mockall::predicate::eq;

    use super::{
        CertificateResolver, ConnectionMapReactor, DummyAlpnChallengeResolver,
        MockAlpnChallengeResolver,
    };

    static CERTIFICATES_DIRECTORY: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/certificates");
    // Certificate is valid for "foobar.tld" and "*.foobar.tld"
    static DOMAINS_FOOBAR: &[&str] = &["foobar.tld", "something.foobar.tld", "other.foobar.tld"];
    // Certificate is valid for "localhost"
    static DOMAINS_LOCALHOST: &[&str] = &["localhost"];
    static UNKNOWN_DOMAINS: &[&str] = &[".invalid.", "tld", "example.com", "too.nested.foobar.tld"];

    #[tokio::test]
    async fn allows_valid_domains() {
        let resolver = CertificateResolver::watch(
            CERTIFICATES_DIRECTORY.parse().unwrap(),
            RwLock::new(Box::new(DummyAlpnChallengeResolver)),
        )
        .await
        .unwrap();
        for domain in DOMAINS_FOOBAR {
            assert!(
                resolver.resolve_server_name(domain).is_some(),
                "couldn't resolve valid domain {}",
                domain
            );
        }
        for domain in DOMAINS_LOCALHOST {
            assert!(
                resolver.resolve_server_name(domain).is_some(),
                "couldn't resolve valid domain {}",
                domain
            );
        }
    }

    #[tokio::test]
    async fn forbids_invalid_domains() {
        let resolver = CertificateResolver::watch(
            CERTIFICATES_DIRECTORY.parse().unwrap(),
            RwLock::new(Box::new(DummyAlpnChallengeResolver)),
        )
        .await
        .unwrap();
        for domain in UNKNOWN_DOMAINS {
            assert!(
                resolver.resolve_server_name(domain).is_none(),
                "shouldn't have resolved unknown domain {}",
                domain
            );
        }
    }

    #[tokio::test]
    async fn updates_alpn_resolver_on_reaction() {
        let mut mock = MockAlpnChallengeResolver::new();
        mock.expect_update_domains()
            .once()
            .with(eq(vec!["example.com".to_string()]))
            .returning(|_| {});
        let resolver = Arc::new(
            CertificateResolver::watch(
                CERTIFICATES_DIRECTORY.parse().unwrap(),
                RwLock::new(Box::new(mock)),
            )
            .await
            .unwrap(),
        );
        resolver.call(vec!["foobar.tld".into(), "example.com".into()]);
    }
}
