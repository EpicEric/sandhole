use std::{
    fmt::Debug,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};

use crate::{directory::watch_directory, droppable_handle::DroppableHandle, error::ServerError};
#[cfg(test)]
use mockall::automock;
use notify::RecommendedWatcher;
use rustls::{
    ServerConfig,
    client::verify_server_name,
    crypto::aws_lc_rs::sign::any_supported_type,
    pki_types::{DnsName, PrivateKeyDer, ServerName, pem::PemObject},
    server::{ClientHello, ParsedCertificate, ResolvesServerCert},
    sign::CertifiedKey,
};
use rustls_pki_types::CertificateDer;
use tokio::{fs::read_dir, sync::oneshot};
use tracing::{error, warn};
use trie_rs::map::{Trie, TrieBuilder};
use webpki::EndEntityCert;

#[derive(Debug)]
pub(crate) struct DummyAlpnChallengeResolver;

#[cfg_attr(test, automock)]
pub(crate) trait AlpnChallengeResolver: Debug + Send + Sync {
    fn update_domains(&mut self, domains: Vec<String>);
    #[allow(clippy::needless_lifetimes)]
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
    // Data for certificates based on an efficient trie lookup.
    certificates: Arc<RwLock<Trie<String, Arc<CertifiedKey>>>>,
    // Resolver for TLS-ALPN-01 challenges and its ACME certificates.
    alpn_resolver: RwLock<Box<dyn AlpnChallengeResolver>>,
    // Task that updates certificates data upon filesystem changes.
    _join_handle: DroppableHandle<()>,
    // Filesystem change watcher.
    _watcher: RecommendedWatcher,
}

impl CertificateResolver {
    // Start watching on the directory, waiting for certificates that get added or removed.
    pub(crate) async fn watch(
        directory: PathBuf,
        alpn_resolver: RwLock<Box<dyn AlpnChallengeResolver>>,
    ) -> color_eyre::Result<Self> {
        if !directory.as_path().is_dir() {
            return Err(ServerError::MissingDirectory(directory).into());
        }
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
                        // For each subdirectory in the certificates directory
                        while let Ok(Some(entry)) = read_dir.next_entry().await {
                            if entry
                                .file_type()
                                .await
                                .is_ok_and(|filetype| filetype.is_dir())
                            {
                                // Get the certificate(s) from the fullchain.pem file
                                let certificate_path = entry.path().join("fullchain.pem");
                                let cert = match CertificateDer::pem_file_iter(&certificate_path)
                                    .and_then(|iter| iter.collect::<Result<Vec<_>, _>>())
                                {
                                    Ok(cert) => cert,
                                    Err(error) => {
                                        warn!(
                                            path = ?certificate_path,
                                            %error,
                                            "Unable to load certificate chain.",
                                        );
                                        continue;
                                    }
                                };
                                // Get the associated private key privkey.pem file
                                let key_path = entry.path().join("privkey.pem");
                                let key = match PrivateKeyDer::from_pem_file(&key_path) {
                                    Ok(key) => key,
                                    Err(error) => {
                                        warn!(
                                            path = ?key_path,
                                            %error,
                                            "Unable to load certificate key.",
                                        );
                                        continue;
                                    }
                                };
                                let key = match any_supported_type(&key) {
                                    Ok(key) => key,
                                    Err(error) => {
                                        warn!(
                                            path = ?key_path,
                                            %error,
                                            "Invalid key.",
                                        );
                                        continue;
                                    }
                                };
                                // Create the certificate + key pair
                                let ck = Arc::new(CertifiedKey::new(cert, key));
                                // Populate the trie with the valid DNS names for the certificate
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
                    Err(error) => {
                        error!(
                            ?directory, %error,
                            "Unable to read certificates directory.",
                        );
                    }
                }
                // Notify about initial certificates population
                if let Some(tx) = init_tx.take() {
                    let _ = tx.send(());
                }
                tokio::time::sleep(Duration::from_secs(2)).await
            }
        }));
        // Wait until the certificates have been populated once
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
        // Get the server name for the provided address
        let Ok(dns_server_name) = DnsName::try_from(server_name).map(ServerName::DnsName) else {
            return None;
        };
        self.certificates
            .read()
            .unwrap()
            // Return all certificates whose prefix match the server name
            .common_prefix_search(
                server_name
                    .split('.')
                    .rev()
                    .map(String::from)
                    .collect::<Vec<_>>(),
            )
            // Find a certificate that is valid for the given server name
            .find(|(_, ck): &(String, &Arc<CertifiedKey>)| {
                ck.end_entity_cert().is_ok_and(|eec| {
                    ParsedCertificate::try_from(eec)
                        .is_ok_and(|cert| verify_server_name(&cert, &dns_server_name).is_ok())
                })
            })
            .map(|(_, ck)| Arc::clone(ck))
    }

    // Return the config for TLS-ALPN-01 challenges
    pub(crate) fn challenge_rustls_config(&self) -> Option<Arc<ServerConfig>> {
        self.alpn_resolver.read().unwrap().challenge_rustls_config()
    }

    // Find the list of domains that don't have a certificate associated with them, and request ACME challenges for them.
    pub(crate) fn update_acme_domains(&self, hostnames: &[String]) {
        let domains = hostnames
            .iter()
            .filter(|domain| self.resolve_server_name(domain).is_none())
            .cloned()
            .collect();
        self.alpn_resolver.write().unwrap().update_domains(domains);
    }
}

impl ResolvesServerCert for CertificateResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        match client_hello
            .server_name()
            .and_then(|server_name| self.resolve_server_name(server_name))
        {
            // Return the certificate that we have if it matches
            Some(cert) => Some(cert),
            // Otherwise, return any certificate from the ACME resolver
            None => self.alpn_resolver.read().unwrap().resolve(client_hello),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod certificate_resolver_tests {
    use std::sync::{Arc, RwLock};

    use mockall::predicate::eq;
    use rand::{rng, seq::IndexedRandom};
    use tokio::fs;

    use super::{CertificateResolver, DummyAlpnChallengeResolver, MockAlpnChallengeResolver};

    static CERTIFICATES_DIRECTORY: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/certificates");
    // Certificate is valid for "foobar.tld" and "*.foobar.tld"
    static DOMAINS_FOOBAR: &[&str] = &["foobar.tld", "something.foobar.tld", "other.foobar.tld"];
    // Certificate is valid for "localhost"
    static DOMAINS_LOCALHOST: &[&str] = &["localhost"];
    static UNKNOWN_DOMAINS: &[&str] = &[".invalid.", "tld", "example.com", "too.nested.foobar.tld"];

    #[test_log::test(tokio::test)]
    #[should_panic(expected = "Missing directory")]
    async fn errors_on_missing_directory() {
        CertificateResolver::watch(
            std::env::temp_dir().join("invalid_directory_123"),
            RwLock::new(Box::new(DummyAlpnChallengeResolver)),
        )
        .await
        .unwrap();
    }

    #[test_log::test(tokio::test)]
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
                "couldn't resolve valid domain {domain}"
            );
        }
        for domain in DOMAINS_LOCALHOST {
            assert!(
                resolver.resolve_server_name(domain).is_some(),
                "couldn't resolve valid domain {domain}"
            );
        }
    }

    #[test_log::test(tokio::test)]
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
                "shouldn't have resolved unknown domain {domain}"
            );
        }
    }

    #[test_log::test(tokio::test)]
    async fn errors_on_missing_certificate() {
        let random_name = String::from_utf8(
            (0..6)
                .flat_map(|_| {
                    "0123456789abcdefghijklmnopqrstuvwxyz"
                        .as_bytes()
                        .choose(&mut rng())
                        .copied()
                })
                .collect(),
        )
        .unwrap();
        let temp_dir = std::env::temp_dir().join(format!("sandhole_certificates_{random_name}"));
        let certs_dir = temp_dir.join("foobar.tld");
        fs::create_dir_all(certs_dir.as_path())
            .await
            .expect("unable to create foobar.tld tempdir");
        fs::write(
            certs_dir.join("privkey.pem"),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/data/certificates/foobar.tld/privkey.pem"
            )),
        )
        .await
        .expect("unable to copy privkey.pem to tempdir");
        let resolver =
            CertificateResolver::watch(temp_dir, RwLock::new(Box::new(DummyAlpnChallengeResolver)))
                .await
                .unwrap();
        assert!(
            resolver.resolve_server_name("test.foobar.tld").is_none(),
            "shouldn't have resolved invalid domain test.foobar.tld"
        );
    }

    #[test_log::test(tokio::test)]
    async fn errors_on_missing_key() {
        let random_name = String::from_utf8(
            (0..6)
                .flat_map(|_| {
                    "0123456789abcdefghijklmnopqrstuvwxyz"
                        .as_bytes()
                        .choose(&mut rng())
                        .copied()
                })
                .collect(),
        )
        .unwrap();
        let temp_dir = std::env::temp_dir().join(format!("sandhole_certificates_{random_name}"));
        let certs_dir = temp_dir.join("foobar.tld");
        fs::create_dir_all(certs_dir.as_path())
            .await
            .expect("unable to create foobar.tld tempdir");
        fs::write(
            certs_dir.join("fullchain.pem"),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/data/certificates/foobar.tld/fullchain.pem"
            )),
        )
        .await
        .expect("unable to copy fullchain.pem to tempdir");
        let resolver =
            CertificateResolver::watch(temp_dir, RwLock::new(Box::new(DummyAlpnChallengeResolver)))
                .await
                .unwrap();
        assert!(
            resolver.resolve_server_name("test.foobar.tld").is_none(),
            "shouldn't have resolved invalid domain test.foobar.tld"
        );
    }

    #[test_log::test(tokio::test)]
    async fn errors_on_invalid_certificate() {
        let random_name = String::from_utf8(
            (0..6)
                .flat_map(|_| {
                    "0123456789abcdefghijklmnopqrstuvwxyz"
                        .as_bytes()
                        .choose(&mut rng())
                        .copied()
                })
                .collect(),
        )
        .unwrap();
        let temp_dir = std::env::temp_dir().join(format!("sandhole_certificates_{random_name}"));
        let certs_dir = temp_dir.join("foobar.tld");
        fs::create_dir_all(certs_dir.as_path())
            .await
            .expect("unable to create foobar.tld tempdir");
        fs::write(certs_dir.join("fullchain.pem"), b"invalid certificate")
            .await
            .expect("unable to write fullchain.pem to tempdir");
        fs::write(
            certs_dir.join("privkey.pem"),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/data/certificates/foobar.tld/privkey.pem"
            )),
        )
        .await
        .expect("unable to copy privkey.pem to tempdir");
        let resolver =
            CertificateResolver::watch(temp_dir, RwLock::new(Box::new(DummyAlpnChallengeResolver)))
                .await
                .unwrap();
        assert!(
            resolver.resolve_server_name("test.foobar.tld").is_none(),
            "shouldn't have resolved invalid domain test.foobar.tld"
        );
    }

    #[test_log::test(tokio::test)]
    async fn errors_on_invalid_key() {
        let random_name = String::from_utf8(
            (0..6)
                .flat_map(|_| {
                    "0123456789abcdefghijklmnopqrstuvwxyz"
                        .as_bytes()
                        .choose(&mut rng())
                        .copied()
                })
                .collect(),
        )
        .unwrap();
        let temp_dir = std::env::temp_dir().join(format!("sandhole_certificates_{random_name}"));
        let certs_dir = temp_dir.join("foobar.tld");
        fs::create_dir_all(certs_dir.as_path())
            .await
            .expect("unable to create foobar.tld tempdir");
        fs::write(
            certs_dir.join("fullchain.pem"),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/data/certificates/foobar.tld/fullchain.pem"
            )),
        )
        .await
        .expect("unable to copy fullchain.pem to tempdir");
        fs::write(certs_dir.join("privkey.pem"), b"invalid key")
            .await
            .expect("unable to write privkey.pem to tempdir");
        let resolver =
            CertificateResolver::watch(temp_dir, RwLock::new(Box::new(DummyAlpnChallengeResolver)))
                .await
                .unwrap();
        assert!(
            resolver.resolve_server_name("test.foobar.tld").is_none(),
            "shouldn't have resolved invalid domain test.foobar.tld"
        );
    }

    #[test_log::test(tokio::test)]
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
        resolver.update_acme_domains(&["foobar.tld".into(), "example.com".into()]);
    }
}
