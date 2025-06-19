use std::{
    fmt::Debug,
    path::{Path, PathBuf},
    sync::Arc,
};

#[cfg(test)]
use mockall::automock;
use rustls::{
    ServerConfig,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use rustls_acme::{AcmeConfig, AcmeState, UseChallenge, caches::DirCache};
use tokio_stream::StreamExt;
use tracing::{info, warn};

use crate::{certificates::AlpnChallengeResolver, droppable_handle::DroppableHandle};

// Struct wrapping an ACME ALPN challenge resolver.
#[derive(Debug)]
pub(crate) struct AlpnAcmeResolverState(AcmeState<std::io::Error, std::io::Error>);

#[derive(Debug)]
pub(crate) struct AlpnAcmeResolver;

// Trait for ACME challenge resolution.
#[cfg_attr(test, automock(type State=MockResolverState;))]
pub(crate) trait Resolver {
    type State;

    // Create a new instance of this resolver state.
    fn state(
        &self,
        domains: Vec<String>,
        contact_email: &str,
        cache_dir: &Path,
        use_staging: bool,
    ) -> Self::State;
}

impl Resolver for AlpnAcmeResolver {
    type State = AlpnAcmeResolverState;

    fn state(
        &self,
        domains: Vec<String>,
        contact_email: &str,
        cache_dir: &Path,
        use_staging: bool,
    ) -> Self::State {
        AlpnAcmeResolverState(
            AcmeConfig::new(domains)
                .contact_push(format!("mailto:{contact_email}"))
                .cache(DirCache::new(cache_dir.to_owned()))
                .directory_lets_encrypt(!use_staging)
                .challenge_type(UseChallenge::TlsAlpn01)
                .state(),
        )
    }
}

// Trait for ACME challenge resolution.
#[cfg_attr(test, automock)]
pub(crate) trait ResolverState {
    // Create a configuration for TLS-ALPN-01 challenges.
    fn config(&self) -> Arc<ServerConfig>;

    // Create a certificate resolver for ACME-generated certificates.
    fn certificate_resolver(&self) -> Arc<dyn ResolvesServerCert>;

    // Spawn the new background task.
    fn join_handle(self) -> DroppableHandle<()>;
}

impl ResolverState for AlpnAcmeResolverState {
    fn config(&self) -> Arc<ServerConfig> {
        self.0.challenge_rustls_config()
    }

    fn certificate_resolver(&self) -> Arc<dyn ResolvesServerCert> {
        self.0.resolver()
    }

    fn join_handle(mut self) -> DroppableHandle<()> {
        DroppableHandle(tokio::spawn(async move {
            while let Some(msg) = self.0.next().await {
                if let Err(error) = msg {
                    warn!(%error, "ACME listener error.");
                }
            }
        }))
    }
}

unsafe impl Sync for AlpnAcmeResolverState {}

// Service that resolves ACME TLS-ALPN-01 challenges and the certificates they generate.
#[derive(Debug)]
pub(crate) struct AcmeResolver<R: Resolver> {
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
    cert_resolver: Option<Arc<dyn ResolvesServerCert>>,
    resolver: R,
}

impl<R: Resolver> AcmeResolver<R> {
    pub(crate) fn new(resolver: R, cache_dir: PathBuf, contact: String, use_staging: bool) -> Self {
        AcmeResolver {
            cache_dir,
            contact,
            use_staging,
            join_handle: None,
            config: None,
            cert_resolver: None,
            resolver,
        }
    }
}

impl<R> AlpnChallengeResolver for AcmeResolver<R>
where
    R: Resolver + Debug + Sync + Send,
    R::State: ResolverState + Debug + Sync + Send + Unpin + 'static,
{
    // Handle the new list of domains to manage certificates for with TLS-ALPN-01 challenges.
    fn update_domains(&mut self, domains: Vec<String>) {
        // Clear config variables if the list is empty.
        if domains.is_empty() {
            self.config = None;
            self.cert_resolver = None;
            self.join_handle = None;
            return;
        }
        info!(?domains, "Generating ACME certificates.",);
        // Create a new ACME config state.
        let new_state =
            self.resolver
                .state(domains, &self.contact, &self.cache_dir, self.use_staging);
        self.config = Some(new_state.config());
        self.cert_resolver = Some(new_state.certificate_resolver());
        self.join_handle = Some(new_state.join_handle());
    }

    // Return the appropriate certificate for the given TLS ClientHello.
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.cert_resolver
            .as_ref()
            .and_then(|resolver| resolver.resolve(client_hello))
    }

    // Return the config used for TLS-ALPN-01 challenges.
    fn challenge_rustls_config(&self) -> Option<Arc<ServerConfig>> {
        self.config.clone()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod alpn_challenge_resolver_tests {
    use std::{future, sync::Arc};

    use rustls::{
        RootCertStore, ServerConfig,
        server::Acceptor,
        sign::{CertifiedKey, SingleCertAndKey},
    };
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    use tokio_rustls::{LazyConfigAcceptor, TlsConnector};

    use crate::droppable_handle::DroppableHandle;

    use super::{AcmeResolver, AlpnChallengeResolver, MockResolver, MockResolverState};

    // Certificate for sandhole.com.br with custom CA
    const TLS_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----
MIIEGzCCAoOgAwIBAgIQKpoWlpOe+o/75k2YOODeVzANBgkqhkiG9w0BAQsFADBl
MR4wHAYDVQQKExVta2NlcnQgZGV2ZWxvcG1lbnQgQ0ExHTAbBgNVBAsMFGVyaWNA
ZXJpYy1wb3AgKEVyaWMpMSQwIgYDVQQDDBtta2NlcnQgZXJpY0BlcmljLXBvcCAo
RXJpYykwHhcNMjUwMzI4MDExMDI0WhcNMjcwNjI4MDExMDI0WjBIMScwJQYDVQQK
Ex5ta2NlcnQgZGV2ZWxvcG1lbnQgY2VydGlmaWNhdGUxHTAbBgNVBAsMFGVyaWNA
ZXJpYy1wb3AgKEVyaWMpMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
0IYz3Shy2GM7g8usGNO2ezCEgwsslrBX/VHE/nOlt/IUI2O3OIjNyP/smjITM8nu
6hHVsxBBEFS5e3D9HJUTRi8sftzZ4+lzWDSP6eYh8IeVk+taFbeQ2VKbSrhKsdHT
7URaV7o2IGYiKIMdTxD314aIZ5p+tRrMJyuFOmV1RU+jlnaa1n522fs8fC2AGkyt
aYP7NrqKoTvqTv9I9loxpbXxQMHUATZSoABnG/A7Ije4QsdeaE4i8ZABzVaCGSCl
IBKdbpOtLiT/RHKL0wMpJ+DlSWQnyOwz+mpM3R83my5x7WJrTB1eu5ro9vBR9NW3
CuLNNjOkW1kxUdqaObVirwIDAQABo2QwYjAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0l
BAwwCgYIKwYBBQUHAwEwHwYDVR0jBBgwFoAUt/sgfOEuNa0wsaUas98rXIcFa4Ew
GgYDVR0RBBMwEYIPc2FuZGhvbGUuY29tLmJyMA0GCSqGSIb3DQEBCwUAA4IBgQBz
VYkidjXl6wdn6Lng0oKQBzJxBTSRFfG+gYetuXjL8t5XTu+THYUpd9gjjZ3Fikug
bm09qAAGzmYCk+RcEkcOTM6BBZoDwk9zxwTmIi+sTqnCicXi3KpwTY890OTsZlJ8
LRpGHFvPT8Kv6dnZNbFqwoqFH1gUjoHdXNbwvzk6alXrRou3o9QjRJNctbOMekIW
sb24kNUsQ6VrLA2dHssSqKcZaiZvheXhLGYFLS4FPKfmFSXKpE6kjaWHRnKPa4bz
VuMylFcMWBI+62N6uWo9l5pcWWp12hwt7FskJmC6ROWJ08gEJTm1p7G7ZPq1/ygf
dtw9MMzodcnHvIBylk9B7mkAckgOvmnnLsKtVOvD73nZYpZJovYeBMj/RPLUcUtq
n3cJTrBy2R+HYXfW3I14esz2kskcpYeJP1ateSOtvQcIH0cFkgS+uREl+9WO31NE
84Ps5Z/Z0Wr7FeBl7AJ9dvI2EgUuNVcYRpvlJSFQhrtxho/pqywVP3S6Yjz6nkA=
-----END CERTIFICATE-----
";

    const TLS_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDQhjPdKHLYYzuD
y6wY07Z7MISDCyyWsFf9UcT+c6W38hQjY7c4iM3I/+yaMhMzye7qEdWzEEEQVLl7
cP0clRNGLyx+3Nnj6XNYNI/p5iHwh5WT61oVt5DZUptKuEqx0dPtRFpXujYgZiIo
gx1PEPfXhohnmn61GswnK4U6ZXVFT6OWdprWfnbZ+zx8LYAaTK1pg/s2uoqhO+pO
/0j2WjGltfFAwdQBNlKgAGcb8DsiN7hCx15oTiLxkAHNVoIZIKUgEp1uk60uJP9E
covTAykn4OVJZCfI7DP6akzdHzebLnHtYmtMHV67muj28FH01bcK4s02M6RbWTFR
2po5tWKvAgMBAAECggEAEWxlQQF0NyhzfJu0EY7/HGP9boWsgBrT/1Kpxykam7ga
fqqCULL9nuHjfy7X8+fXkq9Sz9d32El8Bhh2zcCXD7I5YZBKlISZIrGhpMWZ6GMr
2GQ97rqb28zPNPsZIqqJrrWbZuEkTKi8Ce6KsGSWkOeo1h9OnwtSK6OzSiHYHqZW
HHWjJJINVKES6BVst/rOzKm6RpfPJtU45gl0BqfZqHZD8AvzOS1Wfic/0xnuOnUo
P5iqxxgqbObNpoKzART6XAvlDzw6DyTCXgw5PhYvLf6IHB5JdWg/6BE3kKX9mHWY
ufjJB///7alAxeWyvTsvtIUDKFKMCTUKRZ/WYlzxoQKBgQDTK48I1sNLCXR15Mns
XsweTyv7E/lv0TqO4BWG1wIAEhFh9fqelwavoS+sI3Hq39UyA0RfVYS5Jzmzy5E1
kyF/a7UuCDoiJIBt0g4U3jSMfaCZ7RXZ5nWhjo1gSlzTHPcS7tQznZ8GwLYjLFyY
L6n7dsMUAC2dr/ogOqji1ZlR0wKBgQD8ytihCuUoIuFN7HUeC48zr4sZvU3VIDW6
pldt9+TNJPGViryVep2bWi0DyjkP6fav6dLrowLwAUHNel4xO2Kn/n9qw/m9XphX
uGU+75kSRz/Sb6Q/38PteXYXrrx9n4on2aVzq9POFcQfB2w9R5rz4PJMUN8dHuK8
0SiNlnGGNQKBgQDQaKT57DtBy0sNL4e5qLV7FFgrrEL5gF1ytOWJ9pkayLovHD0E
V7lZjJMoKLM9Qzt96IuKKzSaJ4RjVf0yCst8nihqDeSR3cSCnlUXc1YZccMXJ03x
h+mAUNhmt/10vZl7LgpwBpf0ai1X+WhJKoFwlH1jN+nNPuh09m/Hr1dp0QKBgQCg
Mf+j1l6v16LFmdICLzsZeuYAcrlvFRFXbfA7zPsekYnSxW+KnoBgIX4jR7RvhEmC
4v95ufyzkWhcyW4FbuevJBUk2Hpb6iVKeZ0XjAiJz8L/HSaOH8RuqikPCvmB9mc7
p640pi/8CkkVjMOn9ceZQvTpLdql/pubIkS7rRnV/QKBgQDK68UzGJJrK2MWuecE
gv/IFroGyBkT+srvbFP9VVbS8GZgxU/Io88UnQz8j3NW96gvyIJha9JpjGhSt7fA
8FDgfgzg3Yk2dumXG51R/LpITxB9mwuqWPZZ/sTVK2OOoxXD3ooeyC257TltLJ5k
o6ioYnJQHPsfaym/DY0seYghtg==
-----END PRIVATE KEY-----
";

    #[test_log::test(tokio::test)]
    async fn update_acme_resolver_with_no_domains() {
        let mut mock = MockResolver::new();
        mock.expect_state().never();
        let mut resolver = AcmeResolver::new(
            mock,
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/acme_cache/").into(),
            "foobar@sandhole.com.br".into(),
            true,
        );
        resolver.update_domains(vec![]);
        assert!(
            resolver.cert_resolver.is_none(),
            "cert resolver should be None"
        );
        assert!(resolver.config.is_none(), "config should be None");
        assert!(resolver.join_handle.is_none(), "join handle should be None");
        assert!(
            resolver.challenge_rustls_config().is_none(),
            "challenge_rustls_config should be None"
        );
        // assert!(resolver.resolve().is_none(), "resolving should return None");
    }

    #[test_log::test(tokio::test)]
    async fn update_acme_resolver_with_single_domain() {
        let mut mock_state = MockResolverState::default();
        mock_state.expect_config().once().return_once(|| {
            Arc::new(
                ServerConfig::builder_with_provider(Arc::new(
                    rustls::crypto::aws_lc_rs::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    CertificateDer::pem_slice_iter(TLS_CERTIFICATE.as_bytes())
                        .collect::<Result<Vec<_>, _>>()
                        .expect("invalid certificate"),
                    PrivateKeyDer::from_pem_slice(TLS_KEY.as_bytes()).expect("invalid key"),
                )
                .expect("invalid key/certificate pair"),
            )
        });
        mock_state
            .expect_certificate_resolver()
            .once()
            .return_once(|| {
                Arc::new(SingleCertAndKey::from(CertifiedKey::new(
                    CertificateDer::pem_slice_iter(TLS_CERTIFICATE.as_bytes())
                        .collect::<Result<Vec<_>, _>>()
                        .expect("invalid certificate"),
                    rustls::crypto::aws_lc_rs::sign::any_supported_type(
                        &PrivateKeyDer::from_pem_slice(TLS_KEY.as_bytes()).expect("invalid key"),
                    )
                    .expect("error creating signing key"),
                )))
            });
        mock_state
            .expect_join_handle()
            .once()
            .return_once(|| DroppableHandle(tokio::spawn(future::pending())));
        let mut mock = MockResolver::new();
        mock.expect_state()
            .once()
            .return_once(|_, _, _, _| mock_state);
        let mut resolver = AcmeResolver::new(
            mock,
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/acme_cache/").into(),
            "foobar@sandhole.com.br".into(),
            true,
        );
        resolver.update_domains(vec!["sandhole.com.br".into()]);
        assert!(resolver.cert_resolver.is_some(), "missing cert resolver");
        assert!(resolver.config.is_some(), "missing config");
        assert!(resolver.join_handle.is_some(), "missing join handle");
        assert!(
            resolver.challenge_rustls_config().is_some(),
            "missing challenge_rustls_config"
        );

        // Test SNI resolution for the valid domain
        let mut root_store = RootCertStore::empty();
        root_store.add_parsable_certificates(
            CertificateDer::pem_file_iter(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/data/ca/rootCA.pem"
            ))
            .and_then(|iter| iter.collect::<Result<Vec<_>, _>>())
            .expect("Failed to parse certificates"),
        );
        let tls_config = Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
        );
        let connector = TlsConnector::from(tls_config);

        let (client, server) = tokio::io::duplex(65536);
        let jh = tokio::spawn(async move {
            connector
                .connect("sandhole.com.br".try_into().unwrap(), client)
                .await
        });
        let handshake = LazyConfigAcceptor::new(Acceptor::default(), server)
            .await
            .expect("unable to connect via TLS");
        assert!(
            resolver.resolve(handshake.client_hello()).is_some(),
            "failed to resolve key for sandhole.com.br"
        );
        jh.abort();
    }
}
