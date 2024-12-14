use std::{hash::Hash, net::SocketAddr};

use async_trait::async_trait;
use hickory_resolver::{proto::rr::RecordType, TokioAsyncResolver};
use itertools::Itertools;
use log::{debug, warn};
#[cfg(test)]
use mockall::automock;
use rand::{seq::SliceRandom, thread_rng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rand_seeder::SipHasher;
use ssh_key::Fingerprint;
use webpki::types::DnsName;

use crate::{
    config::{BindHostnames, RandomSubdomainSeed},
    tcp::is_alias,
};

pub(crate) struct DnsResolver(TokioAsyncResolver);

#[cfg_attr(test, automock)]
#[async_trait]
pub(crate) trait Resolver {
    // Check if there is a TXT record for the provided fingerprint.
    async fn has_txt_record_for_fingerprint(
        &self,
        txt_record_prefix: &str,
        requested_address: &str,
        fingerprint: &Fingerprint,
    ) -> bool;

    // Check if there is a CNAME record pointing to Sandhole's domain.
    async fn has_cname_record_for_domain(&self, requested_address: &str, domain: &str) -> bool;
}

impl DnsResolver {
    pub(crate) fn new() -> Self {
        DnsResolver(TokioAsyncResolver::tokio(
            Default::default(),
            Default::default(),
        ))
    }
}

#[async_trait]
impl Resolver for DnsResolver {
    async fn has_txt_record_for_fingerprint(
        &self,
        txt_record_prefix: &str,
        requested_address: &str,
        fingerprint: &Fingerprint,
    ) -> bool {
        if let Ok(lookup) = self
            .0
            .txt_lookup(format!("{}.{}.", txt_record_prefix, requested_address))
            .await
        {
            lookup.iter().any(|txt| {
                txt.iter().any(|data| {
                    String::from_utf8_lossy(data)
                        .parse::<Fingerprint>()
                        .as_ref()
                        == Ok(fingerprint)
                })
            })
        } else {
            false
        }
    }

    async fn has_cname_record_for_domain(&self, requested_address: &str, domain: &str) -> bool {
        if let Ok(lookup) = self
            .0
            .lookup(format!("{}.", requested_address), RecordType::CNAME)
            .await
        {
            lookup
                .iter()
                .filter_map(|rdata| rdata.clone().into_cname().ok())
                .any(|cname| {
                    let cname = cname
                        .iter()
                        .map(|data| String::from_utf8_lossy(data))
                        .join(".");
                    debug!("cname {}", &cname);
                    cname == domain
                })
        } else {
            false
        }
    }
}

pub(crate) struct AddressDelegator<R> {
    resolver: R,
    txt_record_prefix: String,
    root_domain: String,
    seed: u64,
    random_subdomain_seed: Option<RandomSubdomainSeed>,
    bind_hostnames: BindHostnames,
    force_random_subdomains: bool,
}

impl<R: Resolver> AddressDelegator<R> {
    pub(crate) fn new(
        resolver: R,
        txt_record_prefix: String,
        root_domain: String,
        bind_hostnames: BindHostnames,
        force_random_subdomains: bool,
        random_subdomain_seed: Option<RandomSubdomainSeed>,
    ) -> Self {
        debug_assert!(!txt_record_prefix.is_empty());
        debug_assert!(!root_domain.is_empty());
        AddressDelegator {
            resolver,
            txt_record_prefix,
            root_domain,
            bind_hostnames,
            force_random_subdomains,
            random_subdomain_seed,
            seed: thread_rng().next_u64(),
        }
    }

    // Assign an address given the current configuration
    pub(crate) async fn get_address(
        &self,
        requested_address: &str,
        user: &Option<String>,
        fingerprint: &Option<Fingerprint>,
        socket_address: &SocketAddr,
    ) -> String {
        if DnsName::try_from(requested_address).is_ok() {
            if matches!(self.bind_hostnames, BindHostnames::All) {
                return requested_address.to_string();
            }
            if matches!(self.bind_hostnames, BindHostnames::Cname)
                && requested_address != self.root_domain
                && self
                    .resolver
                    .has_cname_record_for_domain(requested_address, &self.root_domain)
                    .await
            {
                return requested_address.to_string();
            }
            if matches!(
                self.bind_hostnames,
                BindHostnames::Cname | BindHostnames::Txt
            ) {
                if let Some(fingerprint) = fingerprint {
                    if self
                        .resolver
                        .has_txt_record_for_fingerprint(
                            &self.txt_record_prefix,
                            requested_address,
                            fingerprint,
                        )
                        .await
                    {
                        return requested_address.to_string();
                    }
                }
            }
            if !self.force_random_subdomains {
                // Assign specified subdomain under the root domain
                let address = requested_address.trim_end_matches(&format!(".{}", self.root_domain));
                if !address.is_empty() && !address.contains('.') {
                    return format!("{}.{}", address, self.root_domain);
                }
            }
            if is_alias(requested_address) {
                warn!(
                    "Invalid address requested ({}), defaulting to random",
                    requested_address
                );
            }
        } else {
            warn!(
                "Invalid address requested ({}), defaulting to random",
                requested_address
            );
        }
        // Assign random subdomain under the root domain
        format!(
            "{}.{}",
            self.get_random_subdomain(requested_address, user, fingerprint, socket_address),
            self.root_domain
        )
    }

    // Generate a random subdomain based on the configured strategy
    fn get_random_subdomain(
        &self,
        requested_address: &str,
        user: &Option<String>,
        fingerprint: &Option<Fingerprint>,
        socket_address: &SocketAddr,
    ) -> String {
        let mut hasher = SipHasher::default();
        self.seed.hash(&mut hasher);
        let mut hash_initialized = false;
        if let Some(strategy) = self.random_subdomain_seed {
            match strategy {
                RandomSubdomainSeed::User => {
                    if let Some(user) = user {
                        requested_address.hash(&mut hasher);
                        user.hash(&mut hasher);
                        hash_initialized = true;
                    } else {
                        warn!("No SSH user when assigning subdomain. Defaulting to random.")
                    }
                }
                RandomSubdomainSeed::KeyFingerprint => {
                    if let Some(fingerprint) = fingerprint {
                        requested_address.hash(&mut hasher);
                        fingerprint.as_bytes().hash(&mut hasher);
                        hash_initialized = true;
                    } else {
                        warn!(
                            "No SSH key fingerprint when assigning subdomain. Defaulting to random."
                        )
                    }
                }
                RandomSubdomainSeed::IpAndUser => {
                    requested_address.hash(&mut hasher);
                    socket_address.ip().hash(&mut hasher);
                    if let Some(user) = user {
                        user.hash(&mut hasher);
                    }
                    hash_initialized = true;
                }
                RandomSubdomainSeed::SocketAddress => {
                    requested_address.hash(&mut hasher);
                    socket_address.hash(&mut hasher);
                    hash_initialized = true;
                }
            }
        }
        if !hash_initialized {
            // Random seed
            thread_rng().next_u64().hash(&mut hasher);
        }
        // Generate random subdomain from hashed state
        let mut seed: <ChaCha20Rng as SeedableRng>::Seed = Default::default();
        hasher.into_rng().fill(&mut seed);
        let mut rng = ChaCha20Rng::from_seed(seed);
        String::from_utf8(
            (0..6)
                .flat_map(|_| {
                    "0123456789abcdefghijklmnopqrstuvwxyz"
                        .as_bytes()
                        .choose(&mut rng)
                        .copied()
                })
                .collect(),
        )
        .unwrap()
    }
}

#[cfg(test)]
mod address_delegator_tests {
    use crate::config::BindHostnames;

    use super::{AddressDelegator, MockResolver};
    use mockall::predicate::*;
    use rand::rngs::OsRng;
    use regex::Regex;
    use ssh_key::HashAlg;
    use std::net::SocketAddr;
    use webpki::types::DnsName;

    #[tokio::test]
    async fn returns_provided_address_when_binding_any_host() {
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint().never();
        let delegator = AddressDelegator::new(
            mock,
            "_some_prefix".into(),
            "root.tld".into(),
            BindHostnames::All,
            false,
            None,
        );
        let address = delegator
            .get_address(
                "some.address",
                &None,
                &None,
                &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert_eq!(address, "some.address");
        assert!(DnsName::try_from(address).is_ok());
    }

    #[tokio::test]
    async fn returns_root_domain_when_binding_any_host() {
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint().never();
        let delegator = AddressDelegator::new(
            mock,
            "_some_prefix".into(),
            "root.tld".into(),
            BindHostnames::All,
            false,
            None,
        );
        let address = delegator
            .get_address(
                "root.tld",
                &None,
                &None,
                &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert_eq!(address, "root.tld");
        assert!(DnsName::try_from(address).is_ok());
    }

    #[tokio::test]
    async fn returns_provided_address_when_cname_is_match() {
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint().never();
        mock.expect_has_cname_record_for_domain()
            .once()
            .return_const(true);
        let delegator = AddressDelegator::new(
            mock,
            "_some_prefix".into(),
            "root.tld".into(),
            BindHostnames::Cname,
            false,
            None,
        );
        let address = delegator
            .get_address(
                "some.address",
                &None,
                &None,
                &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert_eq!(address, "some.address");
        assert!(DnsName::try_from(address).is_ok());
    }

    #[tokio::test]
    async fn returns_provided_address_if_cname_matches_fingerprint() {
        let fingerprint =
            russh_keys::PrivateKey::random(&mut OsRng, russh_keys::Algorithm::Ed25519)
                .unwrap()
                .fingerprint(HashAlg::Sha256);
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint()
            .with(
                eq("_some_prefix"),
                eq("some.address"),
                eq(fingerprint.clone()),
            )
            .return_const(true);
        mock.expect_has_cname_record_for_domain()
            .once()
            .return_const(false);
        let delegator = AddressDelegator::new(
            mock,
            "_some_prefix".into(),
            "root.tld".into(),
            BindHostnames::Cname,
            false,
            None,
        );
        let address = delegator
            .get_address(
                "some.address",
                &None,
                &Some(fingerprint),
                &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert_eq!(address, "some.address");
        assert!(DnsName::try_from(address).is_ok());
    }

    #[tokio::test]
    async fn returns_provided_address_if_txt_record_matches_fingerprint() {
        let fingerprint =
            russh_keys::PrivateKey::random(&mut OsRng, russh_keys::Algorithm::Ed25519)
                .unwrap()
                .fingerprint(HashAlg::Sha256);
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint()
            .with(
                eq("_some_prefix"),
                eq("some.address"),
                eq(fingerprint.clone()),
            )
            .return_const(true);
        let delegator = AddressDelegator::new(
            mock,
            "_some_prefix".into(),
            "root.tld".into(),
            BindHostnames::Txt,
            false,
            None,
        );
        let address = delegator
            .get_address(
                "some.address",
                &None,
                &Some(fingerprint),
                &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert_eq!(address, "some.address");
        assert!(DnsName::try_from(address).is_ok());
    }

    #[tokio::test]
    async fn returns_provided_subdomain_if_no_fingerprint() {
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint()
            .never()
            .return_const(true);
        let delegator = AddressDelegator::new(
            mock,
            "_some_prefix".into(),
            "root.tld".into(),
            BindHostnames::Txt,
            false,
            None,
        );
        let address = delegator
            .get_address(
                "subdomain",
                &None,
                &None,
                &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert_eq!(address, "subdomain.root.tld");
        assert!(DnsName::try_from(address).is_ok());
    }

    #[tokio::test]
    async fn returns_subdomain_if_no_txt_record_matches_fingerprint() {
        let fingerprint =
            russh_keys::PrivateKey::random(&mut OsRng, russh_keys::Algorithm::Ed25519)
                .unwrap()
                .fingerprint(HashAlg::Sha256);
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint()
            .with(eq("_some_prefix"), eq("something"), eq(fingerprint.clone()))
            .return_const(false);
        let delegator = AddressDelegator::new(
            mock,
            "_some_prefix".into(),
            "root.tld".into(),
            BindHostnames::Txt,
            false,
            None,
        );
        let address = delegator
            .get_address(
                "something",
                &None,
                &Some(fingerprint),
                &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert_eq!(address, "something.root.tld");
        assert!(DnsName::try_from(address).is_ok());
    }

    #[tokio::test]
    async fn returns_subdomain_if_requested_subdomain_of_host_domain() {
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint().never();
        let delegator = AddressDelegator::new(
            mock,
            "_some_prefix".into(),
            "root.tld".into(),
            BindHostnames::None,
            false,
            None,
        );
        let address = delegator
            .get_address(
                "prefix.root.tld",
                &None,
                &None,
                &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert_eq!(address, "prefix.root.tld");
        assert!(DnsName::try_from(address).is_ok());
    }

    #[tokio::test]
    async fn returns_host_domain_if_address_equals_host_domain_and_has_fingerprint() {
        let fingerprint =
            russh_keys::PrivateKey::random(&mut OsRng, russh_keys::Algorithm::Ed25519)
                .unwrap()
                .fingerprint(HashAlg::Sha256);
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint()
            .once()
            .return_const(true);
        let delegator = AddressDelegator::new(
            mock,
            "_some_prefix".into(),
            "root.tld".into(),
            BindHostnames::Txt,
            false,
            None,
        );
        let address = delegator
            .get_address(
                "root.tld",
                &None,
                &Some(fingerprint),
                &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert_eq!(address, "root.tld");
        assert!(DnsName::try_from(address).is_ok());
    }

    #[tokio::test]
    async fn returns_random_subdomain_if_address_equals_host_domain_and_doesnt_have_fingerprint() {
        let fingerprint =
            russh_keys::PrivateKey::random(&mut OsRng, russh_keys::Algorithm::Ed25519)
                .unwrap()
                .fingerprint(HashAlg::Sha256);
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint()
            .once()
            .return_const(false);
        let delegator = AddressDelegator::new(
            mock,
            "_some_prefix".into(),
            "root.tld".into(),
            BindHostnames::Txt,
            false,
            None,
        );
        let address = delegator
            .get_address(
                "root.tld",
                &None,
                &Some(fingerprint),
                &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert!(
            Regex::new(r"^[0-9a-z]+\.root\.tld$")
                .unwrap()
                .is_match(&address),
            "invalid address {}",
            address
        );
        assert!(DnsName::try_from(address).is_ok());
    }

    #[tokio::test]
    async fn returns_random_subdomain_if_requested_address_is_not_direct_subdomain() {
        let fingerprint =
            russh_keys::PrivateKey::random(&mut OsRng, russh_keys::Algorithm::Ed25519)
                .unwrap()
                .fingerprint(HashAlg::Sha256);
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint()
            .once()
            .return_const(false);
        let delegator = AddressDelegator::new(
            mock,
            "_some_prefix".into(),
            "root.tld".into(),
            BindHostnames::Txt,
            false,
            None,
        );
        let address = delegator
            .get_address(
                "we.are.root.tld",
                &None,
                &Some(fingerprint),
                &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert!(
            Regex::new(r"^[0-9a-z]+\.root\.tld$")
                .unwrap()
                .is_match(&address),
            "invalid address {}",
            address
        );
        assert!(DnsName::try_from(address).is_ok());
    }

    #[tokio::test]
    async fn returns_random_subdomain_if_invalid_address() {
        let fingerprint =
            russh_keys::PrivateKey::random(&mut OsRng, russh_keys::Algorithm::Ed25519)
                .unwrap()
                .fingerprint(HashAlg::Sha256);
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint().never();
        let delegator = AddressDelegator::new(
            mock,
            "_some_prefix".into(),
            "root.tld".into(),
            BindHostnames::Cname,
            false,
            None,
        );
        let address = delegator
            .get_address(
                ".",
                &None,
                &Some(fingerprint),
                &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert!(
            Regex::new(r"^[0-9a-z]+\.root\.tld$")
                .unwrap()
                .is_match(&address),
            "invalid address {}",
            address
        );
        assert!(DnsName::try_from(address).is_ok());
    }

    #[tokio::test]
    async fn returns_unique_random_subdomains_if_forced() {
        let fingerprint =
            russh_keys::PrivateKey::random(&mut OsRng, russh_keys::Algorithm::Ed25519)
                .unwrap()
                .fingerprint(HashAlg::Sha256);
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint().never();
        let delegator = AddressDelegator::new(
            mock,
            "_some_prefix".into(),
            "root.tld".into(),
            BindHostnames::None,
            true,
            None,
        );
        let mut set = std::collections::HashSet::new();
        let regex = Regex::new(r"^[0-9a-z]+\.root\.tld$").unwrap();
        for _ in 0..100 {
            let address = delegator
                .get_address(
                    "some.address",
                    &None,
                    &Some(fingerprint),
                    &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
                )
                .await;
            assert!(regex.is_match(&address), "invalid address {}", address);
            assert!(DnsName::try_from(address.clone()).is_ok());
            assert!(!set.contains(&address));
            set.insert(address);
        }
    }

    #[tokio::test]
    async fn returns_unique_random_subdomains_per_user_and_address_if_forced() {
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint().never();
        let delegator = AddressDelegator::new(
            mock,
            "_some_prefix".into(),
            "root.tld".into(),
            BindHostnames::None,
            true,
            Some(crate::config::RandomSubdomainSeed::User),
        );
        let address1_u1_a1 = delegator
            .get_address(
                "a1",
                &Some("u1".into()),
                &None,
                &"127.0.0.1:12341".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address2_u1_a1 = delegator
            .get_address(
                "a1",
                &Some("u1".into()),
                &None,
                &"127.0.0.1:12342".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address3_u2_a1 = delegator
            .get_address(
                "a1",
                &Some("u2".into()),
                &None,
                &"127.0.0.1:12343".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address4_u1_a2 = delegator
            .get_address(
                "a2",
                &Some("u1".into()),
                &None,
                &"127.0.0.1:12344".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert_eq!(address1_u1_a1, address2_u1_a1);
        assert_ne!(address1_u1_a1, address3_u2_a1);
        assert_ne!(address1_u1_a1, address4_u1_a2);
        assert_ne!(address3_u2_a1, address4_u1_a2);
        assert!(DnsName::try_from(address1_u1_a1).is_ok());
        assert!(DnsName::try_from(address2_u1_a1).is_ok());
        assert!(DnsName::try_from(address3_u2_a1).is_ok());
        assert!(DnsName::try_from(address4_u1_a2).is_ok());
    }

    #[tokio::test]
    async fn returns_unique_random_subdomains_per_fingerprint_and_address_if_forced() {
        let f1 = russh_keys::PrivateKey::random(&mut OsRng, russh_keys::Algorithm::Ed25519)
            .unwrap()
            .fingerprint(HashAlg::Sha256);
        let f2 = russh_keys::PrivateKey::random(&mut OsRng, russh_keys::Algorithm::Ed25519)
            .unwrap()
            .fingerprint(HashAlg::Sha256);
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint().never();
        let delegator = AddressDelegator::new(
            mock,
            "_some_prefix".into(),
            "root.tld".into(),
            BindHostnames::None,
            true,
            Some(crate::config::RandomSubdomainSeed::KeyFingerprint),
        );
        let address1_f1_a1 = delegator
            .get_address(
                "a1",
                &None,
                &Some(f1.clone()),
                &"127.0.0.1:12341".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address2_f1_a1 = delegator
            .get_address(
                "a1",
                &None,
                &Some(f1.clone()),
                &"127.0.0.1:12341".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address3_f2_a1 = delegator
            .get_address(
                "a1",
                &None,
                &Some(f2.clone()),
                &"127.0.0.1:12342".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address4_f1_a2 = delegator
            .get_address(
                "a2",
                &None,
                &Some(f1.clone()),
                &"127.0.0.1:12341".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert_eq!(address1_f1_a1, address2_f1_a1);
        assert_ne!(address1_f1_a1, address3_f2_a1);
        assert_ne!(address1_f1_a1, address4_f1_a2);
        assert_ne!(address3_f2_a1, address4_f1_a2);
        assert!(DnsName::try_from(address1_f1_a1).is_ok());
        assert!(DnsName::try_from(address2_f1_a1).is_ok());
        assert!(DnsName::try_from(address3_f2_a1).is_ok());
        assert!(DnsName::try_from(address4_f1_a2).is_ok());
    }

    #[tokio::test]
    async fn returns_unique_random_subdomains_per_socket_and_address_if_forced() {
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint().never();
        let delegator = AddressDelegator::new(
            mock,
            "_some_prefix".into(),
            "root.tld".into(),
            BindHostnames::None,
            true,
            Some(crate::config::RandomSubdomainSeed::SocketAddress),
        );
        let address1_s1_a1 = delegator
            .get_address(
                "a1",
                &None,
                &None,
                &"127.0.0.1:12341".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address2_s1_a1 = delegator
            .get_address(
                "a1",
                &None,
                &None,
                &"127.0.0.1:12341".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address3_s2_a1 = delegator
            .get_address(
                "a1",
                &None,
                &None,
                &"127.0.0.1:12342".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address4_s1_a2 = delegator
            .get_address(
                "a2",
                &None,
                &None,
                &"127.0.0.1:12341".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert_eq!(address1_s1_a1, address2_s1_a1);
        assert_ne!(address1_s1_a1, address3_s2_a1);
        assert_ne!(address1_s1_a1, address4_s1_a2);
        assert_ne!(address3_s2_a1, address4_s1_a2);
        assert!(DnsName::try_from(address1_s1_a1).is_ok());
        assert!(DnsName::try_from(address2_s1_a1).is_ok());
        assert!(DnsName::try_from(address3_s2_a1).is_ok());
        assert!(DnsName::try_from(address4_s1_a2).is_ok());
    }
}
