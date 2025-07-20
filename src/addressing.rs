use std::{hash::Hash, net::SocketAddr, sync::Mutex};

use block_id::{Alphabet, BlockId};
use bon::Builder;
use hickory_resolver::{TokioResolver, proto::rr::RecordType};
use itertools::Itertools;
use rand::{self, Rng, SeedableRng, seq::IndexedRandom};
use rand_chacha::ChaCha20Rng;
use rand_seeder::SipHasher;
use russh::keys::ssh_key::Fingerprint;
use rustls_pki_types::DnsName;
use rustrict::CensorStr;
use tracing::{debug, warn};

use crate::config::{BindHostnames, RandomSubdomainSeed};

// Struct wrapping a DNS async resolver.
pub(crate) struct DnsResolver(TokioResolver);

// Trait for DNS record verification.
#[cfg_attr(test, mockall::automock)]
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
        DnsResolver(
            TokioResolver::builder_tokio()
                .expect("failed to create DNS resolver")
                .build(),
        )
    }
}

impl Resolver for DnsResolver {
    // Check if there is a TXT record for the provided fingerprint.
    async fn has_txt_record_for_fingerprint(
        &self,
        txt_record_prefix: &str,
        requested_address: &str,
        fingerprint: &Fingerprint,
    ) -> bool {
        // Find the TXT entries.
        match self
            .0
            .txt_lookup(format!("{txt_record_prefix}.{requested_address}."))
            .await
        {
            Ok(lookup) => {
                // Iterate over the TXT records
                lookup.iter().any(|txt| {
                    txt.iter().any(|data| {
                        // See if the parsed record matches the given fingerprint
                        String::from_utf8_lossy(data)
                            .parse::<Fingerprint>()
                            .as_ref()
                            == Ok(fingerprint)
                    })
                })
            }
            _ => false,
        }
    }

    // Check if there is a CNAME record pointing to Sandhole's domain.
    async fn has_cname_record_for_domain(&self, requested_address: &str, domain: &str) -> bool {
        // Find the CNAME entries
        match self
            .0
            .lookup(format!("{requested_address}."), RecordType::CNAME)
            .await
        {
            Ok(lookup) => {
                // Iterate over the CNAME records
                lookup
                    .iter()
                    .filter_map(|rdata| rdata.clone().into_cname().ok())
                    .any(|cname| {
                        // Retrieve the domain name from the pieces
                        let cname = cname
                            .iter()
                            .map(|data| String::from_utf8_lossy(data))
                            .join(".");
                        debug!(%cname, "Checking CNAME.");
                        // Check if the domain name matches
                        cname == domain
                    })
            }
            _ => false,
        }
    }
}

// Service that assigns addresses to HTTP proxies.
#[derive(Builder)]
pub(crate) struct AddressDelegator<R> {
    // The length of the string appended to the start of random subdomains.
    #[builder(setters(vis = "", name = random_subdomain_length_internal))]
    random_subdomain_length: usize,
    // Mapping between numbers and IDs.
    #[builder(setters(vis = "", name = block_id_internal))]
    block_id: BlockId<char>,
    // DNS resolver.
    resolver: R,
    // Prefix to add for TXT records.
    txt_record_prefix: String,
    // Root domain for Sandhole.
    root_domain: String,
    // Policy on how to allow binding hostnames.
    bind_hostnames: BindHostnames,
    // Whether subdomains should be random or not.
    force_random_subdomains: bool,
    // Policy for generating random subdomains.
    random_subdomain_seed: Option<RandomSubdomainSeed>,
    // Whether profanities should be filtered out from random subdomain addressing.
    random_subdomain_filter_profanities: bool,
    // Trie to optionally verify for profanities in requested domains.
    requested_domain_filter_profanities: bool,
    // Trie to optionally verify for profanities in requested subdomains.
    requested_subdomain_filter_profanities: bool,
    // Random seed for generating consistent yet secure random values.
    #[builder(default = rand::rng().random())]
    seed: u64,
    // Counter to generate random IDs with the block ID.
    #[builder(skip = Mutex::new(0))]
    block_rng: Mutex<u64>,
}

impl<R, S: address_delegator_builder::State> AddressDelegatorBuilder<R, S> {
    pub(crate) fn random_subdomain_length(
        self,
        length: impl Copy + Into<u8>,
    ) -> AddressDelegatorBuilder<
        R,
        address_delegator_builder::SetBlockId<
            address_delegator_builder::SetRandomSubdomainLength<S>,
        >,
    >
    where
        S::RandomSubdomainLength: address_delegator_builder::IsUnset,
        S::BlockId: address_delegator_builder::IsUnset,
    {
        self.random_subdomain_length_internal(length.into().into())
            .block_id_internal(BlockId::new(
                Alphabet::lowercase_alphanumeric(),
                rand::rng().random(),
                length.into(),
            ))
    }
}

impl<R: Resolver> AddressDelegator<R> {
    // Assign an HTTP address given the current configuration
    pub(crate) async fn get_http_address(
        &self,
        requested_address: &str,
        user: &Option<String>,
        fingerprint: &Option<Fingerprint>,
        socket_address: &SocketAddr,
    ) -> String {
        // Only consider valid DNS addresses
        if DnsName::try_from(requested_address).is_ok() {
            let subdomain = requested_address.trim_end_matches(&format!(".{}", self.root_domain));
            let is_subdomain = !subdomain.is_empty() && !subdomain.contains('.');
            // Ensure that the domain/subdomain passes the profanity filter(s) if set
            if (is_subdomain
                && self.requested_subdomain_filter_profanities
                && subdomain.is_inappropriate())
                || (!is_subdomain
                    && self.requested_domain_filter_profanities
                    && requested_address.is_inappropriate())
            {
                warn!(%requested_address, "Profane address requested, defaulting to random.");
            } else {
                // If we bind all hostnames, return the provided address
                if matches!(self.bind_hostnames, BindHostnames::All) {
                    return requested_address.to_string();
                }
                // If we bind by CNAME records, check that this address points to Sandhole's root domain
                if matches!(self.bind_hostnames, BindHostnames::Cname)
                    && requested_address != self.root_domain
                    && self
                        .resolver
                        .has_cname_record_for_domain(requested_address, &self.root_domain)
                        .await
                {
                    return requested_address.to_string();
                }
                // If we bind by TXT or CNAME records, check that the public key's fingerprint is among the TXT records
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
                // If subdomains aren't random, check if user provided a valid one
                if !self.force_random_subdomains {
                    if is_subdomain {
                        // Assign specified subdomain under the root domain
                        return format!("{}.{}", subdomain, self.root_domain);
                    } else {
                        warn!(
                            %requested_address, "Invalid address requested, defaulting to random."
                        );
                    }
                }
            }
        } else {
            warn!(%requested_address, "Invalid address requested, defaulting to random.");
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
        // Use a hasher to generate the random address
        let mut hasher = SipHasher::default();
        // Populate initially with the address delegator's random seed
        self.seed.hash(&mut hasher);
        // Keep track of whether the hash was initialized in the first pass or not
        let mut hash_initialized = false;
        // Hash with the given strategy
        if let Some(ref strategy) = self.random_subdomain_seed {
            match strategy {
                // Requested address and user
                RandomSubdomainSeed::User => {
                    if let Some(user) = user {
                        requested_address.hash(&mut hasher);
                        user.hash(&mut hasher);
                        hash_initialized = true;
                    } else {
                        warn!("No SSH user when assigning subdomain. Defaulting to random.")
                    }
                }
                // Requested address, user, and fingerprint
                RandomSubdomainSeed::Fingerprint => {
                    if let Some(user) = user {
                        requested_address.hash(&mut hasher);
                        user.hash(&mut hasher);
                        hash_initialized = true;
                        if let Some(fingerprint) = fingerprint {
                            fingerprint.as_bytes().hash(&mut hasher);
                        }
                    } else if let Some(fingerprint) = fingerprint {
                        requested_address.hash(&mut hasher);
                        fingerprint.as_bytes().hash(&mut hasher);
                        hash_initialized = true;
                    } else {
                        warn!(
                            "No SSH user or key fingerprint when assigning subdomain. Defaulting to random."
                        )
                    }
                }
                // Requested address, IP, and user
                RandomSubdomainSeed::IpAndUser => {
                    requested_address.hash(&mut hasher);
                    socket_address.ip().hash(&mut hasher);
                    if let Some(user) = user {
                        user.hash(&mut hasher);
                    }
                    hash_initialized = true;
                }
                // Requested address
                RandomSubdomainSeed::Address => {
                    requested_address.hash(&mut hasher);
                    socket_address.hash(&mut hasher);
                    hash_initialized = true;
                }
            }
        }
        if hash_initialized {
            // Generate random subdomain from hashed state
            let mut hasher_rng = hasher.into_rng();
            loop {
                let mut seed: <ChaCha20Rng as SeedableRng>::Seed = Default::default();
                hasher_rng.fill(&mut seed);
                let mut rng = ChaCha20Rng::from_seed(seed);
                let result = String::from_utf8(
                    (0..self.random_subdomain_length)
                        .flat_map(|_| {
                            b"0123456789abcdefghijklmnopqrstuvwxyz"
                                .choose(&mut rng)
                                .copied()
                        })
                        .collect(),
                )
                .unwrap();
                if !self.random_subdomain_filter_profanities || !result.is_inappropriate() {
                    break result;
                }
            }
        } else {
            // Hash hasn't been initialized, use block ID to generate a random string
            let mut result = loop {
                let mut block_rng = self.block_rng.lock().unwrap();
                let result = self.block_id.encode_string(*block_rng).unwrap();
                *block_rng = block_rng.wrapping_add(1);
                if !self.random_subdomain_filter_profanities || !result.is_inappropriate() {
                    break result;
                }
            };
            result.drain(self.random_subdomain_length..);
            result
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod address_delegator_tests {
    use std::{collections::HashSet, net::SocketAddr};

    use mockall::predicate::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use regex::Regex;
    use russh::keys::{HashAlg, ssh_key::private::Ed25519Keypair};
    use rustls_pki_types::DnsName;

    use crate::config::{BindHostnames, RandomSubdomainSeed};

    use super::{AddressDelegator, MockResolver};

    #[test_log::test(tokio::test)]
    async fn returns_provided_address_when_binding_any_host() {
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint().never();
        let delegator = AddressDelegator::builder()
            .resolver(mock)
            .txt_record_prefix("_some_prefix".into())
            .root_domain("root.tld".into())
            .bind_hostnames(BindHostnames::All)
            .force_random_subdomains(false)
            .random_subdomain_length(6)
            .random_subdomain_filter_profanities(false)
            .requested_domain_filter_profanities(false)
            .requested_subdomain_filter_profanities(false)
            .build();
        let address = delegator
            .get_http_address(
                "some.address",
                &None,
                &None,
                &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert_eq!(address, "some.address");
        assert!(
            DnsName::try_from(address.clone()).is_ok(),
            "non DNS-compatible address {address}"
        );
    }

    #[test_log::test(tokio::test)]
    async fn returns_root_domain_when_binding_any_host() {
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint().never();
        let delegator = AddressDelegator::builder()
            .resolver(mock)
            .txt_record_prefix("_some_prefix".into())
            .root_domain("root.tld".into())
            .bind_hostnames(BindHostnames::All)
            .force_random_subdomains(false)
            .random_subdomain_length(6)
            .random_subdomain_filter_profanities(false)
            .requested_domain_filter_profanities(false)
            .requested_subdomain_filter_profanities(false)
            .build();
        let address = delegator
            .get_http_address(
                "root.tld",
                &None,
                &None,
                &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert_eq!(address, "root.tld");
        assert!(
            DnsName::try_from(address.clone()).is_ok(),
            "non DNS-compatible address {address}"
        );
    }

    #[test_log::test(tokio::test)]
    async fn returns_provided_address_when_cname_is_match() {
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint().never();
        mock.expect_has_cname_record_for_domain()
            .once()
            .return_const(true);
        let delegator = AddressDelegator::builder()
            .resolver(mock)
            .txt_record_prefix("_some_prefix".into())
            .root_domain("root.tld".into())
            .bind_hostnames(BindHostnames::Cname)
            .force_random_subdomains(false)
            .random_subdomain_length(6)
            .random_subdomain_filter_profanities(false)
            .requested_domain_filter_profanities(false)
            .requested_subdomain_filter_profanities(false)
            .build();
        let address = delegator
            .get_http_address(
                "some.address",
                &None,
                &None,
                &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert_eq!(address, "some.address");
        assert!(
            DnsName::try_from(address.clone()).is_ok(),
            "non DNS-compatible address {address}"
        );
    }

    #[test_log::test(tokio::test)]
    async fn returns_provided_address_if_cname_matches_fingerprint() {
        let fingerprint = russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(
            &ChaCha20Rng::from_os_rng().random(),
        ))
        .fingerprint(HashAlg::Sha256);
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint()
            .with(eq("_some_prefix"), eq("some.address"), eq(fingerprint))
            .return_const(true);
        mock.expect_has_cname_record_for_domain()
            .once()
            .return_const(false);
        let delegator = AddressDelegator::builder()
            .resolver(mock)
            .txt_record_prefix("_some_prefix".into())
            .root_domain("root.tld".into())
            .bind_hostnames(BindHostnames::Cname)
            .force_random_subdomains(false)
            .random_subdomain_length(6)
            .random_subdomain_filter_profanities(false)
            .requested_domain_filter_profanities(false)
            .requested_subdomain_filter_profanities(false)
            .build();
        let address = delegator
            .get_http_address(
                "some.address",
                &None,
                &Some(fingerprint),
                &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert_eq!(address, "some.address");
        assert!(
            DnsName::try_from(address.clone()).is_ok(),
            "non DNS-compatible address {address}"
        );
    }

    #[test_log::test(tokio::test)]
    async fn returns_provided_address_if_txt_record_matches_fingerprint() {
        let fingerprint = russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(
            &ChaCha20Rng::from_os_rng().random(),
        ))
        .fingerprint(HashAlg::Sha256);
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint()
            .with(eq("_some_prefix"), eq("some.address"), eq(fingerprint))
            .return_const(true);
        let delegator = AddressDelegator::builder()
            .resolver(mock)
            .txt_record_prefix("_some_prefix".into())
            .root_domain("root.tld".into())
            .bind_hostnames(BindHostnames::Txt)
            .force_random_subdomains(false)
            .random_subdomain_length(6)
            .random_subdomain_filter_profanities(false)
            .requested_domain_filter_profanities(false)
            .requested_subdomain_filter_profanities(false)
            .build();
        let address = delegator
            .get_http_address(
                "some.address",
                &None,
                &Some(fingerprint),
                &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert_eq!(address, "some.address");
        assert!(
            DnsName::try_from(address.clone()).is_ok(),
            "non DNS-compatible address {address}"
        );
    }

    #[test_log::test(tokio::test)]
    async fn returns_provided_subdomain_if_no_fingerprint() {
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint()
            .never()
            .return_const(true);
        let delegator = AddressDelegator::builder()
            .resolver(mock)
            .txt_record_prefix("_some_prefix".into())
            .root_domain("root.tld".into())
            .bind_hostnames(BindHostnames::Txt)
            .force_random_subdomains(false)
            .random_subdomain_length(6)
            .random_subdomain_filter_profanities(false)
            .requested_domain_filter_profanities(false)
            .requested_subdomain_filter_profanities(false)
            .build();
        let address = delegator
            .get_http_address(
                "subdomain",
                &None,
                &None,
                &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert_eq!(address, "subdomain.root.tld");
        assert!(
            DnsName::try_from(address.clone()).is_ok(),
            "non DNS-compatible address {address}"
        );
    }

    #[test_log::test(tokio::test)]
    async fn returns_subdomain_if_no_txt_record_matches_fingerprint() {
        let fingerprint = russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(
            &ChaCha20Rng::from_os_rng().random(),
        ))
        .fingerprint(HashAlg::Sha256);
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint()
            .with(eq("_some_prefix"), eq("something"), eq(fingerprint))
            .return_const(false);
        let delegator = AddressDelegator::builder()
            .resolver(mock)
            .txt_record_prefix("_some_prefix".into())
            .root_domain("root.tld".into())
            .bind_hostnames(BindHostnames::Txt)
            .force_random_subdomains(false)
            .random_subdomain_length(6)
            .random_subdomain_filter_profanities(false)
            .requested_domain_filter_profanities(false)
            .requested_subdomain_filter_profanities(false)
            .build();
        let address = delegator
            .get_http_address(
                "something",
                &None,
                &Some(fingerprint),
                &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert_eq!(address, "something.root.tld");
        assert!(
            DnsName::try_from(address.clone()).is_ok(),
            "non DNS-compatible address {address}"
        );
    }

    #[test_log::test(tokio::test)]
    async fn returns_subdomain_if_requested_subdomain_of_host_domain() {
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint().never();
        let delegator = AddressDelegator::builder()
            .resolver(mock)
            .txt_record_prefix("_some_prefix".into())
            .root_domain("root.tld".into())
            .bind_hostnames(BindHostnames::None)
            .force_random_subdomains(false)
            .random_subdomain_length(6)
            .random_subdomain_filter_profanities(false)
            .requested_domain_filter_profanities(false)
            .requested_subdomain_filter_profanities(false)
            .build();
        let address = delegator
            .get_http_address(
                "prefix.root.tld",
                &None,
                &None,
                &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert_eq!(address, "prefix.root.tld");
        assert!(
            DnsName::try_from(address.clone()).is_ok(),
            "non DNS-compatible address {address}"
        );
    }

    #[test_log::test(tokio::test)]
    async fn returns_host_domain_if_address_equals_host_domain_and_has_fingerprint() {
        let fingerprint = russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(
            &ChaCha20Rng::from_os_rng().random(),
        ))
        .fingerprint(HashAlg::Sha256);
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint()
            .once()
            .return_const(true);
        let delegator = AddressDelegator::builder()
            .resolver(mock)
            .txt_record_prefix("_some_prefix".into())
            .root_domain("root.tld".into())
            .bind_hostnames(BindHostnames::Txt)
            .force_random_subdomains(false)
            .random_subdomain_length(6)
            .random_subdomain_filter_profanities(false)
            .requested_domain_filter_profanities(false)
            .requested_subdomain_filter_profanities(false)
            .build();
        let address = delegator
            .get_http_address(
                "root.tld",
                &None,
                &Some(fingerprint),
                &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert_eq!(address, "root.tld");
        assert!(
            DnsName::try_from(address.clone()).is_ok(),
            "non DNS-compatible address {address}"
        );
    }

    #[test_log::test(tokio::test)]
    async fn returns_random_subdomain_if_address_equals_host_domain_and_doesnt_have_fingerprint() {
        let fingerprint = russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(
            &ChaCha20Rng::from_os_rng().random(),
        ))
        .fingerprint(HashAlg::Sha256);
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint()
            .once()
            .return_const(false);
        let delegator = AddressDelegator::builder()
            .resolver(mock)
            .txt_record_prefix("_some_prefix".into())
            .root_domain("root.tld".into())
            .bind_hostnames(BindHostnames::Txt)
            .force_random_subdomains(false)
            .random_subdomain_length(6)
            .random_subdomain_filter_profanities(false)
            .requested_domain_filter_profanities(false)
            .requested_subdomain_filter_profanities(false)
            .build();
        let address = delegator
            .get_http_address(
                "root.tld",
                &None,
                &Some(fingerprint),
                &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert!(
            Regex::new(r"^[0-9a-z]{6}\.root\.tld$")
                .unwrap()
                .is_match(&address),
            "invalid address {address}"
        );
        assert!(
            DnsName::try_from(address.clone()).is_ok(),
            "non DNS-compatible address {address}"
        );
    }

    #[test_log::test(tokio::test)]
    async fn returns_random_subdomain_if_requested_address_is_not_direct_subdomain() {
        let fingerprint = russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(
            &ChaCha20Rng::from_os_rng().random(),
        ))
        .fingerprint(HashAlg::Sha256);
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint()
            .once()
            .return_const(false);
        let delegator = AddressDelegator::builder()
            .resolver(mock)
            .txt_record_prefix("_some_prefix".into())
            .root_domain("root.tld".into())
            .bind_hostnames(BindHostnames::Txt)
            .force_random_subdomains(false)
            .random_subdomain_length(6)
            .random_subdomain_filter_profanities(false)
            .requested_domain_filter_profanities(false)
            .requested_subdomain_filter_profanities(false)
            .build();
        let address = delegator
            .get_http_address(
                "we.are.root.tld",
                &None,
                &Some(fingerprint),
                &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert!(
            Regex::new(r"^[0-9a-z]{6}\.root\.tld$")
                .unwrap()
                .is_match(&address),
            "invalid address {address}"
        );
        assert!(
            DnsName::try_from(address.clone()).is_ok(),
            "non DNS-compatible address {address}"
        );
    }

    #[test_log::test(tokio::test)]
    async fn returns_random_subdomain_if_invalid_address() {
        let fingerprint = russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(
            &ChaCha20Rng::from_os_rng().random(),
        ))
        .fingerprint(HashAlg::Sha256);
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint().never();
        let delegator = AddressDelegator::builder()
            .resolver(mock)
            .txt_record_prefix("_some_prefix".into())
            .root_domain("root.tld".into())
            .bind_hostnames(BindHostnames::Cname)
            .force_random_subdomains(false)
            .random_subdomain_length(6)
            .random_subdomain_filter_profanities(false)
            .requested_domain_filter_profanities(false)
            .requested_subdomain_filter_profanities(false)
            .build();
        let address = delegator
            .get_http_address(
                ".",
                &None,
                &Some(fingerprint),
                &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert!(
            Regex::new(r"^[0-9a-z]{6}\.root\.tld$")
                .unwrap()
                .is_match(&address),
            "invalid address {address}"
        );
        assert!(
            DnsName::try_from(address.clone()).is_ok(),
            "non DNS-compatible address {address}"
        );
    }

    #[test_log::test(tokio::test)]
    async fn returns_unique_random_subdomains_if_forced() {
        let fingerprint = russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(
            &ChaCha20Rng::from_os_rng().random(),
        ))
        .fingerprint(HashAlg::Sha256);
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint().never();
        let delegator = AddressDelegator::builder()
            .resolver(mock)
            .txt_record_prefix("_some_prefix".into())
            .root_domain("root.tld".into())
            .bind_hostnames(BindHostnames::None)
            .force_random_subdomains(true)
            .random_subdomain_length(6)
            .random_subdomain_filter_profanities(false)
            .requested_domain_filter_profanities(false)
            .requested_subdomain_filter_profanities(false)
            .build();
        // 99.99% chance of collision with naïve implementation
        static SIZE: usize = 200_000;
        let mut set = HashSet::with_capacity(SIZE);
        let regex = Regex::new(r"^[0-9a-z]{6}\.root\.tld$").unwrap();
        let initial_block_rng = *delegator.block_rng.lock().unwrap();
        for _ in 0..SIZE {
            let address = delegator
                .get_http_address(
                    "some.address",
                    &None,
                    &Some(fingerprint),
                    &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
                )
                .await;
            assert!(regex.is_match(&address), "invalid address {address}");
            assert!(
                DnsName::try_from(address.clone()).is_ok(),
                "non DNS-compatible address {address}"
            );
            assert!(
                !set.contains(&address),
                "generated non-unique address: {address}"
            );
            set.insert(address);
        }
        let final_block_rng = *delegator.block_rng.lock().unwrap();
        assert_eq!((final_block_rng - initial_block_rng) as usize, SIZE);
    }

    #[test_log::test(tokio::test)]
    async fn returns_unique_random_subdomains_with_different_size_and_no_profanities() {
        let fingerprint = russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(
            &ChaCha20Rng::from_os_rng().random(),
        ))
        .fingerprint(HashAlg::Sha256);
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint().never();
        let delegator = AddressDelegator::builder()
            .resolver(mock)
            .txt_record_prefix("_some_prefix".into())
            .root_domain("root.tld".into())
            .bind_hostnames(BindHostnames::None)
            .force_random_subdomains(true)
            .random_subdomain_length(4)
            .random_subdomain_filter_profanities(true)
            .requested_domain_filter_profanities(false)
            .requested_subdomain_filter_profanities(false)
            .build();
        // 99.99999...% chance of collision with naïve implementation
        static SIZE: usize = 10_000;
        let mut set = HashSet::with_capacity(SIZE);
        let regex = Regex::new(r"^[0-9a-z]{4}\.root\.tld$").unwrap();
        let initial_block_rng = *delegator.block_rng.lock().unwrap();
        for _ in 0..SIZE {
            let address = delegator
                .get_http_address(
                    "some.address",
                    &None,
                    &Some(fingerprint),
                    &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
                )
                .await;
            assert!(regex.is_match(&address), "invalid address {address}");
            assert!(
                DnsName::try_from(address.clone()).is_ok(),
                "non DNS-compatible address {address}"
            );
            assert!(
                !set.contains(&address),
                "generated non-unique address: {address}"
            );
            set.insert(address);
        }
        let final_block_rng = *delegator.block_rng.lock().unwrap();
        assert!(
            (final_block_rng - initial_block_rng) as usize > SIZE,
            "expected at least one word to get filtered"
        );
    }

    #[test_log::test(tokio::test)]
    async fn returns_random_subdomain_if_requested_subdomain_contains_profanity() {
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint().never();
        let delegator = AddressDelegator::builder()
            .resolver(mock)
            .txt_record_prefix("_some_prefix".into())
            .root_domain("root.tld".into())
            .bind_hostnames(BindHostnames::All)
            .force_random_subdomains(false)
            .random_subdomain_length(8)
            .random_subdomain_filter_profanities(false)
            .requested_domain_filter_profanities(false)
            .requested_subdomain_filter_profanities(true)
            .build();
        let address = delegator
            .get_http_address(
                "fuck.root.tld",
                &None,
                &None,
                &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert!(
            Regex::new(r"^[0-9a-z]{8}\.root\.tld$")
                .unwrap()
                .is_match(&address),
            "invalid address {address}"
        );
        assert!(
            !address.contains("fuck"),
            "address contains user-provided profanity"
        );
        assert!(
            DnsName::try_from(address.clone()).is_ok(),
            "non DNS-compatible address {address}"
        );
    }

    #[test_log::test(tokio::test)]
    async fn returns_random_subdomain_if_requested_domain_contains_profanity() {
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint().never();
        let delegator = AddressDelegator::builder()
            .resolver(mock)
            .txt_record_prefix("_some_prefix".into())
            .root_domain("root.tld".into())
            .bind_hostnames(BindHostnames::All)
            .force_random_subdomains(false)
            .random_subdomain_length(8)
            .random_subdomain_filter_profanities(false)
            .requested_domain_filter_profanities(true)
            .requested_subdomain_filter_profanities(false)
            .build();
        let address = delegator
            .get_http_address(
                "fuck.another.tld",
                &None,
                &None,
                &"127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert!(
            Regex::new(r"^[0-9a-z]{8}\.root\.tld$")
                .unwrap()
                .is_match(&address),
            "invalid address {address}"
        );
        assert!(
            !address.contains("fuck"),
            "address contains user-provided profanity"
        );
        assert!(
            DnsName::try_from(address.clone()).is_ok(),
            "non DNS-compatible address {address}"
        );
    }

    #[test_log::test(tokio::test)]
    async fn returns_unique_random_subdomains_per_user_and_address_if_forced() {
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint().never();
        let delegator = AddressDelegator::builder()
            .resolver(mock)
            .txt_record_prefix("_some_prefix".into())
            .root_domain("root.tld".into())
            .bind_hostnames(BindHostnames::None)
            .force_random_subdomains(true)
            .random_subdomain_seed(RandomSubdomainSeed::User)
            .random_subdomain_length(6)
            .random_subdomain_filter_profanities(false)
            .requested_domain_filter_profanities(false)
            .requested_subdomain_filter_profanities(false)
            .build();
        let address1_u1_a1 = delegator
            .get_http_address(
                "a1",
                &Some("u1".into()),
                &None,
                &"127.0.0.1:12301".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address2_u1_a1 = delegator
            .get_http_address(
                "a1",
                &Some("u1".into()),
                &None,
                &"127.0.0.1:12302".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address3_u2_a1 = delegator
            .get_http_address(
                "a1",
                &Some("u2".into()),
                &None,
                &"127.0.0.1:12303".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address4_u1_a2 = delegator
            .get_http_address(
                "a2",
                &Some("u1".into()),
                &None,
                &"127.0.0.1:12304".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert_eq!(address1_u1_a1, address2_u1_a1);
        assert_ne!(address1_u1_a1, address3_u2_a1);
        assert_ne!(address1_u1_a1, address4_u1_a2);
        assert_ne!(address3_u2_a1, address4_u1_a2);
        assert!(
            DnsName::try_from(address1_u1_a1.clone()).is_ok(),
            "non DNS-compatible address {address1_u1_a1}"
        );
        assert!(
            DnsName::try_from(address2_u1_a1.clone()).is_ok(),
            "non DNS-compatible address {address2_u1_a1}"
        );
        assert!(
            DnsName::try_from(address3_u2_a1.clone()).is_ok(),
            "non DNS-compatible address {address3_u2_a1}"
        );
        assert!(
            DnsName::try_from(address4_u1_a2.clone()).is_ok(),
            "non DNS-compatible address {address4_u1_a2}"
        );
    }

    #[test_log::test(tokio::test)]
    async fn returns_unique_random_subdomains_per_fingerprint_user_and_address_if_forced() {
        let f1: russh::keys::ssh_key::Fingerprint = russh::keys::PrivateKey::from(
            Ed25519Keypair::from_seed(&ChaCha20Rng::from_os_rng().random()),
        )
        .fingerprint(HashAlg::Sha256);
        let f2 = russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(
            &ChaCha20Rng::from_os_rng().random(),
        ))
        .fingerprint(HashAlg::Sha256);
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint().never();
        let delegator = AddressDelegator::builder()
            .resolver(mock)
            .txt_record_prefix("_some_prefix".into())
            .root_domain("root.tld".into())
            .bind_hostnames(BindHostnames::None)
            .force_random_subdomains(true)
            .random_subdomain_seed(RandomSubdomainSeed::Fingerprint)
            .random_subdomain_length(6)
            .random_subdomain_filter_profanities(false)
            .requested_domain_filter_profanities(false)
            .requested_subdomain_filter_profanities(false)
            .build();
        let address1_f1_a1_u0 = delegator
            .get_http_address(
                "a1",
                &None,
                &Some(f1),
                &"127.0.0.1:12301".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address2_f1_a1_u0 = delegator
            .get_http_address(
                "a1",
                &None,
                &Some(f1),
                &"127.0.0.1:12302".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address3_f2_a1_u0 = delegator
            .get_http_address(
                "a1",
                &None,
                &Some(f2),
                &"127.0.0.1:12303".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address4_f1_a2_u0 = delegator
            .get_http_address(
                "a2",
                &None,
                &Some(f1),
                &"127.0.0.1:12304".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address5_f1_a1_u1 = delegator
            .get_http_address(
                "a1",
                &Some("u1".into()),
                &Some(f1),
                &"127.0.0.1:12305".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address6_f1_a1_u1 = delegator
            .get_http_address(
                "a1",
                &Some("u1".into()),
                &Some(f1),
                &"127.0.0.1:12306".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address7_f2_a1_u1 = delegator
            .get_http_address(
                "a1",
                &Some("u1".into()),
                &Some(f2),
                &"127.0.0.1:12307".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address8_f1_a2_u1 = delegator
            .get_http_address(
                "a2",
                &Some("u1".into()),
                &Some(f1),
                &"127.0.0.1:12308".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address9_f1_a1_u2 = delegator
            .get_http_address(
                "a1",
                &Some("u2".into()),
                &Some(f1),
                &"127.0.0.1:12309".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address10_f1_a1_u2 = delegator
            .get_http_address(
                "a1",
                &Some("u2".into()),
                &Some(f1),
                &"127.0.0.1:12310".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address11_f2_a1_u2 = delegator
            .get_http_address(
                "a1",
                &Some("u2".into()),
                &Some(f2),
                &"127.0.0.1:12311".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address12_f1_a2_u2 = delegator
            .get_http_address(
                "a2",
                &Some("u2".into()),
                &Some(f1),
                &"127.0.0.1:12312".parse::<SocketAddr>().unwrap(),
            )
            .await;

        assert_eq!(address1_f1_a1_u0, address2_f1_a1_u0);
        assert_ne!(address1_f1_a1_u0, address3_f2_a1_u0);
        assert_ne!(address1_f1_a1_u0, address4_f1_a2_u0);
        assert_ne!(address3_f2_a1_u0, address4_f1_a2_u0);

        assert_eq!(address5_f1_a1_u1, address6_f1_a1_u1);
        assert_ne!(address5_f1_a1_u1, address7_f2_a1_u1);
        assert_ne!(address5_f1_a1_u1, address8_f1_a2_u1);
        assert_ne!(address7_f2_a1_u1, address8_f1_a2_u1);

        assert_eq!(address9_f1_a1_u2, address10_f1_a1_u2);
        assert_ne!(address9_f1_a1_u2, address11_f2_a1_u2);
        assert_ne!(address9_f1_a1_u2, address12_f1_a2_u2);
        assert_ne!(address11_f2_a1_u2, address12_f1_a2_u2);

        assert_ne!(address1_f1_a1_u0, address5_f1_a1_u1);
        assert_ne!(address1_f1_a1_u0, address9_f1_a1_u2);
        assert_ne!(address5_f1_a1_u1, address9_f1_a1_u2);

        assert!(
            DnsName::try_from(address1_f1_a1_u0.clone()).is_ok(),
            "non DNS-compatible address {address1_f1_a1_u0}"
        );
        assert!(
            DnsName::try_from(address2_f1_a1_u0.clone()).is_ok(),
            "non DNS-compatible address {address2_f1_a1_u0}"
        );
        assert!(
            DnsName::try_from(address3_f2_a1_u0.clone()).is_ok(),
            "non DNS-compatible address {address3_f2_a1_u0}"
        );
        assert!(
            DnsName::try_from(address4_f1_a2_u0.clone()).is_ok(),
            "non DNS-compatible address {address4_f1_a2_u0}"
        );
        assert!(
            DnsName::try_from(address5_f1_a1_u1.clone()).is_ok(),
            "non DNS-compatible address {address5_f1_a1_u1}"
        );
        assert!(
            DnsName::try_from(address6_f1_a1_u1.clone()).is_ok(),
            "non DNS-compatible address {address6_f1_a1_u1}"
        );
        assert!(
            DnsName::try_from(address7_f2_a1_u1.clone()).is_ok(),
            "non DNS-compatible address {address7_f2_a1_u1}"
        );
        assert!(
            DnsName::try_from(address8_f1_a2_u1.clone()).is_ok(),
            "non DNS-compatible address {address8_f1_a2_u1}"
        );
        assert!(
            DnsName::try_from(address9_f1_a1_u2.clone()).is_ok(),
            "non DNS-compatible address {address9_f1_a1_u2}"
        );
        assert!(
            DnsName::try_from(address10_f1_a1_u2.clone()).is_ok(),
            "non DNS-compatible address {address10_f1_a1_u2}"
        );
        assert!(
            DnsName::try_from(address11_f2_a1_u2.clone()).is_ok(),
            "non DNS-compatible address {address11_f2_a1_u2}"
        );
        assert!(
            DnsName::try_from(address12_f1_a2_u2.clone()).is_ok(),
            "non DNS-compatible address {address12_f1_a2_u2}"
        );
    }

    #[test_log::test(tokio::test)]
    async fn returns_unique_random_subdomains_per_ip_and_user_if_forced() {
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint().never();
        let delegator = AddressDelegator::builder()
            .resolver(mock)
            .txt_record_prefix("_some_prefix".into())
            .root_domain("root.tld".into())
            .bind_hostnames(BindHostnames::None)
            .force_random_subdomains(true)
            .random_subdomain_seed(RandomSubdomainSeed::IpAndUser)
            .random_subdomain_length(6)
            .random_subdomain_filter_profanities(false)
            .requested_domain_filter_profanities(false)
            .requested_subdomain_filter_profanities(false)
            .build();
        let address1_u1_i1 = delegator
            .get_http_address(
                "a1",
                &Some("user1".into()),
                &None,
                &"192.168.0.1:12301".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address2_u1_i1 = delegator
            .get_http_address(
                "a1",
                &Some("user1".into()),
                &None,
                &"192.168.0.1:12302".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address3_u2_i1 = delegator
            .get_http_address(
                "a1",
                &Some("user2".into()),
                &None,
                &"192.168.0.1:12303".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address4_u1_i2 = delegator
            .get_http_address(
                "a1",
                &Some("user1".into()),
                &None,
                &"192.168.0.2:12304".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert_eq!(address1_u1_i1, address2_u1_i1);
        assert_ne!(address1_u1_i1, address3_u2_i1);
        assert_ne!(address1_u1_i1, address4_u1_i2);
        assert_ne!(address3_u2_i1, address4_u1_i2);
        assert!(
            DnsName::try_from(address1_u1_i1.clone()).is_ok(),
            "non DNS-compatible address {address1_u1_i1}"
        );
        assert!(
            DnsName::try_from(address2_u1_i1.clone()).is_ok(),
            "non DNS-compatible address {address2_u1_i1}"
        );
        assert!(
            DnsName::try_from(address3_u2_i1.clone()).is_ok(),
            "non DNS-compatible address {address3_u2_i1}"
        );
        assert!(
            DnsName::try_from(address4_u1_i2.clone()).is_ok(),
            "non DNS-compatible address {address4_u1_i2}"
        );
    }

    #[test_log::test(tokio::test)]
    async fn returns_unique_random_subdomains_per_socket_and_address_if_forced() {
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint().never();
        let delegator = AddressDelegator::builder()
            .resolver(mock)
            .txt_record_prefix("_some_prefix".into())
            .root_domain("root.tld".into())
            .bind_hostnames(BindHostnames::None)
            .force_random_subdomains(true)
            .random_subdomain_seed(RandomSubdomainSeed::Address)
            .random_subdomain_length(6)
            .random_subdomain_filter_profanities(false)
            .requested_domain_filter_profanities(false)
            .requested_subdomain_filter_profanities(false)
            .build();
        let address1_s1_a1 = delegator
            .get_http_address(
                "a1",
                &None,
                &None,
                &"127.0.0.1:12301".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address2_s1_a1 = delegator
            .get_http_address(
                "a1",
                &None,
                &None,
                &"127.0.0.1:12301".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address3_s2_a1 = delegator
            .get_http_address(
                "a1",
                &None,
                &None,
                &"127.0.0.1:12302".parse::<SocketAddr>().unwrap(),
            )
            .await;
        let address4_s1_a2 = delegator
            .get_http_address(
                "a2",
                &None,
                &None,
                &"127.0.0.1:12301".parse::<SocketAddr>().unwrap(),
            )
            .await;
        assert_eq!(address1_s1_a1, address2_s1_a1);
        assert_ne!(address1_s1_a1, address3_s2_a1);
        assert_ne!(address1_s1_a1, address4_s1_a2);
        assert_ne!(address3_s2_a1, address4_s1_a2);
        assert!(
            DnsName::try_from(address1_s1_a1.clone()).is_ok(),
            "non DNS-compatible address {address1_s1_a1}"
        );
        assert!(
            DnsName::try_from(address2_s1_a1.clone()).is_ok(),
            "non DNS-compatible address {address2_s1_a1}"
        );
        assert!(
            DnsName::try_from(address3_s2_a1.clone()).is_ok(),
            "non DNS-compatible address {address3_s2_a1}"
        );
        assert!(
            DnsName::try_from(address4_s1_a2.clone()).is_ok(),
            "non DNS-compatible address {address4_s1_a2}"
        );
    }

    #[test_log::test(tokio::test)]
    async fn returns_fixed_subdomains_for_ip_and_user_if_set_seed() {
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint().never();
        let delegator = AddressDelegator::builder()
            .resolver(mock)
            .txt_record_prefix("_some_prefix".into())
            .root_domain("root.tld".into())
            .bind_hostnames(BindHostnames::None)
            .force_random_subdomains(true)
            .random_subdomain_seed(RandomSubdomainSeed::IpAndUser)
            .random_subdomain_length(6)
            .random_subdomain_filter_profanities(false)
            .requested_domain_filter_profanities(false)
            .requested_subdomain_filter_profanities(false)
            .seed(42)
            .build();
        assert_eq!(
            delegator
                .get_http_address(
                    "address",
                    &Some("user".into()),
                    &None,
                    &"127.0.0.1:12345".parse().unwrap()
                )
                .await,
            "2z4fd6.root.tld"
        );
    }

    #[test_log::test(tokio::test)]
    async fn returns_fixed_subdomains_for_user_if_set_seed() {
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint().never();
        let delegator = AddressDelegator::builder()
            .resolver(mock)
            .txt_record_prefix("_some_prefix".into())
            .root_domain("root.tld".into())
            .bind_hostnames(BindHostnames::None)
            .force_random_subdomains(true)
            .random_subdomain_seed(RandomSubdomainSeed::User)
            .random_subdomain_length(6)
            .random_subdomain_filter_profanities(false)
            .requested_domain_filter_profanities(false)
            .requested_subdomain_filter_profanities(false)
            .seed(42)
            .build();
        assert_eq!(
            delegator
                .get_http_address(
                    "address",
                    &Some("user".into()),
                    &None,
                    &"127.0.0.1:12345".parse().unwrap()
                )
                .await,
            "aec4bv.root.tld"
        );
    }

    #[test_log::test(tokio::test)]
    async fn returns_fixed_subdomains_for_address_if_set_seed() {
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint().never();
        let delegator = AddressDelegator::builder()
            .resolver(mock)
            .txt_record_prefix("_some_prefix".into())
            .root_domain("root.tld".into())
            .bind_hostnames(BindHostnames::None)
            .force_random_subdomains(true)
            .random_subdomain_seed(RandomSubdomainSeed::Address)
            .random_subdomain_length(6)
            .random_subdomain_filter_profanities(false)
            .requested_domain_filter_profanities(false)
            .requested_subdomain_filter_profanities(false)
            .seed(42)
            .build();
        assert_eq!(
            delegator
                .get_http_address("address", &None, &None, &"127.0.0.1:12345".parse().unwrap())
                .await,
            "c95czw.root.tld"
        );
    }

    #[test_log::test(tokio::test)]
    async fn returns_fixed_subdomains_for_fingerprint_if_set_seed() {
        let fingerprint: russh::keys::ssh_key::Fingerprint = russh::keys::PrivateKey::from(
            Ed25519Keypair::from_seed(&(0..32).collect::<Vec<_>>().try_into().unwrap()),
        )
        .fingerprint(HashAlg::Sha256);
        let mut mock = MockResolver::new();
        mock.expect_has_txt_record_for_fingerprint().never();
        let delegator = AddressDelegator::builder()
            .resolver(mock)
            .txt_record_prefix("_some_prefix".into())
            .root_domain("root.tld".into())
            .bind_hostnames(BindHostnames::None)
            .force_random_subdomains(true)
            .random_subdomain_seed(RandomSubdomainSeed::Fingerprint)
            .random_subdomain_length(6)
            .random_subdomain_filter_profanities(false)
            .requested_domain_filter_profanities(false)
            .requested_subdomain_filter_profanities(false)
            .seed(42)
            .build();
        assert_eq!(
            delegator
                .get_http_address(
                    "address",
                    &None,
                    &Some(fingerprint),
                    &"127.0.0.1:12345".parse().unwrap()
                )
                .await,
            "3g68u5.root.tld"
        );
    }
}
