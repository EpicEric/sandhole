use std::{
    hash::{DefaultHasher, Hash, Hasher},
    net::SocketAddr,
};

use hickory_resolver::TokioAsyncResolver;
use rand::{seq::SliceRandom, thread_rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use webpki::types::DnsName;

use crate::config::RandomSubdomainSeed;

pub(crate) struct AddressDelegator {
    resolver: TokioAsyncResolver,
    txt_record_prefix: String,
    root_domain: String,
    seed: u64,
    random_subdomain_seed: Option<RandomSubdomainSeed>,
    bind_any_host: bool,
    force_random_subdomains: bool,
}

impl AddressDelegator {
    pub(crate) fn new(
        resolver: TokioAsyncResolver,
        txt_record_prefix: String,
        root_domain: String,
        bind_any_host: bool,
        force_random_subdomains: bool,
        random_subdomain_seed: Option<RandomSubdomainSeed>,
    ) -> Self {
        debug_assert!(!txt_record_prefix.is_empty());
        debug_assert!(!root_domain.is_empty());
        AddressDelegator {
            resolver,
            txt_record_prefix,
            root_domain,
            bind_any_host,
            force_random_subdomains,
            random_subdomain_seed,
            seed: thread_rng().next_u64(),
        }
    }

    pub(crate) async fn get_address(
        &self,
        requested_address: &str,
        user: &Option<String>,
        fingerprint: &Option<String>,
        socket_address: &SocketAddr,
    ) -> String {
        if self.bind_any_host {
            return requested_address.to_string();
        }
        if DnsName::try_from(requested_address).is_ok() {
            if let Some(fingerprint) = fingerprint {
                // Verify requested address through DNS
                // TO-DO: Allow verifying whole subdomain chain for a matching fingerprint
                if let Ok(lookup) = self
                    .resolver
                    .txt_lookup(format!("{}.{}.", self.txt_record_prefix, requested_address))
                    .await
                {
                    for data in lookup.iter().flat_map(|txt| txt.iter()) {
                        if data.ends_with(fingerprint.as_bytes()) {
                            return requested_address.to_string();
                        }
                    }
                }
                eprintln!("Invalid credentials for address: {}", requested_address);
            }
            if !self.force_random_subdomains {
                // Assign specified subdomain under the root domain
                let address = requested_address.trim_end_matches(&format!(".{}", self.root_domain));
                if !address.is_empty() {
                    return format!("{}.{}", address, self.root_domain);
                } else {
                    eprintln!(
                        "Invalid address requested, defaulting to random: {}",
                        requested_address
                    );
                }
            }
        } else if !self.force_random_subdomains {
            eprintln!(
                "Invalid address requested, defaulting to random: {}",
                requested_address
            );
        }
        // Assign random subdomain under the root domain
        format!(
            "{}.{}",
            self.get_random_subdomain(user, fingerprint, socket_address),
            self.root_domain
        )
    }

    fn get_random_subdomain(
        &self,
        user: &Option<String>,
        fingerprint: &Option<String>,
        socket_address: &SocketAddr,
    ) -> String {
        let mut hasher = DefaultHasher::default();
        self.seed.hash(&mut hasher);
        let mut hash_initialized = false;
        if let Some(strategy) = self.random_subdomain_seed {
            match strategy {
                RandomSubdomainSeed::User => {
                    if let Some(user) = user {
                        user.hash(&mut hasher);
                        hash_initialized = true;
                    } else {
                        eprintln!("No SSH user when assigning subdomain. Defaulting to random.")
                    }
                }
                RandomSubdomainSeed::KeyFingerprint => {
                    if let Some(fingerprint) = fingerprint {
                        fingerprint.hash(&mut hasher);
                        hash_initialized = true;
                    } else {
                        eprintln!(
                            "No SSH key fingerprint when assigning subdomain. Defaulting to random."
                        )
                    }
                }
                RandomSubdomainSeed::SocketAddress => {
                    socket_address.hash(&mut hasher);
                }
            }
        }
        if !hash_initialized {
            // Random seed
            thread_rng().next_u64().hash(&mut hasher);
        }
        // Generate random subdomain from hashed state
        // TODO: Use more entropy than 64 bits
        let mut rng = ChaCha20Rng::seed_from_u64(hasher.finish());
        String::from_utf8(
            "0123456789abcdefghijklmnopqrstuvwxyz"
                .as_bytes()
                .choose_multiple(&mut rng, 6)
                .copied()
                .collect(),
        )
        .unwrap()
    }
}
