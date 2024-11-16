use std::{
    hash::{DefaultHasher, Hash, Hasher},
    net::SocketAddr,
    sync::LazyLock,
};

use hickory_resolver::TokioAsyncResolver;
use rand::{seq::SliceRandom, thread_rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use webpki::types::DnsName;

use crate::config::{RandomSubdomainSeed, CONFIG};

static RESOLVER: LazyLock<TokioAsyncResolver> =
    LazyLock::new(|| TokioAsyncResolver::tokio(Default::default(), Default::default()));
static TXT_RECORD_PREFIX: LazyLock<&str> =
    LazyLock::new(|| &CONFIG.get().unwrap().txt_record_prefix.trim_matches('.'));
static ROOT_DOMAIN: LazyLock<&str> =
    LazyLock::new(|| &CONFIG.get().unwrap().domain.trim_matches('.'));
static SEED: LazyLock<u64> = LazyLock::new(|| thread_rng().next_u64());

pub(crate) async fn get_address(
    requested_address: &str,
    user: &Option<String>,
    fingerprint: &Option<String>,
    socket_address: &SocketAddr,
) -> String {
    if CONFIG.get().unwrap().bind_any_host {
        return requested_address.to_string();
    }
    if DnsName::try_from(requested_address).is_ok() {
        if let Some(fingerprint) = fingerprint {
            // Verify requested address through DNS
            // TO-DO: Verify whole DNS chain for a matching fingerprint
            if let Ok(lookup) = RESOLVER
                .txt_lookup(format!("{}.{}.", *TXT_RECORD_PREFIX, requested_address))
                .await
            {
                for txt in lookup {
                    for data in txt.txt_data() {
                        if data.ends_with(fingerprint.as_bytes()) {
                            return requested_address.to_string();
                        }
                    }
                }
            }
            eprintln!("Invalid credentials for address: {}", requested_address);
        }
        if !CONFIG.get().unwrap().force_random_subdomains {
            // Assign specified subdomain under the root domain
            let address = requested_address.trim_end_matches(&format!(".{}", *ROOT_DOMAIN));
            if !address.is_empty() {
                return format!("{}.{}", address, *ROOT_DOMAIN);
            } else {
                eprintln!(
                    "Invalid address requested, defaulting to random: {}",
                    requested_address
                );
            }
        }
    } else if !CONFIG.get().unwrap().force_random_subdomains {
        eprintln!(
            "Invalid address requested, defaulting to random: {}",
            requested_address
        );
    }
    // Assign random subdomain under the root domain
    format!(
        "{}.{}",
        get_random_subdomain(user, fingerprint, socket_address),
        *ROOT_DOMAIN
    )
}

fn get_random_subdomain(
    user: &Option<String>,
    fingerprint: &Option<String>,
    socket_address: &SocketAddr,
) -> String {
    let mut hasher = DefaultHasher::default();
    SEED.hash(&mut hasher);
    let mut hash_initialized = false;
    if let Some(strategy) = CONFIG.get().unwrap().random_subdomain_seed {
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
