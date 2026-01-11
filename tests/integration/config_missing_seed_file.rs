use std::time::Duration;

use clap::Parser;
use rand::{rng, seq::IndexedRandom};
use sandhole::{ApplicationConfig, entrypoint};
use tokio::{fs, time::timeout};

/// This test ensures that a missing `--random-subdomain-value-file`
/// results in an error when launching Sandhole.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn config_missing_seed_file() {
    // 1. Create random temporary directory and fail to initialize Sandhole
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
    let temp_dir = std::env::temp_dir().join(format!("sandhole_test_{random_name}"));
    fs::create_dir(temp_dir.as_path())
        .await
        .expect("Unable to create tempdir");
    let config = ApplicationConfig::parse_from([
        "sandhole",
        "--domain=foobar.tld",
        "--user-keys-directory",
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/user_keys"),
        "--admin-keys-directory",
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/admin_keys"),
        "--certificates-directory",
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/certificates"),
        "--private-key-file",
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/server_keys/ssh"),
        "--acme-cache-directory",
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/acme_cache"),
        "--disable-directory-creation",
        "--listen-address=127.0.0.1",
        "--ssh-port=18022",
        "--http-port=18080",
        "--https-port=18443",
        "--acme-use-staging",
        "--bind-hostnames=none",
        "--random-subdomain-length=6",
        "--random-subdomain-seed=user",
        "--random-subdomain-value-file",
        temp_dir.join("seed").to_str().unwrap(),
        "--idle-connection-timeout=1s",
        "--authentication-request-timeout=5s",
        "--http-request-timeout=5s",
    ]);
    if timeout(Duration::from_secs(5), async {
        assert!(entrypoint(config).await.is_err());
    })
    .await
    .is_err()
    {
        panic!("Timeout waiting for Sandhole to start.")
    };
}
