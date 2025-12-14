use std::time::Duration;

use clap::Parser;
use sandhole::{ApplicationConfig, entrypoint};
use tokio::time::timeout;

/// This test ensures that an invalid secret key path results in an error when
/// launching Sandhole.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn config_invalid_secret_key_path() {
    // 1. Fail to initialize Sandhole
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
        "/",
        "--acme-cache-directory",
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/acme_cache"),
        "--listen-address=127.0.0.1",
        "--ssh-port=18022",
        "--disable-http",
        "--disable-tcp",
        "--disable-aliasing",
        "--acme-use-staging",
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
