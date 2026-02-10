use std::time::Duration;

use clap::Parser;
use rand::{rng, seq::IndexedRandom};
use sandhole::{ApplicationConfig, entrypoint};
use tokio::{fs, time::timeout};

/// This test ensures that setting a read-only directory for the secret key
/// results in an error when launching Sandhole.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn config_no_write_permissions_for_secret_key() {
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
    temp_dir
        .metadata()
        .expect("Failed to get metadata for tempdir")
        .permissions()
        .set_readonly(true);
    let temp_dir_path = |path: &str| temp_dir.join(path).to_string_lossy().to_string();
    let config = ApplicationConfig::parse_from([
        "sandhole",
        "--domain=foobar.tld",
        "--user-keys-directory",
        &(format!(
            "{}/tests/data/user_keys",
            std::env::var("CARGO_MANIFEST_DIR").unwrap()
        )),
        "--admin-keys-directory",
        &(format!(
            "{}/tests/data/admin_keys",
            std::env::var("CARGO_MANIFEST_DIR").unwrap()
        )),
        "--certificates-directory",
        &(format!(
            "{}/tests/data/certificates",
            std::env::var("CARGO_MANIFEST_DIR").unwrap()
        )),
        "--private-key-file",
        &temp_dir_path("unwritable_ssh_file"),
        "--acme-cache-directory",
        &(format!(
            "{}/tests/data/acme_cache",
            std::env::var("CARGO_MANIFEST_DIR").unwrap()
        )),
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
