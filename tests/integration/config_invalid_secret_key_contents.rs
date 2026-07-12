// sandhole: Expose HTTP/SSH/TCP services through SSH port forwarding
// Copyright (C) 2024-2026 Eric Rodrigues Pires
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for
// more details.
//
// You should have received a copy of the GNU Affero General Public License along
// with this program. If not, see <https://www.gnu.org/licenses/>.

use std::time::Duration;

use clap::Parser;
use rand::{rng, seq::IndexedRandom};
use sandhole::{ApplicationConfig, entrypoint};
use tokio::{fs, time::timeout};

/// This test ensures that an invalid secret key results in an error when
/// launching Sandhole.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn config_invalid_secret_key_contents() {
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
    let temp_dir_path = |path: &str| temp_dir.join(path).to_string_lossy().to_string();
    fs::write(temp_dir_path("bad_ssh_key"), "bad data")
        .await
        .expect("Failed to write bad SSH key.");
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
        &temp_dir_path("bad_ssh_key"),
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
