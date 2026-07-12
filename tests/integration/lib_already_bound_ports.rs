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
use sandhole::{ApplicationConfig, entrypoint};
use tokio::{
    net::TcpListener,
    time::{sleep, timeout},
};

/// This test ensures that Sandhole fails to initialize if it attempts to
/// connect to a port that's already bound.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn lib_already_bound_ports() {
    for (i, port) in [18022, 18080, 18443].into_iter().enumerate() {
        if i > 0 {
            sleep(Duration::from_millis(200)).await;
        }
        // 1. Bind the specific port before Sandhole does
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("should be able to bind open port");
        // 2. Fail to initialize Sandhole
        if timeout(Duration::from_secs(2), async {
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
                &(format!(
                    "{}/tests/data/server_keys/ssh",
                    std::env::var("CARGO_MANIFEST_DIR").unwrap()
                )),
                "--acme-cache-directory",
                &(format!(
                    "{}/tests/data/acme_cache",
                    std::env::var("CARGO_MANIFEST_DIR").unwrap()
                )),
                "--disable-directory-creation",
                "--listen-address=127.0.0.1",
                "--ssh-port=18022",
                "--http-port=18080",
                "--https-port=18443",
                "--acme-use-staging",
                "--bind-hostnames=none",
                "--idle-connection-timeout=1s",
                "--authentication-request-timeout=5s",
                "--http-request-timeout=5s",
            ]);
            assert!(
                entrypoint(config).await.is_err(),
                "should've failed to start server"
            )
        })
        .await
        .is_err()
        {
            panic!("Timeout waiting for Sandhole to start.")
        };
        // 3. Unbind the port
        drop(listener);
    }
}
