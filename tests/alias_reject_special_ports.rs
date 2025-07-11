use std::{sync::Arc, time::Duration};

use clap::Parser;
use russh::keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use sandhole::{ApplicationConfig, entrypoint};
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};

/// This test ensures that remote forwarded aliases cannot have either port 0
/// or 10 assigned to them.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn alias_reject_special_ports() {
    // 1. Initialize Sandhole
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
        "--idle-connection-timeout=1s",
        "--authentication-request-timeout=5s",
        "--http-request-timeout=5s",
    ]);
    tokio::spawn(async move { entrypoint(config).await });
    if timeout(Duration::from_secs(5), async {
        while TcpStream::connect("127.0.0.1:18022").await.is_err() {
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .is_err()
    {
        panic!("Timeout waiting for Sandhole to start.")
    };

    for port in [0, 10] {
        // 2. Start SSH client that will fail to proxy on the port
        let key = load_secret_key(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
            None,
        )
        .expect("Missing file key1");
        let ssh_client = SshClient;
        let mut proxy_session =
            russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
                .await
                .expect("Failed to connect to SSH server");
        assert!(
            proxy_session
                .authenticate_publickey(
                    "user",
                    PrivateKeyWithHashAlg::new(
                        Arc::new(key),
                        proxy_session
                            .best_supported_rsa_hash()
                            .await
                            .unwrap()
                            .flatten()
                    )
                )
                .await
                .expect("SSH authentication failed")
                .success(),
            "authentication didn't succeed"
        );
        assert!(
            proxy_session
                .tcpip_forward("my.tunnel", port)
                .await
                .is_err(),
            "shouldn't alias on port 0"
        );
    }
}

struct SshClient;

impl russh::client::Handler for SshClient {
    type Error = color_eyre::eyre::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
