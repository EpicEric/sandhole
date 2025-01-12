use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use clap::Parser;
use russh_keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use sandhole::{entrypoint, ApplicationConfig};
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};

#[tokio::test(flavor = "multi_thread")]
async fn config_ip_blocklist() {
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
        "--listen-address=::",
        "--ssh-port=18022",
        "--http-port=18080",
        "--https-port=18443",
        "--ip-allowlist=::/32",
        "--ip-blocklist=127.0.0.0/8",
        "--acme-use-staging",
        "--bind-hostnames=none",
        "--idle-connection-timeout=1s",
        "--authentication-request-timeout=5s",
        "--http-request-timeout=5s",
    ]);
    tokio::spawn(async move { entrypoint(config).await });
    if timeout(Duration::from_secs(5), async {
        while let Err(_) = TcpStream::connect("127.0.0.1:18022").await {
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .is_err()
    {
        panic!("Timeout waiting for Sandhole to start.")
    };

    // 2. Start SSH client that will be blocked by IP blocklist
    let ssh_client = SshClient;
    assert!(
        russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
            .await
            .is_err(),
        "SSH connection should've failed"
    );

    // 3. Start SSH client that will be allowed by IP allowlist
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
        None,
    )
    .expect("Missing file key1");
    let ssh_client = SshClient;
    let mut session = russh::client::connect(Default::default(), "[::]:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(
        session
            .authenticate_publickey(
                "user",
                PrivateKeyWithHashAlg::new(Arc::new(key), None).unwrap()
            )
            .await
            .expect("SSH authentication failed"),
        "authentication didn't succeed"
    );
}

struct SshClient;

#[async_trait]
impl russh::client::Handler for SshClient {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, _key: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}