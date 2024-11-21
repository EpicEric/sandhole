use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use russh::client;
use russh_keys::key;
use sandhole::{
    config::{ApplicationConfig, BindHostnames},
    entrypoint,
};
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};

/// In order for tunneling to work, Sandhole must allow any public key to connect.
/// However, unauthorized users should have much more restricted access, only being allowed
/// to request local port forwarding (as of this version).
///
/// This test ensures that any other actions result in an error with a disconnect.
#[tokio::test(flavor = "multi_thread")]
async fn prevent_unauthorized_actions() {
    // 1. Initialize Sandhole
    let config = ApplicationConfig {
        domain: "foobar.tld".into(),
        domain_redirect: "https://tokio.rs/".into(),
        user_keys_directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/user_keys").into(),
        admin_keys_directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/admin_keys").into(),
        certificates_directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/certificates")
            .into(),
        private_key_file: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/server_keys/ssh").into(),
        listen_address: "127.0.0.1".into(),
        ssh_port: 18022,
        http_port: 18080,
        https_port: 18443,
        force_https: false,
        acme_contact_email: None,
        acme_cache_directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/acme_cache").into(),
        acme_use_staging: true,
        bind_hostnames: BindHostnames::None,
        allow_provided_subdomains: false,
        allow_requested_ports: true,
        random_subdomain_seed: None,
        idle_connection_timeout: Duration::from_millis(800),
        txt_record_prefix: "_sandhole".into(),
        request_timeout: Duration::from_secs(5),
    };
    tokio::spawn(async move { entrypoint(config).await });
    if let Err(_) = timeout(Duration::from_secs(5), async {
        while let Err(_) = TcpStream::connect("127.0.0.1:18022").await {
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    {
        panic!("Timeout waiting for Sandhole to start.")
    };

    // 2a. Try to port-forward without credentials
    let key = russh_keys::key::KeyPair::generate_ed25519();
    let ssh_client = SshClient;
    let mut session = client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(session
        .authenticate_publickey("user", Arc::new(key))
        .await
        .expect("SSH authentication failed"));
    assert!(session.tcpip_forward("my.hostname", 12345).await.is_err());
    assert!(session.is_closed());

    // 2b. Try to local-forward with an inexistent host
    let key = russh_keys::key::KeyPair::generate_ed25519();
    let ssh_client = SshClient;
    let mut session = client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(session
        .authenticate_publickey("user", Arc::new(key))
        .await
        .expect("SSH authentication failed"));
    assert!(session
        .channel_open_direct_tcpip("unknown.hostname", 80, "my.hostname", 12345)
        .await
        .is_err());
    assert!(session.is_closed());

    // 2c. Try to open session without credentials
    let key = russh_keys::key::KeyPair::generate_ed25519();
    let ssh_client = SshClient;
    let mut session = client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(session
        .authenticate_publickey("user", Arc::new(key))
        .await
        .expect("SSH authentication failed"));
    assert!(session.channel_open_session().await.is_err());
    assert!(session.is_closed());

    // 2d. Try to idle longer than the idle_connection_timeout configuration
    let key = russh_keys::key::KeyPair::generate_ed25519();
    let ssh_client = SshClient;
    let mut session = client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(session
        .authenticate_publickey("user", Arc::new(key))
        .await
        .expect("SSH authentication failed"));
    sleep(Duration::from_millis(1_000)).await;
    assert!(session.is_closed());
}

struct SshClient;

#[async_trait]
impl client::Handler for SshClient {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, _key: &key::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
