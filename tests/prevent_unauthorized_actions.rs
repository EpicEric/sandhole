use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use russh::{
    client::{self, Msg, Session},
    Channel,
};
use russh_keys::{key, load_secret_key};
use sandhole::{
    config::{ApplicationConfig, BindHostnames, LoadBalancing},
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
        password_authentication_url: None,
        certificates_directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/certificates")
            .into(),
        private_key_file: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/server_keys/ssh").into(),
        disable_directory_creation: true,
        listen_address: "127.0.0.1".into(),
        ssh_port: 18022,
        http_port: 18080,
        https_port: 18443,
        force_https: false,
        disable_http_logs: false,
        disable_tcp_logs: false,
        acme_contact_email: None,
        acme_cache_directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/acme_cache").into(),
        acme_use_staging: true,
        bind_hostnames: BindHostnames::None,
        load_balancing: LoadBalancing::Allow,
        allow_provided_subdomains: false,
        allow_requested_ports: true,
        random_subdomain_seed: None,
        txt_record_prefix: "_sandhole".into(),
        idle_connection_timeout: Duration::from_millis(800),
        authentication_request_timeout: Duration::from_secs(5),
        http_request_timeout: Duration::from_secs(5),
        tcp_connection_timeout: None,
    };
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

    // 2. Start SSH client that will be proxied via alias
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
        None,
    )
    .expect("Missing file key1");
    let ssh_client = SshClient;
    let mut session = russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(session
        .authenticate_publickey("user", Arc::new(key))
        .await
        .expect("SSH authentication failed"));
    session
        .tcpip_forward("proxy.hostname", 12345)
        .await
        .expect("tcpip_forward failed");

    // 3a. Try to port forward without credentials
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

    // 3b. Try to local-forward with an inexistent alias
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

    // 3c. Try to open session without credentials
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

    // 3d. Local-forward with proxy, then try to port forward
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
        .channel_open_direct_tcpip("proxy.hostname", 12345, "my.hostname", 23456)
        .await
        .is_ok());
    assert!(!session.is_closed());
    assert!(session
        .tcpip_forward("proxy.hostname", 12345)
        .await
        .is_err());
    assert!(session.is_closed());

    // 3e. Try to idle longer than the idle_connection_timeout configuration
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
impl russh::client::Handler for SshClient {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, _key: &key::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        channel.data(&b"Hello, world!"[..]).await.unwrap();
        channel.eof().await.unwrap();
        Ok(())
    }
}
