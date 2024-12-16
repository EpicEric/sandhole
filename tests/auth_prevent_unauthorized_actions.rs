use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use rand::rngs::OsRng;
use russh::{
    client::{self, Msg, Session},
    Channel,
};
use russh_keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use sandhole::{entrypoint, ApplicationConfig, BindHostnames, LoadBalancing};
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
async fn auth_prevent_unauthorized_actions() {
    // 1. Initialize Sandhole
    let config = ApplicationConfig {
        domain: "foobar.tld".into(),
        domain_redirect: "https://tokio.rs/".into(),
        user_keys_directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/user_keys").into(),
        admin_keys_directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/admin_keys").into(),
        certificates_directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/certificates")
            .into(),
        private_key_file: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/server_keys/ssh").into(),
        disable_directory_creation: true,
        listen_address: "127.0.0.1".into(),
        password_authentication_url: None,
        ssh_port: 18022,
        http_port: 18080,
        https_port: 18443,
        force_https: false,
        disable_http_logs: false,
        disable_tcp_logs: false,
        acme_contact_email: None,
        acme_cache_directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/acme_cache").into(),
        acme_use_staging: true,
        bind_hostnames: BindHostnames::All,
        load_balancing: LoadBalancing::Allow,
        allow_requested_subdomains: false,
        allow_requested_ports: true,
        quota_per_user: None,
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
    session
        .tcpip_forward("http.hostname", 80)
        .await
        .expect("tcpip_forward failed");
    session
        .tcpip_forward("proxy.hostname", 12345)
        .await
        .expect("tcpip_forward failed");

    // 3a. Try to port forward without credentials
    let key = russh_keys::PrivateKey::random(&mut OsRng, russh_keys::Algorithm::Ed25519).unwrap();
    let ssh_client = SshClient;
    let mut session = client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
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
    assert!(
        session.tcpip_forward("my.hostname", 12345).await.is_err(),
        "shouldn't allow remote forwarding for unauthed user"
    );
    assert!(session.is_closed(), "didn't disconnect unauthed user");

    // 3b. Try to close port forward without credentials
    let key = russh_keys::PrivateKey::random(&mut OsRng, russh_keys::Algorithm::Ed25519).unwrap();
    let ssh_client = SshClient;
    let mut session = client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
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
    assert!(
        session
            .cancel_tcpip_forward("proxy.hostname", 12345)
            .await
            .is_err(),
        "shouldn't allow canceling remote forwarding for unauthed user"
    );
    assert!(session.is_closed(), "didn't disconnect unauthed user");

    // 3c. Try to local-forward with an inexistent alias
    let key = russh_keys::PrivateKey::random(&mut OsRng, russh_keys::Algorithm::Ed25519).unwrap();
    let ssh_client = SshClient;
    let mut session = client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
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
    assert!(
        session
            .channel_open_direct_tcpip("unknown.hostname", 80, "my.hostname", 12345)
            .await
            .is_err(),
        "shouldn't allow local port forwarding for unknown service"
    );
    assert!(session.is_closed(), "didn't disconnect unauthed user");

    // 3d. Try to open session without credentials
    let key = russh_keys::PrivateKey::random(&mut OsRng, russh_keys::Algorithm::Ed25519).unwrap();
    let ssh_client = SshClient;
    let mut session = client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
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
    assert!(
        session.channel_open_session().await.is_err(),
        "shouldn't allow open session for unauthed user"
    );
    assert!(session.is_closed(), "didn't disconnect unauthed user");

    // 3e. Local-forward with HTTP proxy, then try to port forward
    let key = russh_keys::PrivateKey::random(&mut OsRng, russh_keys::Algorithm::Ed25519).unwrap();
    let ssh_client = SshClient;
    let mut session = client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
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
    assert!(
        session
            .channel_open_direct_tcpip("http.hostname", 18080, "my.hostname", 8080)
            .await
            .is_ok(),
        "didn't create valid local forwarding"
    );
    assert!(
        !session.is_closed(),
        "shouldn't disconnect valid local forwarding session"
    );
    assert!(
        session.tcpip_forward("some.hostname", 12345).await.is_err(),
        "shouldn't allow remote forwarding for unauthed user"
    );
    assert!(session.is_closed(), "didn't disconnect unauthed user");

    // 3f. Local-forward with TCP proxy, then try to port forward
    let key = russh_keys::PrivateKey::random(&mut OsRng, russh_keys::Algorithm::Ed25519).unwrap();
    let ssh_client = SshClient;
    let mut session = client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
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
    assert!(
        session
            .channel_open_direct_tcpip("proxy.hostname", 12345, "my.hostname", 23456)
            .await
            .is_ok(),
        "didn't create valid local forwarding"
    );
    assert!(
        !session.is_closed(),
        "shouldn't disconnect valid local forwarding session"
    );
    assert!(
        session
            .tcpip_forward("another.hostname", 12345)
            .await
            .is_err(),
        "shouldn't allow remote forwarding for unauthed user"
    );
    assert!(session.is_closed(), "didn't disconnect unauthed user");

    // 3g. Try to idle longer than the idle_connection_timeout configuration
    let key = russh_keys::PrivateKey::random(&mut OsRng, russh_keys::Algorithm::Ed25519).unwrap();
    let ssh_client = SshClient;
    let mut session = client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
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
    assert!(
        !session.is_closed(),
        "shouldn't disconnect valid unauthed session"
    );
    sleep(Duration::from_millis(1_000)).await;
    assert!(
        session.is_closed(),
        "didn't disconnect lingering unauthed user"
    );
}

struct SshClient;

#[async_trait]
impl russh::client::Handler for SshClient {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, _key: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
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
