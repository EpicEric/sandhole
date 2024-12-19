use std::{fs, sync::Arc, time::Duration};

use async_trait::async_trait;
use rand::{seq::SliceRandom, thread_rng};
use russh::{
    client::{Msg, Session},
    Channel,
};
use russh_keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use sandhole::{entrypoint, ApplicationConfig, BindHostnames, LoadBalancing};
use ssh_key::HashAlg;
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};

#[tokio::test(flavor = "multi_thread")]
async fn lib_configure_from_scratch() {
    // 1. Create random temporary directory and initialize Sandhole
    let random_name = String::from_utf8(
        (0..6)
            .flat_map(|_| {
                "0123456789abcdefghijklmnopqrstuvwxyz"
                    .as_bytes()
                    .choose(&mut thread_rng())
                    .copied()
            })
            .collect(),
    )
    .unwrap();
    let temp_dir = std::env::temp_dir().join(random_name);
    fs::create_dir(temp_dir.as_path()).unwrap();
    let config = ApplicationConfig {
        domain: "foobar.tld".into(),
        domain_redirect: "https://tokio.rs/".into(),
        user_keys_directory: temp_dir.join("user_keys"),
        admin_keys_directory: temp_dir.join("admin_keys"),
        certificates_directory: temp_dir.join("certificates"),
        private_key_file: temp_dir.join("server_keys/ssh"),
        disable_directory_creation: false,
        listen_address: "127.0.0.1".into(),
        password_authentication_url: None,
        ssh_port: 18022,
        http_port: 18080,
        https_port: 18443,
        connect_ssh_on_https_port: false,
        force_https: false,
        disable_http_logs: false,
        disable_tcp_logs: false,
        acme_contact_email: None,
        acme_cache_directory: temp_dir.join("acme_cache"), // Doesn't get created because ACME is disabled
        acme_use_staging: true,
        bind_hostnames: BindHostnames::None,
        load_balancing: LoadBalancing::Allow,
        allow_requested_subdomains: false,
        allow_requested_ports: true,
        quota_per_user: None,
        random_subdomain_seed: None,
        txt_record_prefix: "_sandhole".into(),
        idle_connection_timeout: Duration::from_secs(1),
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
    assert!(temp_dir.join("user_keys").is_dir(), "missing user_keys dir");
    assert!(
        temp_dir.join("admin_keys").is_dir(),
        "missing admin_keys dir"
    );
    assert!(
        temp_dir.join("certificates").is_dir(),
        "missing certificates dir"
    );
    assert!(
        temp_dir.join("server_keys").is_dir(),
        "missing server_keys dir"
    );
    assert!(
        temp_dir.join("server_keys/ssh").is_file(),
        "missing server_keys/ssh file"
    );

    // 2. Start SSH client that is not recognized
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
    assert!(
        session.tcpip_forward("localhost", 12345).await.is_err(),
        "shouldn't allow unknown user to remote forward"
    );

    // 3. Add key for SSH client that will be recognized
    fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/user_keys/keys_1_2.pub"
        ),
        temp_dir.join("user_keys/keys_1_2.pub"),
    )
    .expect("cannot copy key2");
    // Wait for debounce on user pubkeys watcher (2s) + time to process the file
    sleep(Duration::from_millis(3_000)).await;
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key2"),
        None,
    )
    .expect("Missing file key2");
    let ssh_client = SshClient;
    let mut session = russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(
        session
            .authenticate_publickey(
                "user",
                PrivateKeyWithHashAlg::new(Arc::new(key), Some(HashAlg::Sha512)).unwrap()
            )
            .await
            .expect("SSH authentication failed"),
        "authentication didn't succeed"
    );
    session
        .tcpip_forward("localhost", 12345)
        .await
        .expect("unable to request port-forwarding");
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
