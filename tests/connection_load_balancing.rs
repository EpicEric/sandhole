use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use russh::{
    client::{Msg, Session},
    Channel,
};
use russh_keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use sandhole::{entrypoint, ApplicationConfig, BindHostnames, LoadBalancing};
use ssh_key::HashAlg;
use tokio::{
    io::AsyncReadExt,
    net::TcpStream,
    time::{sleep, timeout},
};

#[tokio::test(flavor = "multi_thread")]
async fn tcp_load_balancing() {
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

    // 2. Start SSH clients that will be load-balanced
    let key_1 = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
        None,
    )
    .expect("Missing file key1");
    let ssh_client_a = SshClientA;
    let mut session_a = russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client_a)
        .await
        .expect("Failed to connect to SSH server");
    assert!(
        session_a
            .authenticate_publickey(
                "user",
                PrivateKeyWithHashAlg::new(Arc::new(key_1), None).unwrap()
            )
            .await
            .expect("SSH authentication failed"),
        "authentication didn't succeed"
    );
    session_a
        .tcpip_forward("localhost", 12345)
        .await
        .expect("tcpip_forward failed");
    let key_2 = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key2"),
        None,
    )
    .expect("Missing file key1");
    let ssh_client_b = SshClientB;
    let mut session_b = russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client_b)
        .await
        .expect("Failed to connect to SSH server");
    assert!(
        session_b
            .authenticate_publickey(
                "user",
                PrivateKeyWithHashAlg::new(Arc::new(key_2), Some(HashAlg::Sha512)).unwrap()
            )
            .await
            .expect("SSH authentication failed"),
        "authentication didn't succeed"
    );
    session_b
        .tcpip_forward("localhost", 12345)
        .await
        .expect("tcpip_forward failed");

    // 3. Connect to the TCP port of our proxy
    for _ in 0..10 {
        let mut tcp_stream = TcpStream::connect("127.0.0.1:12345")
            .await
            .expect("TCP connection failed");
        let mut buf = Vec::with_capacity(3);
        tcp_stream.read_to_end(&mut buf).await.unwrap();
        assert!(
            matches!(&buf[..], b"A" | b"B"),
            "received data didn't match expectation"
        );
    }
}

struct SshClientA;

#[async_trait]
impl russh::client::Handler for SshClientA {
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
        channel.data(&b"A"[..]).await.unwrap();
        channel.eof().await.unwrap();
        Ok(())
    }
}

struct SshClientB;

#[async_trait]
impl russh::client::Handler for SshClientB {
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
        channel.data(&b"B"[..]).await.unwrap();
        channel.eof().await.unwrap();
        Ok(())
    }
}
