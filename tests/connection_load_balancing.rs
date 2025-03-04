use std::{sync::Arc, time::Duration};

use clap::Parser;
use russh::keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use russh::{
    client::{Msg, Session},
    Channel,
};
use sandhole::{entrypoint, ApplicationConfig};
use tokio::{
    io::AsyncReadExt,
    net::TcpStream,
    time::{sleep, timeout},
};

#[tokio::test(flavor = "multi_thread")]
async fn connection_load_balancing() {
    // 1. Initialize Sandhole
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .is_test(true)
        .try_init();
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
        "--allow-requested-ports",
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
                PrivateKeyWithHashAlg::new(
                    Arc::new(key_1),
                    session_a.best_supported_rsa_hash().await.unwrap().flatten()
                )
            )
            .await
            .expect("SSH authentication failed")
            .success(),
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
    .expect("Missing file key2");
    let ssh_client_b = SshClientB;
    let mut session_b = russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client_b)
        .await
        .expect("Failed to connect to SSH server");
    assert!(
        session_b
            .authenticate_publickey(
                "user",
                PrivateKeyWithHashAlg::new(
                    Arc::new(key_2),
                    session_b.best_supported_rsa_hash().await.unwrap().flatten()
                )
            )
            .await
            .expect("SSH authentication failed")
            .success(),
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

impl russh::client::Handler for SshClientA {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
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
        tokio::spawn(async move {
            channel.data(&b"A"[..]).await.unwrap();
            channel.eof().await.unwrap();
        });
        Ok(())
    }
}

struct SshClientB;

impl russh::client::Handler for SshClientB {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
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
        tokio::spawn(async move {
            channel.data(&b"B"[..]).await.unwrap();
            channel.eof().await.unwrap();
        });
        Ok(())
    }
}
