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
async fn tcp_timeout() {
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
        "--http-request-timeout=5s",
        "--tcp-connection-timeout=500ms",
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

    // 2. Start SSH client that will be proxied
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
                PrivateKeyWithHashAlg::new(
                    Arc::new(key),
                    session.best_supported_rsa_hash().await.unwrap().flatten()
                )
            )
            .await
            .expect("SSH authentication failed")
            .success(),
        "authentication didn't succeed"
    );
    session
        .tcpip_forward("foobar.tld", 12345)
        .await
        .expect("tcpip_forward failed");

    // 3. Connect to the TCP port of our proxy and get timed out
    let mut tcp_stream = TcpStream::connect("127.0.0.1:12345")
        .await
        .expect("TCP connection failed");
    if timeout(Duration::from_secs(2), async {
        let mut buf = [0u8; 4];
        tcp_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"One\n");
        assert_eq!(tcp_stream.read(&mut buf).await.unwrap(), 0);
    })
    .await
    .is_err()
    {
        panic!("Timeout waiting for TCP stream to reply.")
    };
}

struct SshClient;

impl russh::client::Handler for SshClient {
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
            channel.data(&b"One\n"[..]).await.unwrap();
            sleep(Duration::from_secs(5)).await;
            channel.data(&b"Two\n"[..]).await.unwrap();
            channel.eof().await.unwrap();
        });
        Ok(())
    }
}
