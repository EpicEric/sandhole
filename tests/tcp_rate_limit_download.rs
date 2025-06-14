use std::time::Instant;
use std::{sync::Arc, time::Duration};

use clap::Parser;
use rand::RngCore;
use russh::ChannelMsg;
use russh::{
    Channel,
    client::{Msg, Session},
    keys::{key::PrivateKeyWithHashAlg, load_secret_key},
};
use sandhole::{ApplicationConfig, entrypoint};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};

/// This test ensures that upload rate limiting works as expected for TCP
/// services.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn tcp_rate_limit_download() {
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
        "--allow-requested-ports",
        "--idle-connection-timeout=1s",
        "--authentication-request-timeout=5s",
        "--http-request-timeout=5s",
        "--buffer-size=20KB",
        "--rate-limit-per-user=20KB",
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
    let mut session_one = russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(
        session_one
            .authenticate_publickey(
                "user",
                PrivateKeyWithHashAlg::new(
                    Arc::new(key),
                    session_one
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
    session_one
        .tcpip_forward("foobar.tld", 12345)
        .await
        .expect("tcpip_forward failed");

    // 3. Connect to the TCP port of our proxy
    let mut data = vec![0u8; 50_000];
    rand::rng().fill_bytes(&mut data);
    let mut tcp_stream = TcpStream::connect("127.0.0.1:12345")
        .await
        .expect("TCP connection failed");
    let start = Instant::now();
    tcp_stream.write_all(&data).await.unwrap();
    let mut buf = [0u8; 1];
    tcp_stream.read_exact(&mut buf).await.unwrap();
    let elapsed = start.elapsed();
    assert_eq!(buf, &[42][..]);
    assert!(
        elapsed > Duration::from_secs(2),
        "must've taken more than 2 seconds, but was {:?}",
        elapsed
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "must've taken less than 3 seconds, but was {:?}",
        elapsed
    );
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
        mut channel: Channel<Msg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        tokio::spawn(async move {
            let mut expected_len = 50_000;
            while let Some(msg) = channel.wait().await {
                if let ChannelMsg::Data { data } = msg {
                    expected_len -= data.len();
                    if expected_len == 0 {
                        channel.data(&[42][..]).await.unwrap();
                        return;
                    }
                }
            }
        });
        Ok(())
    }
}
