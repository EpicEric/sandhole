use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use clap::Parser;
use russh::keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use russh::{
    Channel,
    client::{Msg, Session},
};
use sandhole::{ApplicationConfig, entrypoint};
use tokio::{
    io::AsyncReadExt,
    net::TcpStream,
    time::{sleep, timeout},
};

use crate::common::SandholeHandle;

/// This test ensures that queued connections get a spot
/// when the pool gets released.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn tcp_pool_timeout() {
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
        "--allow-requested-ports",
        "--idle-connection-timeout=1s",
        "--authentication-request-timeout=5s",
        "--http-request-timeout=10s",
        "--pool-size=2",
        "--pool-timeout=3s",
    ]);
    let _sandhole_handle = SandholeHandle(tokio::spawn(async move { entrypoint(config).await }));
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
        .tcpip_forward("localhost", 12345)
        .await
        .expect("tcpip_forward failed");

    // 3. Start long-running requests that fill the pool
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut jhs = Vec::new();
    let started = Instant::now();
    for _ in 0..2 {
        let mut tcp_stream = TcpStream::connect("127.0.0.1:12345")
            .await
            .expect("TCP connection failed");
        let jh = tokio::spawn(async move {
            let mut data = [0u8; 10];
            tcp_stream.read_exact(&mut data).await.unwrap();
            assert_eq!(data, b"0123456789"[..]);
        });
        jhs.push(jh);
    }

    // 3. Start request that gets rate-limited from pool exhaustion
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut tcp_stream = TcpStream::connect("127.0.0.1:12345")
        .await
        .expect("TCP connection failed");
    let mut data = [0u8; 10];
    assert!(tcp_stream.read_exact(&mut data).await.is_err());

    // 4. Start request that gets queued and eventually completes
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let mut tcp_stream = TcpStream::connect("127.0.0.1:12345")
        .await
        .expect("TCP connection failed");
    let jh = tokio::spawn(async move {
        let mut data = [0u8; 10];
        assert!(started.elapsed() < Duration::from_secs(5));
        tcp_stream.read_exact(&mut data).await.unwrap();
        assert!(started.elapsed() > Duration::from_secs(5));
        assert_eq!(data, b"0123456789"[..]);
    });
    jhs.push(jh);

    timeout(Duration::from_secs(10), async move {
        for jh in jhs {
            jh.await.unwrap();
        }
    })
    .await
    .expect("timeout waiting for join handles to finish");
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
            tokio::time::sleep(Duration::from_secs(5)).await;
            channel.data(&b"0123456789"[..]).await.unwrap();
            channel.eof().await.unwrap();
            channel.close().await.unwrap();
        });
        Ok(())
    }
}
