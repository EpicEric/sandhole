use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use clap::Parser;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use russh::{
    Channel,
    client::{Msg, Session},
    keys::ssh_key::private::Ed25519Keypair,
};
use russh::{
    ChannelId,
    keys::{key::PrivateKeyWithHashAlg, load_secret_key},
};
use sandhole::{ApplicationConfig, entrypoint};
use tokio::{
    net::TcpStream,
    sync::oneshot,
    time::{sleep, timeout},
};

use crate::common::SandholeHandle;

/// This test ensures that queued alias connections get a spot
/// when the pool gets released.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn alias_pool_timeout() {
    // 1. Initialize Sandhole
    let config = ApplicationConfig::parse_from([
        "sandhole",
        "--domain=foobar.tld",
        "--user-keys-directory",
        &(format!(
            "{}/tests/data/user_keys",
            std::env::var("CARGO_MANIFEST_DIR").unwrap()
        )),
        "--admin-keys-directory",
        &(format!(
            "{}/tests/data/admin_keys",
            std::env::var("CARGO_MANIFEST_DIR").unwrap()
        )),
        "--certificates-directory",
        &(format!(
            "{}/tests/data/certificates",
            std::env::var("CARGO_MANIFEST_DIR").unwrap()
        )),
        "--private-key-file",
        &(format!(
            "{}/tests/data/server_keys/ssh",
            std::env::var("CARGO_MANIFEST_DIR").unwrap()
        )),
        "--acme-cache-directory",
        &(format!(
            "{}/tests/data/acme_cache",
            std::env::var("CARGO_MANIFEST_DIR").unwrap()
        )),
        "--disable-directory-creation",
        "--listen-address=127.0.0.1",
        "--ssh-port=18022",
        "--http-port=18080",
        "--https-port=18443",
        "--acme-use-staging",
        "--bind-hostnames=all",
        "--idle-connection-timeout=1s",
        "--authentication-request-timeout=5s",
        "--http-request-timeout=10s",
        "--pool-size=10",
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
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("tests/data/private_keys/key1"),
        None,
    )
    .expect("Missing file key1");
    let (tx, rx) = oneshot::channel();
    let ssh_client = SshClient(Some(tx));
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
        .tcpip_forward("some.alias", 12345)
        .await
        .expect("tcpip_forward failed");
    let channel = session
        .channel_open_session()
        .await
        .expect("channel_open_session_failed");
    channel.exec(true, "pool=2").await.expect("exec failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.await.unwrap() }).await else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());

    // 3. Start long-running requests that fill the pool
    let mut jhs = Vec::new();
    let started = Instant::now();
    for _ in 0..2 {
        let key = russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(
            &ChaCha20Rng::from_os_rng().random(),
        ));
        let ssh_client = SshAliasClient;
        let mut client_session =
            russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
                .await
                .expect("Failed to connect to SSH server");
        assert!(
            client_session
                .authenticate_publickey(
                    "user",
                    PrivateKeyWithHashAlg::new(
                        Arc::new(key),
                        client_session
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
        let mut channel = client_session
            .channel_open_direct_tcpip("some.alias", 12345, "::1", 23456)
            .await
            .expect("Local forwarding failed");
        let jh = tokio::spawn(async move {
            while let Some(msg) = channel.wait().await {
                if let russh::ChannelMsg::Data { data } = msg {
                    assert_eq!(&data[..], &b"Ping"[..]);
                    break;
                }
            }
            drop(client_session);
        });
        jhs.push(jh);
    }

    // 4. Start request that gets rate-limited from pool exhaustion
    tokio::time::sleep(Duration::from_millis(500)).await;
    let key = russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(
        &ChaCha20Rng::from_os_rng().random(),
    ));
    let ssh_client = SshAliasClient;
    let mut client_session =
        russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
            .await
            .expect("Failed to connect to SSH server");
    assert!(
        client_session
            .authenticate_publickey(
                "user",
                PrivateKeyWithHashAlg::new(
                    Arc::new(key),
                    client_session
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
    assert!(
        client_session
            .channel_open_direct_tcpip("some.alias", 12345, "::1", 23456)
            .await
            .is_err()
    );

    // 5. Start request that gets queued and eventually completes
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let key = russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(
        &ChaCha20Rng::from_os_rng().random(),
    ));
    let ssh_client = SshAliasClient;
    let mut client_session =
        russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
            .await
            .expect("Failed to connect to SSH server");
    assert!(
        client_session
            .authenticate_publickey(
                "user",
                PrivateKeyWithHashAlg::new(
                    Arc::new(key),
                    client_session
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
    assert!(started.elapsed() < Duration::from_secs(5));
    let mut channel = client_session
        .channel_open_direct_tcpip("some.alias", 12345, "::1", 23456)
        .await
        .expect("Local forwarding failed");
    let jh = tokio::spawn(async move {
        while let Some(msg) = channel.wait().await {
            if let russh::ChannelMsg::Data { data } = msg {
                assert_eq!(&data[..], &b"Ping"[..]);
                assert!(started.elapsed() > Duration::from_secs(5));
                break;
            }
        }
        drop(client_session);
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

struct SshClient(Option<oneshot::Sender<ChannelId>>);

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
            channel.data(&b"Ping"[..]).await.unwrap();
            channel.eof().await.unwrap();
            channel.close().await.unwrap();
        });
        Ok(())
    }

    async fn channel_success(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(tx) = self.0.take() {
            tx.send(channel).unwrap();
        };
        Ok(())
    }
}

struct SshAliasClient;

impl russh::client::Handler for SshAliasClient {
    type Error = color_eyre::eyre::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
