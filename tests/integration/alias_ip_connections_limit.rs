use std::{sync::Arc, time::Duration};

use clap::Parser;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use russh::keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use russh::{
    Channel,
    client::{Msg, Session},
    keys::ssh_key::private::Ed25519Keypair,
};
use sandhole::{ApplicationConfig, entrypoint};
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};

use crate::common::SandholeHandle;

/// This test ensures that no more aliased connections from the same IP
/// than the specified limit are able to connect at the same time.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn alias_ip_connections_limit() {
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
        "--listen-address=::",
        "--ssh-port=18022",
        "--http-port=18080",
        "--https-port=18443",
        "--acme-use-staging",
        "--bind-hostnames=all",
        "--idle-connection-timeout=1s",
        "--authentication-request-timeout=5s",
        "--max-simultaneous-connections-per-ip=1",
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
        .tcpip_forward("some.alias", 12345)
        .await
        .expect("tcpip_forward failed");

    // 3. Start long-running request that takes the spot for the IP
    let key = russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(
        &ChaCha20Rng::from_os_rng().random(),
    ));
    let ssh_client = SshClient;
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

    // 4. Start request that gets rate-limited from IP connection exhaustion
    tokio::time::sleep(Duration::from_millis(500)).await;
    let key = russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(
        &ChaCha20Rng::from_os_rng().random(),
    ));
    let ssh_client = SshClient;
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

    // 5. Start request from different IP that succeeds
    let key = russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(
        &ChaCha20Rng::from_os_rng().random(),
    ));
    let ssh_client = SshClient;
    let mut client_session = russh::client::connect(Default::default(), "[::1]:18022", ssh_client)
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
            .is_ok(),
        "local forwarding failed"
    );

    timeout(Duration::from_secs(5), async move {
        jh.await.unwrap();
    })
    .await
    .expect("timeout waiting for join handle to finish");
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
            tokio::time::sleep(Duration::from_secs(3)).await;
            channel.data(&b"Ping"[..]).await.unwrap();
            channel.eof().await.unwrap();
            channel.close().await.unwrap();
        });
        Ok(())
    }
}
