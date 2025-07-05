use std::{sync::Arc, time::Duration};

use clap::Parser;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use russh::{
    Channel,
    client::{self, Msg, Session},
};
use sandhole::{ApplicationConfig, entrypoint};
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};

/// This test ensures that aliases with the allowed-fingerprints option can only
/// be locally forwarded to by the provided fingerprints.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn alias_require_allowed_fingerprints() {
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
        "--idle-connection-timeout=800ms",
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

    // 2. Start SSH client that will be proxied via alias for specific fingerprints
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
        .tcpip_forward("proxy.hostname", 12345)
        .await
        .expect("tcpip_forward failed");
    let channel = session
        .channel_open_session()
        .await
        .expect("channel_open_session_failed");
    channel
        .exec(
            false,
            // key1 and admin
            "allowed-fingerprints=\
            SHA256:GehKyA21BBK6eJCouziacUmqYDNl8BPMGG0CTtLSrbQ,\
            SHA256:eDZoeAWBWd+SO64PPW1VBrdlBxYM4OEywSkGlIy0Kro",
        )
        .await
        .expect("exec failed");

    // 3a. Local-forward with valid key
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
        None,
    )
    .expect("Missing file key1");
    let ssh_client = SshClient;
    let mut session = client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
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
    let mut channel = session
        .channel_open_direct_tcpip("proxy.hostname", 12345, "my.hostname", 23456)
        .await
        .expect("channel_open_direct_tcpip failed");
    if timeout(Duration::from_secs(5), async {
        match channel.wait().await.unwrap() {
            russh::ChannelMsg::Data { data } => {
                assert_eq!(data.to_vec(), b"Hello, some of the world!");
            }
            msg => panic!("Unexpected message {msg:?}"),
        }
    })
    .await
    .is_err()
    {
        panic!("Timeout waiting for server to reply.")
    };

    // 3b. Try to local-forward with invalid key
    let key = russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(
        &ChaCha20Rng::from_os_rng().random(),
    ));
    let ssh_client = SshClient;
    let mut session = client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
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
    assert!(
        session
            .channel_open_direct_tcpip("proxy.hostname", 12345, "my.hostname", 23456)
            .await
            .is_err(),
        "shouldn't be able to connect to restricted tunnel"
    );
    assert!(
        !session.is_closed(),
        "shouldn't immediately close connection for unauthenticated session"
    );
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
            channel
                .data(&b"Hello, some of the world!"[..])
                .await
                .unwrap();
            channel.eof().await.unwrap();
        });
        Ok(())
    }
}
