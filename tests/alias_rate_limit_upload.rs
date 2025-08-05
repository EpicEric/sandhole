use std::time::Instant;
use std::{sync::Arc, time::Duration};

use clap::Parser;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use russh::{
    Channel,
    client::{Msg, Session},
};
use sandhole::{ApplicationConfig, entrypoint};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};

/// This test ensures that upload rate limiting works as expected for aliases.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn alias_rate_limit_upload() {
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
    let mut proxy_session =
        russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
            .await
            .expect("Failed to connect to SSH server");
    assert!(
        proxy_session
            .authenticate_publickey(
                "user",
                PrivateKeyWithHashAlg::new(
                    Arc::new(key),
                    proxy_session
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
    proxy_session
        .tcpip_forward("my.tunnel", 42)
        .await
        .expect("tcpip_forward failed");
    assert!(
        TcpStream::connect("127.0.0.1:42").await.is_err(),
        "alias shouldn't create socket listener"
    );

    // 3. Establish a tunnel via aliasing
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
    let channel = client_session
        .channel_open_direct_tcpip("my.tunnel", 42, "::1", 23456)
        .await
        .expect("Local forwarding failed");
    let mut data = vec![0u8; 55_000];
    let start = Instant::now();
    channel.into_stream().read_exact(&mut data).await.unwrap();
    let elapsed = start.elapsed();
    assert!(
        elapsed > Duration::from_secs(2),
        "must've taken more than 2 seconds, but was {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "must've taken less than 3 seconds, but was {elapsed:?}"
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
        let mut data = vec![0u8; 55_000];
        rand::rng().fill_bytes(&mut data);
        tokio::spawn(async move {
            let mut stream = channel.into_stream();
            stream.write_all(&data).await.unwrap();
        });
        Ok(())
    }
}
