use std::{sync::Arc, time::Duration};

use clap::Parser;
use rand::{rng, seq::IndexedRandom};
use russh::client::AuthResult;
use russh::keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use russh::{
    Channel,
    client::{Msg, Session},
};
use russh::{MethodKind, MethodSet};
use sandhole::{ApplicationConfig, entrypoint};
use tokio::fs;
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};

use crate::common::SandholeHandle;

/// This test ensures that Sandhole is able to configure itself from scratch,
/// including adding a user key.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn lib_configure_from_scratch() {
    // 1. Create random temporary directory and initialize Sandhole
    let random_name = String::from_utf8(
        (0..6)
            .flat_map(|_| {
                "0123456789abcdefghijklmnopqrstuvwxyz"
                    .as_bytes()
                    .choose(&mut rng())
                    .copied()
            })
            .collect(),
    )
    .unwrap();
    let temp_dir = std::env::temp_dir().join(format!("sandhole_test_{random_name}"));
    fs::create_dir(temp_dir.as_path())
        .await
        .expect("Unable to create tempdir");
    let temp_dir_path = |path: &str| temp_dir.join(path).to_string_lossy().to_string();
    let config = ApplicationConfig::parse_from([
        "sandhole",
        "--domain=foobar.tld",
        "--user-keys-directory",
        &temp_dir_path("user_keys"),
        "--admin-keys-directory",
        &temp_dir_path("admin_keys"),
        "--certificates-directory",
        &temp_dir_path("certificates"),
        "--private-key-file",
        &temp_dir_path("server_keys/ssh"),
        // Doesn't get created because ACME is disabled
        "--acme-cache-directory",
        &temp_dir_path("acme_cache"),
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

    // 2. Get authentication methods via authenticate_none
    let ssh_client = SshClient;
    let mut session = russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    match session.authenticate_none("user").await.unwrap() {
        AuthResult::Failure {
            remaining_methods,
            partial_success,
        } => {
            assert_eq!(
                remaining_methods,
                MethodSet::from([MethodKind::PublicKey].as_slice())
            );
            assert!(!partial_success);
        }
        _ => panic!("unexpected AuthResult from authenticate_none"),
    }

    // 3. Start SSH client that is not recognized
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
    assert!(
        session.tcpip_forward("localhost", 12345).await.is_err(),
        "shouldn't allow unknown user to remote forward"
    );

    // 4. Add key for SSH client that will be recognized
    fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/user_keys/keys_1_2.pub"
        ),
        temp_dir.join("user_keys/keys_1_2.pub"),
    )
    .await
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
        .expect("unable to request port-forwarding");
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
            channel.data(&b"Hello, world!"[..]).await.unwrap();
            channel.eof().await.unwrap();
        });
        Ok(())
    }
}
