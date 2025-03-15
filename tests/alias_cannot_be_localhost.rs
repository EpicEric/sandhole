use std::{sync::Arc, time::Duration};

use clap::Parser;
use russh::{
    ChannelId,
    keys::{key::PrivateKeyWithHashAlg, load_secret_key},
};
use sandhole::{ApplicationConfig, entrypoint};
use tokio::{
    net::TcpStream,
    sync::mpsc,
    time::{sleep, timeout},
};

#[tokio::test(flavor = "multi_thread")]
async fn alias_cannot_be_localhost() {
    // 1. Initialize Sandhole
    let _ = env_logger::builder()
        .filter_module("sandhole", log::LevelFilter::Debug)
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

    // 2a. Start SSH client that will fail to convert HTTP into alias via `tcp-alias`
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
        None,
    )
    .expect("Missing file key1");
    let (tx, mut rx) = mpsc::unbounded_channel();
    let ssh_client = SshClientWithChannelFailure(tx);
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
        .tcpip_forward("localhost", 80)
        .await
        .expect("tcpip_forward failed");
    let channel = session
        .channel_open_session()
        .await
        .expect("channel_open_session failed");
    channel
        .exec(true, "tcp-alias")
        .await
        .expect("exec tcp-alias failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
    sleep(Duration::from_millis(200)).await;
    assert!(session.is_closed(), "session should've been closed");
    // 2b. Start SSH client that will fail to convert HTTP into alias via `allowed-fingerprints`
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
        None,
    )
    .expect("Missing file key1");
    let (tx, mut rx) = mpsc::unbounded_channel();
    let ssh_client = SshClientWithChannelFailure(tx);
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
        .tcpip_forward("localhost", 80)
        .await
        .expect("tcpip_forward failed");
    let channel = session
        .channel_open_session()
        .await
        .expect("channel_open_session failed");
    channel
        .exec(
            true,
            "allowed-fingerprints=SHA256:GehKyA21BBK6eJCouziacUmqYDNl8BPMGG0CTtLSrbQ",
        )
        .await
        .expect("exec allowed-fingerprints failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
    sleep(Duration::from_millis(200)).await;
    assert!(session.is_closed(), "session should've been closed");
    // 2c. Start SSH client that will fail to create localhost HTTP after invoking `tcp-alias`
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
        None,
    )
    .expect("Missing file key1");
    let (tx, mut rx) = mpsc::unbounded_channel();
    let ssh_client = SshClientWithChannelSuccess(tx);
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
    let channel = session
        .channel_open_session()
        .await
        .expect("channel_open_session failed");
    channel
        .exec(true, "tcp-alias")
        .await
        .expect("exec tcp-alias failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
    assert!(
        session.tcpip_forward("localhost", 80).await.is_err(),
        "tcpip_forward with localhost should've failed"
    );
    assert!(!session.is_closed(), "session shouldn't have been closed");
    // 2d. Start SSH client that will fail to create localhost HTTP after invoking `allowed-fingerprints`
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
        None,
    )
    .expect("Missing file key1");
    let (tx, mut rx) = mpsc::unbounded_channel();
    let ssh_client = SshClientWithChannelSuccess(tx);
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
    let channel = session
        .channel_open_session()
        .await
        .expect("channel_open_session failed");
    channel
        .exec(
            true,
            "allowed-fingerprints=SHA256:GehKyA21BBK6eJCouziacUmqYDNl8BPMGG0CTtLSrbQ",
        )
        .await
        .expect("exec allowed-fingerprints failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
    assert!(
        session.tcpip_forward("localhost", 80).await.is_err(),
        "tcpip_forward with localhost should've failed"
    );
    assert!(!session.is_closed(), "session shouldn't have been closed");

    // 3a. Start SSH client that will fail to convert TCP port into alias via `tcp-alias`
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
        None,
    )
    .expect("Missing file key1");
    let (tx, mut rx) = mpsc::unbounded_channel();
    let ssh_client = SshClientWithChannelFailure(tx);
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
    let channel = session
        .channel_open_session()
        .await
        .expect("channel_open_session failed");
    channel
        .exec(true, "tcp-alias")
        .await
        .expect("exec tcp-alias failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
    sleep(Duration::from_millis(200)).await;
    assert!(session.is_closed(), "session should've been closed");
    // 3b. Start SSH client that will fail to convert TCP port into alias via `allowed-fingerprints`
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
        None,
    )
    .expect("Missing file key1");
    let (tx, mut rx) = mpsc::unbounded_channel();
    let ssh_client = SshClientWithChannelFailure(tx);
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
    let channel = session
        .channel_open_session()
        .await
        .expect("channel_open_session failed");
    channel
        .exec(
            true,
            "allowed-fingerprints=SHA256:GehKyA21BBK6eJCouziacUmqYDNl8BPMGG0CTtLSrbQ",
        )
        .await
        .expect("exec allowed-fingerprints failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
    sleep(Duration::from_millis(200)).await;
    assert!(session.is_closed(), "session should've been closed");
    // 3c. Start SSH client that will fail to create localhost TCP port after invoking `tcp-alias`
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
        None,
    )
    .expect("Missing file key1");
    let (tx, mut rx) = mpsc::unbounded_channel();
    let ssh_client = SshClientWithChannelSuccess(tx);
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
    let channel = session
        .channel_open_session()
        .await
        .expect("channel_open_session failed");
    channel
        .exec(true, "tcp-alias")
        .await
        .expect("exec tcp-alias failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
    assert!(
        session.tcpip_forward("localhost", 12345).await.is_err(),
        "tcpip_forward with localhost should've failed"
    );
    assert!(!session.is_closed(), "session shouldn't have been closed");
    // 3d. Start SSH client that will fail to create localhost TCP port after invoking `allowed-fingerprints`
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
        None,
    )
    .expect("Missing file key1");
    let (tx, mut rx) = mpsc::unbounded_channel();
    let ssh_client = SshClientWithChannelSuccess(tx);
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
    let channel = session
        .channel_open_session()
        .await
        .expect("channel_open_session failed");
    channel
        .exec(
            true,
            "allowed-fingerprints=SHA256:GehKyA21BBK6eJCouziacUmqYDNl8BPMGG0CTtLSrbQ",
        )
        .await
        .expect("exec allowed-fingerprints failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
    assert!(
        session.tcpip_forward("localhost", 12345).await.is_err(),
        "tcpip_forward with localhost should've failed"
    );
    assert!(!session.is_closed(), "session shouldn't have been closed");
}

struct SshClientWithChannelSuccess(mpsc::UnboundedSender<ChannelId>);

impl russh::client::Handler for SshClientWithChannelSuccess {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn channel_success(
        &mut self,
        channel: ChannelId,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        self.0.send(channel).unwrap();
        Ok(())
    }
}

struct SshClientWithChannelFailure(mpsc::UnboundedSender<ChannelId>);

impl russh::client::Handler for SshClientWithChannelFailure {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn channel_failure(
        &mut self,
        channel: ChannelId,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        self.0.send(channel).unwrap();
        Ok(())
    }
}
