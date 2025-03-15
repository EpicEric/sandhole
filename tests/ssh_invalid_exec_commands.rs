use std::{sync::Arc, time::Duration};

use clap::Parser;
use russh::keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use russh::{ChannelId, client};
use sandhole::{ApplicationConfig, entrypoint};
use tokio::sync::mpsc;
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};

#[tokio::test(flavor = "multi_thread")]
async fn ssh_invalid_exec_commands() {
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
        "--bind-hostnames=all",
        "--idle-connection-timeout=2s",
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

    // 2a. Start SSH user client that will fail to run user commands
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
        None,
    )
    .expect("Missing file key1");
    let (tx, mut rx) = mpsc::unbounded_channel();
    let ssh_client = SshClient(tx);
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
    let channel = session
        .channel_open_session()
        .await
        .expect("channel_open_session failed");
    // 2b. Fail to run `admin` as non-admin
    channel
        .exec(true, "admin")
        .await
        .expect("exec admin failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
    // 2c. Fail to run `allowed-fingerprints` with no fingerprint
    channel
        .exec(true, "allowed-fingerprints=")
        .await
        .expect("exec allowed-fingerprints failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
    // 2d. Fail to run `allowed-fingerprints` with invalid fingerprint
    channel
        .exec(true, "allowed-fingerprints=SHA256:blah")
        .await
        .expect("exec allowed-fingerprints failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
    // 2e. Fail to run `allowed-fingerprints` twice
    channel
        .exec(
            true,
            "allowed-fingerprints=SHA256:GehKyA21BBK6eJCouziacUmqYDNl8BPMGG0CTtLSrbQ allowed-fingerprints=SHA256:bwf4FDtNeZzFv8xHBzHJwRpDRxssCll8w2tCHFC9n1o",
        )
        .await
        .expect("exec allowed-fingerprints failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
    channel
        .exec(
            true,
            "allowed-fingerprints=SHA256:bwf4FDtNeZzFv8xHBzHJwRpDRxssCll8w2tCHFC9n1o",
        )
        .await
        .expect("exec allowed-fingerprints failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
    // 2f. Fail to run `tcp-alias` twice
    channel
        .exec(true, "tcp-alias tcp-alias")
        .await
        .expect("exec tcp-alias failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
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
    // 2g. Fail to run `force-https` twice
    channel
        .exec(true, "force-https force-https")
        .await
        .expect("exec force-https failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
    channel
        .exec(true, "force-https")
        .await
        .expect("exec force-https failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
    // 2h. Fail to run `ip-allowlist` with invalid CIDR
    channel
        .exec(true, "ip-allowlist=10.0.0")
        .await
        .expect("exec ip-allowlist failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
    // 2i. Fail to run `ip-allowlist` with no CIDRs
    channel
        .exec(true, "ip-allowlist=")
        .await
        .expect("exec ip-allowlist failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
    // 2j. Fail to run `ip-allowlist` twice
    channel
        .exec(
            true,
            "ip-allowlist=192.168.0.0/16 ip-allowlist=dead:beef::/32",
        )
        .await
        .expect("exec ip-allowlist failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
    channel
        .exec(true, "ip-allowlist=dead:beef::/32")
        .await
        .expect("exec ip-allowlist failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
    // 2k. Fail to run `ip-blocklist` with invalid CIDR
    channel
        .exec(true, "ip-blocklist=10.0.0")
        .await
        .expect("exec ip-blocklist failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
    // 2l. Fail to run `ip-blocklist` with no CIDRs
    channel
        .exec(true, "ip-blocklist=")
        .await
        .expect("exec ip-blocklist failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
    // 2m. Fail to run `ip-blocklist` twice
    channel
        .exec(
            true,
            "ip-blocklist=193.168.0.0/16 ip-blocklist=dead:ba11::/32",
        )
        .await
        .expect("exec ip-blocklist failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
    channel
        .exec(true, "ip-blocklist=dead:ba11::/32")
        .await
        .expect("exec ip-blocklist failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
    // 2n. Fail to run an unknown command
    channel
        .exec(true, "unknown-command")
        .await
        .expect("exec ip-blocklist failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
    assert!(!session.is_closed(), "session shouldn't have been closed");

    // 3a. Start SSH admin client that will fail to run admin commands
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/admin"),
        None,
    )
    .expect("Missing file admin");
    let (tx, mut rx) = mpsc::unbounded_channel();
    let ssh_client = SshClient(tx);
    let mut session = client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(
        session
            .authenticate_publickey(
                "admin",
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
        .channel_open_session()
        .await
        .expect("channel_open_session failed");
    // 3b. Fail to run `admin` twice
    channel
        .exec(true, "admin admin")
        .await
        .expect("exec admin failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
    channel
        .exec(true, "admin")
        .await
        .expect("exec admin failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
    // 3c. Ensure that at least one admin session is running
    let (tx, mut rx) = mpsc::unbounded_channel();
    let jh = tokio::spawn(async move {
        let mut parser = vt100_ctt::Parser::new(30, 140, 0);
        let mut screen = Vec::new();
        while let Some(msg) = channel.wait().await {
            if let russh::ChannelMsg::Data { data } = msg {
                parser.process(&data);
                let new_screen = parser.screen();
                let contents_formatted = new_screen.contents_formatted();
                if contents_formatted != screen {
                    screen = contents_formatted;
                    let _ = tx.send(new_screen.contents());
                }
            }
        }
    });
    if timeout(Duration::from_secs(4), async move {
        loop {
            let screen = rx.recv().await.unwrap();
            if screen.contains("Ctrl-C") {
                break;
            }
        }
    })
    .await
    .is_err()
    {
        panic!("Timed out waiting for admin interface.");
    }
    assert!(!session.is_closed(), "session shouldn't have been closed");
    jh.abort();
}

struct SshClient(mpsc::UnboundedSender<ChannelId>);

impl client::Handler for SshClient {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn channel_failure(
        &mut self,
        channel: russh::ChannelId,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.0.send(channel).unwrap();
        Ok(())
    }
}
