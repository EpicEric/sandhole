use std::{sync::Arc, time::Duration};

use clap::Parser;
use russh::keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use russh::ChannelId;
use russh::{
    client::{self, Msg, Session},
    Channel,
};
use sandhole::{entrypoint, ApplicationConfig};
use tokio::{
    net::TcpStream,
    sync::mpsc,
    time::{sleep, timeout},
};

#[tokio::test(flavor = "multi_thread")]
async fn admin_no_interface_if_proxying() {
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
        "--bind-hostnames=all",
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
        .tcpip_forward("proxy.ccc", 12345)
        .await
        .expect("tcpip_forward failed");

    // 3. Create forwarding and fail to open admin interface
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/admin"),
        None,
    )
    .expect("Missing file admin");
    let (tx, mut rx) = mpsc::unbounded_channel();
    let ssh_client = SshClientAdmin(tx);
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
    let _alias_channel = session
        .channel_open_direct_tcpip("proxy.ccc", 12345, "::1", 23456)
        .await
        .expect("Local forwarding failed");
    let channel = session
        .channel_open_session()
        .await
        .expect("channel_open_session failed");
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
    sleep(Duration::from_millis(200)).await;
    assert!(!session.is_closed(), "session shouldn't have been closed");

    // 3. Open admin interface and fail to create forwarding
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/admin"),
        None,
    )
    .expect("Missing file admin");
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
    let channel = session
        .channel_open_session()
        .await
        .expect("channel_open_session failed");
    channel
        .exec(false, "admin")
        .await
        .expect("exec admin failed");
    assert!(
        session
            .channel_open_direct_tcpip("proxy.ccc", 12345, "::1", 23456)
            .await
            .is_err(),
        "proxying should've failed"
    );
    sleep(Duration::from_millis(200)).await;
    assert!(session.is_closed(), "session should've been closed");
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
            channel.data(&b"Hello, world!"[..]).await.unwrap();
            sleep(Duration::from_secs(1)).await;
            channel.eof().await.unwrap();
        });
        Ok(())
    }
}

struct SshClientAdmin(mpsc::UnboundedSender<ChannelId>);

impl russh::client::Handler for SshClientAdmin {
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
