use std::{sync::Arc, time::Duration};

use axum::{routing::get, Router};
use clap::Parser;
use http::{Request, StatusCode};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use russh::keys::{key::PrivateKeyWithHashAlg, load_secret_key, ssh_key::private::Ed25519Keypair};
use russh::{
    client::{Msg, Session},
    Channel, ChannelId,
};
use sandhole::{entrypoint, ApplicationConfig};
use tokio::{
    net::TcpStream,
    sync::mpsc,
    time::{sleep, timeout},
};
use tower::Service;

#[tokio::test(flavor = "multi_thread")]
async fn config_disable_aliasing() {
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
        "--disable-aliasing",
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

    // 2. Start SSH client that will fail to alias
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
        None,
    )
    .expect("Missing file key1");
    let (tx, mut rx) = mpsc::unbounded_channel();
    let ssh_client = SshClientOne(tx);
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
    assert!(
        session_one.tcpip_forward("tcp.tunnel", 42).await.is_err(),
        "should've failed to alias TCP"
    );
    assert!(!session_one.is_closed(), "shouldn't have closed connection");
    assert!(
        session_one.tcpip_forward("ssh.tunnel", 22).await.is_err(),
        "should've failed to alias SSH"
    );
    assert!(!session_one.is_closed(), "shouldn't have closed connection");
    let channel = session_one
        .channel_open_session()
        .await
        .expect("channel_open_session_failed");
    channel
        .exec(true, "tcp-alias")
        .await
        .expect("shouldn't error synchronously for invalid tcp-alias option");
    assert!(!session_one.is_closed(), "shouldn't have closed connection");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(!session_one.is_closed(), "shouldn't have closed connection");
    channel
        .exec(
            true,
            "allowed-fingerprints=\
            SHA256:GehKyA21BBK6eJCouziacUmqYDNl8BPMGG0CTtLSrbQ,\
            SHA256:eDZoeAWBWd+SO64PPW1VBrdlBxYM4OEywSkGlIy0Kro",
        )
        .await
        .expect("shouldn't error synchronously for invalid tcp-alias option");
    assert!(!session_one.is_closed(), "shouldn't have closed connection");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
    else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());
    assert!(!session_one.is_closed(), "shouldn't have closed connection");
    assert!(
        session_one
            .tcpip_forward("test.foobar.tld", 80)
            .await
            .is_ok(),
        "shouldn't have failed to bind HTTP"
    );
    assert!(
        session_one.tcpip_forward("localhost", 12345).await.is_ok(),
        "shouldn't have failed to bind TCP"
    );

    // 3. Start SSH proxy that will fail to local forward
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
        None,
    )
    .expect("Missing file key1");
    let ssh_client = SshClientTwo;
    let mut session_two = russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(
        session_two
            .authenticate_publickey(
                "user",
                PrivateKeyWithHashAlg::new(
                    Arc::new(key),
                    session_two
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
        session_two
            .channel_open_direct_tcpip("test.foobar.tld", 80, "127.0.0.1", 12345)
            .await
            .is_err(),
        "shouldn't be allowed to alias HTTP"
    );

    // 4. Reject anonymous users if aliasing is disabled
    let key = russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(
        &ChaCha20Rng::try_from_os_rng().unwrap().random(),
    ));
    let ssh_client = SshClientTwo;
    let mut session_three =
        russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
            .await
            .expect("Failed to connect to SSH server");
    assert!(
        !session_three
            .authenticate_publickey(
                "user3",
                PrivateKeyWithHashAlg::new(
                    Arc::new(key),
                    session_three
                        .best_supported_rsa_hash()
                        .await
                        .unwrap()
                        .flatten()
                )
            )
            .await
            .expect("SSH authentication failed")
            .success(),
        "mustn't authenticate anonymously if aliasing is disabled"
    );
}

struct SshClientOne(mpsc::UnboundedSender<ChannelId>);

impl russh::client::Handler for SshClientOne {
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
        let router = Router::new().route("/", get(|| async move { StatusCode::NO_CONTENT }));
        let service = service_fn(move |req: Request<Incoming>| router.clone().call(req));
        tokio::spawn(async move {
            Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(channel.into_stream()), service)
                .await
                .expect("Invalid request");
        });
        Ok(())
    }

    async fn channel_failure(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.0.send(channel).unwrap();
        Ok(())
    }
}

struct SshClientTwo;

impl russh::client::Handler for SshClientTwo {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
