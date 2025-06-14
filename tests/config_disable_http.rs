use std::{sync::Arc, time::Duration};

use axum::{Router, routing::get};
use clap::Parser;
use http::{Request, StatusCode};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use russh::keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use russh::{
    Channel,
    client::{Msg, Session},
};
use sandhole::{ApplicationConfig, entrypoint};
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};
use tower::Service;

/// This test ensures that HTTP services can be fully disabled by the
/// `--disable-http` option.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn config_disable_http() {
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
        "--disable-http",
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
    assert!(
        TcpStream::connect("127.0.0.1:18080").await.is_err(),
        "shouldn't listen on HTTP port"
    );
    assert!(
        TcpStream::connect("127.0.0.1:18443").await.is_err(),
        "shouldn't listen on HTTPS port"
    );

    // 2. Start SSH client that will fail to bind HTTP
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
        None,
    )
    .expect("Missing file key1");
    let ssh_client = SshClient;
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
        session_one.tcpip_forward("some.address", 80).await.is_err(),
        "should've failed to bind HTTP"
    );
    assert!(!session_one.is_closed(), "shouldn't have closed connection");
    let channel = session_one
        .channel_open_session()
        .await
        .expect("channel_open_session_failed");
    channel
        .exec(true, "tcp-alias")
        .await
        .expect("shouldn't error synchronously for exec");
    assert!(!session_one.is_closed(), "shouldn't have closed connection");
    assert!(
        session_one.tcpip_forward("some.address", 80).await.is_ok(),
        "shouldn't have failed to create HTTP alias"
    );
    assert!(
        session_one.tcpip_forward("some.proxy", 90).await.is_ok(),
        "shouldn't have failed to bind alias"
    );
    assert!(
        session_one
            .cancel_tcpip_forward("some.address", 80)
            .await
            .is_ok(),
        "shouldn't have failed to cancel HTTP alias"
    );
    assert!(
        session_one
            .cancel_tcpip_forward("some.proxy", 90)
            .await
            .is_ok(),
        "shouldn't have failed to cancel alias"
    );

    // 3. Start SSH client that manages to bind TCP
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
        None,
    )
    .expect("Missing file key1");
    let ssh_client = SshClient;
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
        session_two.tcpip_forward("localhost", 12345).await.is_ok(),
        "shouldn't have failed to bind TCP"
    );
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
        let router = Router::new().route("/", get(async || StatusCode::NO_CONTENT));
        let service = service_fn(move |req: Request<Incoming>| router.clone().call(req));
        tokio::spawn(async move {
            Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(channel.into_stream()), service)
                .await
                .expect("Invalid request");
        });
        Ok(())
    }
}
