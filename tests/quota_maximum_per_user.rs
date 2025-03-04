use std::{sync::Arc, time::Duration};

use axum::{extract::Request, routing::get, Router};
use clap::Parser;
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use russh::keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use russh::{
    client::{Msg, Session},
    Channel,
};
use sandhole::{entrypoint, ApplicationConfig};
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};
use tower::Service;

#[tokio::test(flavor = "multi_thread")]
async fn quota_maximum_per_user() {
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
        "--bind-hostnames=none",
        "--quota-per-user=1",
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

    // 2. Start SSH client that will reach quota
    let key_1 = Arc::new(
        load_secret_key(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
            None,
        )
        .expect("Missing file key1"),
    );
    let ssh_client = SshClient;
    let mut session_1 = russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(
        session_1
            .authenticate_publickey(
                "user",
                PrivateKeyWithHashAlg::new(
                    Arc::clone(&key_1),
                    session_1.best_supported_rsa_hash().await.unwrap().flatten()
                )
            )
            .await
            .expect("SSH authentication failed")
            .success(),
        "authentication didn't succeed"
    );
    session_1
        .tcpip_forward("some.random.hostname", 80)
        .await
        .expect("tcpip_forward failed");
    assert!(
        session_1
            .tcpip_forward("another.random.hostname", 80)
            .await
            .is_err(),
        "shouldn't allow exceeding remote forwarding quota"
    );

    // 3. Try to connect via different client with same credentials and reach quota again
    let ssh_client = SshClient;
    let mut session_2 = russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(
        session_2
            .authenticate_publickey(
                "user",
                PrivateKeyWithHashAlg::new(
                    Arc::clone(&key_1),
                    session_2.best_supported_rsa_hash().await.unwrap().flatten()
                )
            )
            .await
            .expect("SSH authentication failed")
            .success(),
        "authentication didn't succeed"
    );
    assert!(
        session_2
            .tcpip_forward("sneaky.random.hostname", 80)
            .await
            .is_err(),
        "shouldn't allow exceeding remote forwarding quota over multiple sessions"
    );

    // 4. Cancel first forwarding, then succeed on new one
    session_1
        .cancel_tcpip_forward("some.random.hostname", 80)
        .await
        .expect("cancel_tcpip_forward failed");
    session_2
        .tcpip_forward("new.random.hostname", 80)
        .await
        .expect("tcpip_forward failed");

    // 5. Admin user doesn't have quota limit
    let admin_key = Arc::new(
        load_secret_key(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/admin"),
            None,
        )
        .expect("Missing file admin"),
    );
    let ssh_client = SshClient;
    let mut session_admin =
        russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
            .await
            .expect("Failed to connect to SSH server");
    assert!(
        session_admin
            .authenticate_publickey(
                "admin",
                PrivateKeyWithHashAlg::new(
                    Arc::clone(&admin_key),
                    session_admin
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
    session_admin
        .tcpip_forward("some.random.hostname", 80)
        .await
        .expect("tcpip_forward failed");
    session_admin
        .tcpip_forward("another.random.hostname", 80)
        .await
        .expect("tcpip_forward failed");
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
        let router = Router::new().route(
            "/",
            get(|| async move { "Max quota shenanigans.".to_string() }),
        );
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
