use std::{sync::Arc, time::Duration};

use clap::Parser;
use http::{
    Request, StatusCode,
    header::{CONTENT_LENGTH, HOST},
};
use http_body_util::BodyExt;
use hyper_util::rt::{TokioExecutor, TokioIo};
use russh::keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use sandhole::{ApplicationConfig, entrypoint};
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};

/// This test ensures that admin users can access the Prometheus admin-only
/// alias.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn admin_prometheus() {
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

    // 2. Start SSH admin client that will local forward the Prometheus service
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/admin"),
        None,
    )
    .expect("Missing file admin");
    let ssh_client = SshClient;
    let mut session = russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
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
    let channel = session
        .channel_open_direct_tcpip("prometheus.sandhole", 10, "127.0.0.1", 12345)
        .await
        .expect("channel_open_direct_tcpip failed");

    // 3. Access the Prometheus service
    let (mut sender, conn) = hyper::client::conn::http2::handshake(
        TokioExecutor::new(),
        TokioIo::new(channel.into_stream()),
    )
    .await
    .expect("HTTP handshake failed");
    tokio::spawn(async move {
        if let Err(error) = conn.await {
            eprintln!("Connection failed: {error:?}");
        }
    });
    let request = Request::builder()
        .method("GET")
        .uri("/")
        .header(HOST, "localhost:7777")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let Ok(mut response) = timeout(Duration::from_secs(5), async {
        sender
            .send_request(request)
            .await
            .expect("Error sending HTTP request")
    })
    .await
    else {
        panic!("Timeout waiting for server to reply.")
    };
    assert_eq!(response.status(), StatusCode::OK);
    let mut buf = Vec::with_capacity(
        response
            .headers()
            .get(CONTENT_LENGTH)
            .expect("missing Content-Length header")
            .to_str()
            .expect("invalid Content-Length header")
            .parse()
            .expect("non-numeric Content-Length header"),
    );
    let body = response.body_mut();
    while let Some(Ok(frame)) = body.frame().await {
        buf.extend_from_slice(frame.data_ref().unwrap());
    }
    assert!(
        String::from_utf8(buf).expect("invalid str").contains(
            "# HELP sandhole_admin_alias_connections_total Total connections for admin aliases"
        ),
        "Response didn't have Prometheus metrics"
    );
    let request = Request::builder()
        .method("GET")
        .uri("/favicon.ico")
        .header(HOST, "localhost:7777")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let Ok(response) = timeout(Duration::from_secs(5), async {
        sender
            .send_request(request)
            .await
            .expect("Error sending HTTP request")
    })
    .await
    else {
        panic!("Timeout waiting for server to reply.")
    };
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
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
}
