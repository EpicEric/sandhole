use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::{routing::get, Router};
use clap::Parser;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use rand::rngs::OsRng;
use russh::{
    client::{self, Msg, Session},
    Channel,
};
use russh_keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use sandhole::{entrypoint, ApplicationConfig};
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};
use tower::Service;

/// In order for tunneling to work, Sandhole must allow any public key to connect.
/// However, unauthorized users should have much more restricted access, only being allowed
/// to request local port forwarding (as of this version).
///
/// This test ensures that any other actions result in an error with a disconnect.
#[tokio::test(flavor = "multi_thread")]
async fn alias_local_forward_existing_http() {
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
        "--bind-hostnames=all",
        "--idle-connection-timeout=800ms",
        "--authentication-request-timeout=5s",
        "--http-request-timeout=5s",
    ]);
    tokio::spawn(async move { entrypoint(config).await });
    if timeout(Duration::from_secs(5), async {
        while let Err(_) = TcpStream::connect("127.0.0.1:18022").await {
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
                PrivateKeyWithHashAlg::new(Arc::new(key), None).unwrap()
            )
            .await
            .expect("SSH authentication failed"),
        "authentication didn't succeed"
    );
    session
        .tcpip_forward("example.foobar.tld", 80)
        .await
        .expect("tcpip_forward failed");

    // 3. Local-forward instead of connecting directly
    let key = russh_keys::PrivateKey::random(&mut OsRng, russh_keys::Algorithm::Ed25519).unwrap();
    let ssh_client = SshClient;
    let mut session = client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(
        session
            .authenticate_publickey(
                "user",
                PrivateKeyWithHashAlg::new(Arc::new(key), None).unwrap()
            )
            .await
            .expect("SSH authentication failed"),
        "authentication didn't succeed"
    );

    let channel = session
        .channel_open_direct_tcpip("example.foobar.tld", 18080, "localhost", 12345)
        .await
        .expect("channel_open_direct_tcpip failed");
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(TokioIo::new(channel.into_stream()))
            .await
            .expect("HTTP handshake failed");
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            eprintln!("Connection failed: {:?}", err);
        }
    });
    let request = Request::builder()
        .method("GET")
        .uri("/")
        .header("host", "localhost")
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
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(response.status(), StatusCode::OK);
    let response_body = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .expect("Error collecting response")
            .to_bytes()
            .into(),
    )
    .expect("Invalid response body");
    assert_eq!(response_body, "Connected via local forwarding!");
}

struct SshClient;

#[async_trait]
impl russh::client::Handler for SshClient {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, _key: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
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
        let router = Router::new()
            .route(
                "/",
                get(|| async move { "Connected via local forwarding!" }),
            )
            .into_service();
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