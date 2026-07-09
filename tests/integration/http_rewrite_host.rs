use std::{sync::Arc, time::Duration};

use axum::{Router, extract::Request, routing::get};
use clap::Parser;
use http::{HeaderMap, StatusCode, header::HOST};
use http_body_util::BodyExt;
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use russh::{
    Channel,
    client::{Msg, Session},
};
use russh::{
    ChannelId,
    keys::{key::PrivateKeyWithHashAlg, load_secret_key},
};
use sandhole::{ApplicationConfig, entrypoint};
use tokio::{
    net::TcpStream,
    sync::oneshot,
    time::{sleep, timeout},
};
use tower::Service;

use crate::common::SandholeHandle;

/// This test ensures that the user-provided `host` option
/// properly overwrites the Host header for HTTP/1.1 services.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn http_rewrite_host() {
    // 1. Initialize Sandhole
    let config = ApplicationConfig::parse_from([
        "sandhole",
        "--domain=foobar.tld",
        "--user-keys-directory",
        &(format!(
            "{}/tests/data/user_keys",
            std::env::var("CARGO_MANIFEST_DIR").unwrap()
        )),
        "--admin-keys-directory",
        &(format!(
            "{}/tests/data/admin_keys",
            std::env::var("CARGO_MANIFEST_DIR").unwrap()
        )),
        "--certificates-directory",
        &(format!(
            "{}/tests/data/certificates",
            std::env::var("CARGO_MANIFEST_DIR").unwrap()
        )),
        "--private-key-file",
        &(format!(
            "{}/tests/data/server_keys/ssh",
            std::env::var("CARGO_MANIFEST_DIR").unwrap()
        )),
        "--acme-cache-directory",
        &(format!(
            "{}/tests/data/acme_cache",
            std::env::var("CARGO_MANIFEST_DIR").unwrap()
        )),
        "--disable-directory-creation",
        "--listen-address=127.0.0.1",
        "--ssh-port=18022",
        "--http-port=18080",
        "--https-port=18443",
        "--acme-use-staging",
        "--bind-hostnames=all",
        "--idle-connection-timeout=500ms",
        "--authentication-request-timeout=5s",
        "--http-request-timeout=5s",
        "--tcp-connection-timeout=500ms",
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

    // 2. Start SSH client that will set a custom host
    let key = load_secret_key(
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("tests/data/private_keys/key1"),
        None,
    )
    .expect("Missing file key1");
    let (tx, rx) = oneshot::channel();
    let ssh_client = SshClient(Some(tx));
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
        .tcpip_forward("test.foobar.tld", 80)
        .await
        .expect("tcpip_forward failed");
    let channel = session
        .channel_open_session()
        .await
        .expect("channel_open_session_failed");
    channel
        .exec(true, "host=hello.world")
        .await
        .expect("exec failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.await.unwrap() }).await else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());

    // 3. Connect to the HTTP port of our proxy
    let tcp_stream = TcpStream::connect("127.0.0.1:18080")
        .await
        .expect("TCP connection failed");
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp_stream))
        .await
        .expect("HTTP handshake failed");
    let jh = tokio::spawn(async move {
        if let Err(error) = conn.await {
            eprintln!("Connection failed: {error:?}");
        }
    });
    let request = Request::builder()
        .method("GET")
        .uri("/")
        .header(HOST, "test.foobar.tld")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let Ok(response) = timeout(Duration::from_secs(5), async move {
        sender
            .send_request(request)
            .await
            .expect("Error sending HTTP request")
    })
    .await
    else {
        panic!("Timeout waiting for request to finish.");
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
    assert_eq!(response_body, "Hello from the masked host!");
    session
        .cancel_tcpip_forward("test.foobar.tld", 80)
        .await
        .expect("cancel_tcpip_forward failed");
    assert!(
        session
            .cancel_tcpip_forward("test.foobar.tld", 80)
            .await
            .is_err(),
        "cancel_tcpip_forward should've failed for closed tunnel"
    );
    jh.abort();
}

struct SshClient(Option<oneshot::Sender<ChannelId>>);

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
        let router = Router::new().route(
            "/",
            get(async |headers: HeaderMap| {
                if headers.get(HOST).unwrap() == "hello.world" {
                    "Hello from the masked host!"
                } else {
                    "Failure"
                }
            }),
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

    async fn channel_success(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(tx) = self.0.take() {
            tx.send(channel).unwrap();
        };
        Ok(())
    }
}
