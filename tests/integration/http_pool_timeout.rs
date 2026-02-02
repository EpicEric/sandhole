use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{Router, extract::Request, routing::get};
use clap::Parser;
use http::{StatusCode, header::HOST};
use http_body_util::BodyExt;
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

use crate::common::SandholeHandle;

/// This test ensures that queued connections get a spot
/// when the HTTP pool gets released.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn http_pool_timeout() {
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
        "--idle-connection-timeout=1s",
        "--authentication-request-timeout=5s",
        "--http-request-timeout=10s",
        "--pool-size=2",
        "--pool-timeout=3s",
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
        .tcpip_forward("test.foobar.tld", 80)
        .await
        .expect("tcpip_forward failed");

    // 3. Start long-running requests that fill the pool
    let mut jhs = Vec::new();
    let started = Instant::now();
    for _ in 0..2 {
        let tcp_stream = TcpStream::connect("127.0.0.1:18080")
            .await
            .expect("TCP connection failed");
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp_stream))
            .await
            .expect("HTTP handshake failed");
        let request = Request::builder()
            .method("GET")
            .uri("/")
            .header(HOST, "test.foobar.tld")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let jh = tokio::spawn(async move {
            let jh = tokio::spawn(async move {
                if let Err(error) = conn.await {
                    eprintln!("Connection failed: {error:?}");
                }
            });
            let Ok(response) = timeout(Duration::from_secs(10), async move {
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
            assert_eq!(response_body, "Processed");
            jh.abort();
        });
        jhs.push(jh);
    }

    // 3. Start request that gets rate-limited from pool exhaustion
    tokio::time::sleep(Duration::from_millis(500)).await;
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
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    jh.abort();

    // 4. Start request that gets queued and eventually completes
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let tcp_stream = TcpStream::connect("127.0.0.1:18080")
        .await
        .expect("TCP connection failed");
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp_stream))
        .await
        .expect("HTTP handshake failed");
    let request = Request::builder()
        .method("GET")
        .uri("/")
        .header(HOST, "test.foobar.tld")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let jh = tokio::spawn(async move {
        let jh = tokio::spawn(async move {
            if let Err(error) = conn.await {
                eprintln!("Connection failed: {error:?}");
            }
        });
        assert!(started.elapsed() < Duration::from_secs(5));
        let Ok(response) = timeout(Duration::from_secs(10), async move {
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
        assert_eq!(response_body, "Processed");
        assert!(started.elapsed() > Duration::from_secs(5));
        jh.abort();
    });
    jhs.push(jh);

    timeout(Duration::from_secs(10), async move {
        for jh in jhs {
            jh.await.unwrap();
        }
    })
    .await
    .expect("timeout waiting for join handles to finish");
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
        let router = Router::new().route(
            "/",
            get(async || {
                tokio::time::sleep(Duration::from_secs(5)).await;
                "Processed"
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
}
