use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::{routing::get, Router};
use clap::Parser;
use http::{Request, StatusCode};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use russh::{
    client::{Msg, Session},
    Channel,
};
use russh_keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use sandhole::{entrypoint, ApplicationConfig};
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};
use tower::Service;

#[tokio::test(flavor = "multi_thread")]
async fn ip_blocklist_by_user() {
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
        "--listen-address=::",
        "--ssh-port=18022",
        "--http-port=18080",
        "--https-port=18443",
        "--acme-use-staging",
        "--bind-hostnames=all",
        "--idle-connection-timeout=1s",
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

    // 2. Start SSH client that will set ip-allowlist and ip-blocklist
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
                "user1",
                PrivateKeyWithHashAlg::new(Arc::new(key), None).unwrap()
            )
            .await
            .expect("SSH authentication failed"),
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
        .exec(false, "ip-allowlist=127.0.0.0/8 ip-blocklist=::/32")
        .await
        .expect("exec failed");

    // 3. Connect to the HTTP port of our proxy and get blocked by IP
    let tcp_stream = TcpStream::connect("[::]:18080")
        .await
        .expect("TCP connection failed");
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp_stream))
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
        .header("host", "test.foobar.tld")
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
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // 4. Connect to the HTTP port of our proxy and get allowed by IP
    let tcp_stream = TcpStream::connect("127.0.0.1:18080")
        .await
        .expect("TCP connection failed");
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp_stream))
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
        .header("host", "test.foobar.tld")
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
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // 5. Start SSH client that will be blocked from aliasing to the service
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key2"),
        None,
    )
    .expect("Missing file key2");
    let ssh_client = SshClient;
    let mut session = russh::client::connect(Default::default(), "[::]:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(
        session
            .authenticate_publickey(
                "user2",
                PrivateKeyWithHashAlg::new(Arc::new(key), None).unwrap()
            )
            .await
            .expect("SSH authentication failed"),
        "authentication didn't succeed"
    );
    let channel = session
        .channel_open_direct_tcpip("test.foobar.tld", 18080, "my.hostname", 12345)
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
        panic!("Timeout waiting for server to reply.")
    };
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // 6. Start SSH client that will be allowed to alias to the service
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key2"),
        None,
    )
    .expect("Missing file key2");
    let ssh_client = SshClient;
    let mut session = russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(
        session
            .authenticate_publickey(
                "user2",
                PrivateKeyWithHashAlg::new(Arc::new(key), None).unwrap()
            )
            .await
            .expect("SSH authentication failed"),
        "authentication didn't succeed"
    );
    let channel = session
        .channel_open_direct_tcpip("test.foobar.tld", 18080, "my.hostname", 12345)
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
        panic!("Timeout waiting for server to reply.")
    };
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
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
            .route("/", get(|| async move { StatusCode::NO_CONTENT }))
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
