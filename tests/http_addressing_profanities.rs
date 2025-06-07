use std::{sync::Arc, time::Duration};

use axum::{Router, extract::Request, routing::get};
use clap::Parser;
use http_body_util::BodyExt;
use hyper::{StatusCode, body::Incoming, service::service_fn};
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

#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn http_addressing_profanities() {
    // 1. Initialize Sandhole
    let config = ApplicationConfig::parse_from([
        "sandhole",
        "--domain=fuck.tld",
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
        "--requested-domain-filter-profanities",
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

    // 2. Start SSH client that will be proxied with a profanity and a non-profanity name
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
    let mut channel = session
        .channel_open_session()
        .await
        .expect("channel_open_session failed");
    session
        .tcpip_forward("shit.fuck.tld", 80)
        .await
        .expect("tcpip_forward failed");
    let regex = regex::Regex::new(r"http://(\S+)").expect("Invalid regex");
    let Ok((_, hostname)) = timeout(Duration::from_secs(3), async move {
        while let Some(message) = channel.wait().await {
            match message {
                russh::ChannelMsg::Data { data } => {
                    let data =
                        String::from_utf8(data.to_vec()).expect("Invalid UTF-8 from message");
                    if let Some(captures) = regex.captures(&data) {
                        let address = captures.get(0).unwrap().as_str().to_string();
                        let hostname = captures
                            .get(1)
                            .expect("Missing hostname matching group")
                            .as_str()
                            .split(':')
                            .next()
                            .unwrap()
                            .to_string();
                        return (address, hostname);
                    }
                }
                message => panic!("Unexpected message {message:?}"),
            }
        }
        panic!("Unexpected end of channel");
    })
    .await
    else {
        panic!("Timed out waiting for subdomain allocation.");
    };
    assert!(
        regex::Regex::new(r"^[a-z0-9]+\.fuck\.tld$")
            .unwrap()
            .is_match(&hostname),
        "hostname should've matched regex"
    );
    assert!(
        !hostname.starts_with("shit."),
        "hostname shouldn't start with profanity"
    );
    session
        .tcpip_forward("valid-as.fuck.tld", 80)
        .await
        .expect("tcpip_forward failed");

    // 3. Connect to our HTTP proxies
    for host in [&hostname, "valid-as.fuck.tld"] {
        let tcp_stream = TcpStream::connect("127.0.0.1:18080")
            .await
            .expect("TCP connection failed");
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp_stream))
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
            .header("host", host)
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
        assert_eq!(response_body, "Hello from a profane place!");
    }
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
        let router = Router::new().route("/", get(async || "Hello from a profane place!"));
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
