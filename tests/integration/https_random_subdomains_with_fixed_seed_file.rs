use std::{sync::Arc, time::Duration};

use axum::{Router, extract::Request, routing::head};
use clap::Parser;
use http::header::{CONTENT_LENGTH, HOST};
use hyper::{StatusCode, body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use rand::{rng, seq::IndexedRandom};
use russh::keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use russh::{
    Channel,
    client::{Msg, Session},
};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, pem::PemObject},
};
use sandhole::{ApplicationConfig, entrypoint};
use tokio::{
    fs,
    net::TcpStream,
    time::{sleep, timeout},
};
use tokio_rustls::TlsConnector;
use tower::Service;

use crate::common::SandholeHandle;

/// This test ensures that random subdomains are always the same when using a
/// fixed seed through `--random-subdomain-seed` and `--random-subdomain-value-file`.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn https_random_subdomains_with_fixed_seed_file() {
    // 1. Create random temporary directory and initialize Sandhole
    let random_name = String::from_utf8(
        (0..6)
            .flat_map(|_| {
                "0123456789abcdefghijklmnopqrstuvwxyz"
                    .as_bytes()
                    .choose(&mut rng())
                    .copied()
            })
            .collect(),
    )
    .unwrap();
    let temp_dir = std::env::temp_dir().join(format!("sandhole_test_{random_name}"));
    fs::create_dir(temp_dir.as_path())
        .await
        .expect("Unable to create tempdir");
    let temp_seed_file = temp_dir.join("seed");
    fs::write(
        AsRef::<std::path::Path>::as_ref(&temp_seed_file),
        b"\n 12345\t\r",
    )
    .await
    .expect("Unable to create seed file in tempdir");
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
        "--bind-hostnames=none",
        "--random-subdomain-length=6",
        "--random-subdomain-seed=user",
        "--random-subdomain-value-file",
        temp_seed_file.to_str().unwrap(),
        "--random-subdomain-value=999999", // Should be ignored
        "--idle-connection-timeout=1s",
        "--authentication-request-timeout=5s",
        "--http-request-timeout=5s",
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

    // 2. Start SSH client that will be proxied via HTTPS
    let key = load_secret_key(
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("tests/data/private_keys/key1"),
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
        .tcpip_forward("random", 80)
        .await
        .expect("tcpip_forward failed");
    let regex = regex::Regex::new(r"https://(\S+)").expect("Invalid regex");
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
    assert_eq!(
        hostname, "8tcai5.foobar.tld",
        "should create specific hostname with fixed subdomain"
    );

    // 3. Connect to the HTTPS port of our proxy
    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(
        CertificateDer::pem_file_iter(
            std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
                .join("tests/data/ca/rootCA.pem"),
        )
        .and_then(|iter| iter.collect::<Result<Vec<_>, _>>())
        .expect("Failed to parse certificates"),
    );
    let tls_config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );
    let connector = TlsConnector::from(tls_config);
    let tcp_stream = TcpStream::connect("127.0.0.1:18443")
        .await
        .expect("TCP connection failed");
    let tls_stream = connector
        .connect("8tcai5.foobar.tld".try_into().unwrap(), tcp_stream)
        .await
        .expect("TLS stream failed");
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls_stream))
        .await
        .expect("HTTP handshake failed");
    let jh = tokio::spawn(async move {
        if let Err(error) = conn.await {
            eprintln!("Connection failed: {error:?}");
        }
    });
    let request = Request::builder()
        .method("HEAD")
        .uri("/")
        .header(HOST, "8tcai5.foobar.tld")
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
    assert_eq!(response.headers()[CONTENT_LENGTH].to_str().unwrap(), "33");
    jh.abort();
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
        let router = Router::new().route("/", head(async || "I'm always at the same subdomain!"));
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
