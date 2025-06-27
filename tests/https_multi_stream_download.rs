use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Path, Request, State},
    response::IntoResponse,
    routing::get,
};
use clap::Parser;
use http::header::CONTENT_LENGTH;
use http_body_util::BodyExt;
use hyper::{StatusCode, body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use rand::RngCore;
use russh::{
    Channel, Preferred,
    client::{Msg, Session},
};
use russh::{
    client::Config,
    keys::{key::PrivateKeyWithHashAlg, load_secret_key},
};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, pem::PemObject},
};
use sandhole::{ApplicationConfig, entrypoint};
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};
use tokio_rustls::TlsConnector;
use tower::Service;

/// This test ensures that a service can handle multiple big downloads at the
/// same time (mostly for profiling purposes).
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn https_multi_stream_download() {
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
        "--http-request-timeout=60s",
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

    // 2. Start SSH client that will be proxied
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
        None,
    )
    .expect("Missing file key1");
    let mut data = vec![0u8; 20_000_000];
    rand::rng().fill_bytes(&mut data);
    let ssh_client = SshClient(Bytes::from_static(data.leak()));
    let mut session = russh::client::connect(
        Arc::new(Config {
            preferred: Preferred {
                cipher: std::borrow::Cow::Borrowed(&[
                    russh::cipher::CHACHA20_POLY1305,
                    // russh::cipher::AES_256_GCM,
                ]),
                ..Default::default()
            },
            ..Default::default()
        }),
        "127.0.0.1:18022",
        ssh_client,
    )
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
        .tcpip_forward("foobar.tld", 443)
        .await
        .expect("tcpip_forward failed");

    // 3. Connect to the HTTPS port of our proxy with out multiple streams
    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(
        CertificateDer::pem_file_iter(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/ca/rootCA.pem"
        ))
        .and_then(|iter| iter.collect::<Result<Vec<_>, _>>())
        .expect("Failed to parse certificates"),
    );
    let tls_config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );
    let mut jh_vec = vec![];
    for file_size in [7_500_000, 10_000_000, 15_000_000, 20_000_000] {
        let connector = TlsConnector::from(Arc::clone(&tls_config));
        let tcp_stream = TcpStream::connect("127.0.0.1:18443")
            .await
            .expect("TCP connection failed");
        let tls_stream = connector
            .connect("foobar.tld".try_into().unwrap(), tcp_stream)
            .await
            .expect("TLS stream failed");
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls_stream))
            .await
            .expect("HTTP handshake failed");
        tokio::spawn(async move {
            if let Err(error) = conn.await {
                eprintln!("Connection failed: {error:?}");
            }
        });
        let jh = tokio::spawn(async move {
            let request = Request::builder()
                .method("GET")
                .uri(format!("/{file_size}"))
                .header("host", "foobar.tld")
                .body(Body::empty())
                .unwrap();
            let Ok(mut response) = timeout(Duration::from_secs(60), async move {
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
            assert_eq!(
                response
                    .headers()
                    .get(CONTENT_LENGTH)
                    .unwrap()
                    .to_str()
                    .unwrap(),
                file_size.to_string(),
                "Content-Length didn't match file size"
            );
            let body = response.body_mut();
            let mut size = 0usize;
            while let Some(Ok(frame)) = body.frame().await {
                size += frame.data_ref().unwrap().len();
            }
            assert_eq!(size, file_size, "Response size didn't match file size");
        });
        jh_vec.push(jh);
    }
    for jh in jh_vec.into_iter() {
        jh.await.expect("Join handle panicked");
    }
}

struct SshClient(Bytes);

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
        let data = self.0.clone();
        let router = Router::new()
            .route(
                "/{file_size}",
                get(
                    async |Path(file_size): Path<usize>, State(data): State<Bytes>| {
                        if file_size > data.len() {
                            StatusCode::BAD_REQUEST.into_response()
                        } else {
                            data.slice(..file_size).into_response()
                        }
                    },
                ),
            )
            .with_state(data);
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
