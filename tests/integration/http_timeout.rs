use std::{sync::Arc, time::Duration};

use axum::{Router, extract::Request, routing::get};
use clap::Parser;
use hyper::{body::Incoming, client::conn::http1::SendRequest, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
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
    net::TcpStream,
    time::{sleep, timeout},
};
use tokio_rustls::TlsConnector;
use tower::Service;

use crate::common::SandholeHandle;

/// This test ensures that an HTTP connection times out after a certain time
/// configured by the server.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn http_timeout() {
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

    // 2. Start SSH client that will be proxied
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
    session
        .tcpip_forward("foobar.tld", 80)
        .await
        .expect("tcpip_forward failed");

    // 3. Idle after connecting to the HTTP port of our proxy
    let tcp_stream = TcpStream::connect("127.0.0.1:18080")
        .await
        .expect("TCP connection failed");
    let (sender, conn): (SendRequest<Incoming>, _) =
        hyper::client::conn::http1::handshake(TokioIo::new(tcp_stream))
            .await
            .expect("HTTP handshake failed");
    if timeout(Duration::from_secs(2), async {
        assert!(
            conn.await.is_err(),
            "connection should've closed with an error"
        );
    })
    .await
    .is_err()
    {
        panic!("Timeout waiting for connection to be closed.")
    };
    drop(sender);

    // 4. Idle after connecting to the HTTPS port of our proxy
    let tcp_stream = TcpStream::connect("127.0.0.1:18443")
        .await
        .expect("TCP connection failed");
    let mut buf = [0u8; 8];
    if timeout(Duration::from_secs(2), async {
        assert!(
            tcp_stream.try_read(&mut buf).is_err(),
            "connection should've closed with an error"
        );
    })
    .await
    .is_err()
    {
        panic!("Timeout waiting for connection to be closed.")
    };

    // 5. Idle after handshake to the HTTPS port of our proxy
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
        .connect("foobar.tld".try_into().unwrap(), tcp_stream)
        .await
        .expect("TLS stream failed");
    let (sender, conn): (SendRequest<Incoming>, _) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_stream))
            .await
            .expect("HTTP handshake failed");
    if timeout(Duration::from_secs(2), async {
        assert!(
            conn.await.is_err(),
            "connection should've closed with an error"
        );
    })
    .await
    .is_err()
    {
        panic!("Timeout waiting for connection to be closed.")
    };
    drop(sender);
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
        let router = Router::new().route("/", get(async || "Hello from foobar.tld!"));
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
