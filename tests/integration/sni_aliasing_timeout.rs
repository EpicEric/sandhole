use std::{sync::Arc, time::Duration};

use axum::{Router, extract::Request, routing::get};
use clap::Parser;
use http::header::HOST;
use hyper::{body::Incoming, server::conn::http1::Builder, service::service_fn};
use hyper_util::rt::TokioIo;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use russh::{
    Channel,
    client::{Msg, Session},
    keys::ssh_key::private::Ed25519Keypair,
};
use russh::{
    ChannelId,
    keys::{key::PrivateKeyWithHashAlg, load_secret_key},
};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, pem::PemObject},
};
use rustls_pki_types::PrivateKeyDer;
use sandhole::{ApplicationConfig, entrypoint};
use tokio::{
    net::TcpStream,
    sync::oneshot,
    time::{sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tower::Service;

use crate::common::SandholeHandle;

// Certificate for sandhole.com.br with custom CA
const TLS_CERTIFICATE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/data/custom_certificate/fullchain.pem"
));
const TLS_KEY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/data/custom_certificate/privkey.pem"
));

/// This test ensures that an aliased SNI connection times out after a certain
/// time configured by the server.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn sni_aliasing_timeout() {
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

    // 2. Start SSH client that will be proxied with SNI
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
        None,
    )
    .expect("Missing file key1");
    let (tx, rx) = oneshot::channel();
    let ssh_client_one = SshClient(Some(tx));
    let mut session_one =
        russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client_one)
            .await
            .expect("Failed to connect to SSH server");
    assert!(
        session_one
            .authenticate_publickey(
                "user1",
                PrivateKeyWithHashAlg::new(
                    Arc::new(key),
                    session_one
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
    session_one
        .tcpip_forward("sandhole.com.br", 443)
        .await
        .expect("tcpip_forward failed");
    let channel = session_one
        .channel_open_session()
        .await
        .expect("channel_open_session failed");
    channel
        .exec(true, "sni-proxy")
        .await
        .expect("exec sni-proxy failed");
    let Ok(channel_id) = timeout(Duration::from_secs(2), async { rx.await.unwrap() }).await else {
        panic!("Timeout waiting for server to reply.");
    };
    assert_eq!(channel_id, channel.id());

    // 3. Alias to our SNI proxy
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
    let connector = TlsConnector::from(tls_config);
    let key = russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(
        &ChaCha20Rng::from_os_rng().random(),
    ));
    let ssh_client = ProxyClient;
    let mut session_two = russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(
        session_two
            .authenticate_publickey(
                "user2",
                PrivateKeyWithHashAlg::new(
                    Arc::new(key),
                    session_two
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
    let channel_two = session_two
        .channel_open_direct_tcpip("sandhole.com.br", 18443, "::1", 12345)
        .await
        .expect("Local forwarding failed");
    let tls_stream = connector
        .connect(
            "sandhole.com.br".try_into().unwrap(),
            channel_two.into_stream(),
        )
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
        .method("GET")
        .uri("/slow-sni-proxy")
        .header(HOST, "sandhole.com.br")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let Ok(_) = timeout(Duration::from_secs(5), async move {
        assert!(
            sender.send_request(request).await.is_err(),
            "Connection should've timed out"
        )
    })
    .await
    else {
        panic!("Timeout waiting for request to finish.");
    };
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
        tokio::spawn(async move {
            let router = Router::new().route(
                "/slow-sni-proxy",
                get(async || {
                    sleep(Duration::from_secs(1)).await;
                    "Hello from a slow endpoint!"
                }),
            );
            let service = service_fn(move |req: Request<Incoming>| router.clone().call(req));
            let certs = CertificateDer::pem_slice_iter(TLS_CERTIFICATE.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let key = PrivateKeyDer::from_pem_slice(TLS_KEY.as_bytes()).unwrap();
            let config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap();
            let acceptor = TlsAcceptor::from(Arc::new(config));
            let stream = acceptor.accept(channel.into_stream()).await.unwrap();
            Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
                .expect("Invalid request");
        });
        Ok(())
    }

    async fn channel_success(
        &mut self,
        channel: russh::ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(tx) = self.0.take() {
            tx.send(channel).unwrap();
        };
        Ok(())
    }
}

struct ProxyClient;

impl russh::client::Handler for ProxyClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
