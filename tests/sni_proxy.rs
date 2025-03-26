use std::{sync::Arc, time::Duration};

use axum::{Router, extract::Request, routing::get};
use clap::Parser;
use http_body_util::BodyExt;
use hyper::{StatusCode, body::Incoming, server::conn::http1::Builder, service::service_fn};
use hyper_util::rt::TokioIo;
use russh::{
    Channel,
    client::{Msg, Session},
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

// Certificate for sandhole.com.br with custom CA
const TLS_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----
MIIEGzCCAoOgAwIBAgIQKpoWlpOe+o/75k2YOODeVzANBgkqhkiG9w0BAQsFADBl
MR4wHAYDVQQKExVta2NlcnQgZGV2ZWxvcG1lbnQgQ0ExHTAbBgNVBAsMFGVyaWNA
ZXJpYy1wb3AgKEVyaWMpMSQwIgYDVQQDDBtta2NlcnQgZXJpY0BlcmljLXBvcCAo
RXJpYykwHhcNMjUwMzI4MDExMDI0WhcNMjcwNjI4MDExMDI0WjBIMScwJQYDVQQK
Ex5ta2NlcnQgZGV2ZWxvcG1lbnQgY2VydGlmaWNhdGUxHTAbBgNVBAsMFGVyaWNA
ZXJpYy1wb3AgKEVyaWMpMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
0IYz3Shy2GM7g8usGNO2ezCEgwsslrBX/VHE/nOlt/IUI2O3OIjNyP/smjITM8nu
6hHVsxBBEFS5e3D9HJUTRi8sftzZ4+lzWDSP6eYh8IeVk+taFbeQ2VKbSrhKsdHT
7URaV7o2IGYiKIMdTxD314aIZ5p+tRrMJyuFOmV1RU+jlnaa1n522fs8fC2AGkyt
aYP7NrqKoTvqTv9I9loxpbXxQMHUATZSoABnG/A7Ije4QsdeaE4i8ZABzVaCGSCl
IBKdbpOtLiT/RHKL0wMpJ+DlSWQnyOwz+mpM3R83my5x7WJrTB1eu5ro9vBR9NW3
CuLNNjOkW1kxUdqaObVirwIDAQABo2QwYjAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0l
BAwwCgYIKwYBBQUHAwEwHwYDVR0jBBgwFoAUt/sgfOEuNa0wsaUas98rXIcFa4Ew
GgYDVR0RBBMwEYIPc2FuZGhvbGUuY29tLmJyMA0GCSqGSIb3DQEBCwUAA4IBgQBz
VYkidjXl6wdn6Lng0oKQBzJxBTSRFfG+gYetuXjL8t5XTu+THYUpd9gjjZ3Fikug
bm09qAAGzmYCk+RcEkcOTM6BBZoDwk9zxwTmIi+sTqnCicXi3KpwTY890OTsZlJ8
LRpGHFvPT8Kv6dnZNbFqwoqFH1gUjoHdXNbwvzk6alXrRou3o9QjRJNctbOMekIW
sb24kNUsQ6VrLA2dHssSqKcZaiZvheXhLGYFLS4FPKfmFSXKpE6kjaWHRnKPa4bz
VuMylFcMWBI+62N6uWo9l5pcWWp12hwt7FskJmC6ROWJ08gEJTm1p7G7ZPq1/ygf
dtw9MMzodcnHvIBylk9B7mkAckgOvmnnLsKtVOvD73nZYpZJovYeBMj/RPLUcUtq
n3cJTrBy2R+HYXfW3I14esz2kskcpYeJP1ateSOtvQcIH0cFkgS+uREl+9WO31NE
84Ps5Z/Z0Wr7FeBl7AJ9dvI2EgUuNVcYRpvlJSFQhrtxho/pqywVP3S6Yjz6nkA=
-----END CERTIFICATE-----
";

const TLS_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDQhjPdKHLYYzuD
y6wY07Z7MISDCyyWsFf9UcT+c6W38hQjY7c4iM3I/+yaMhMzye7qEdWzEEEQVLl7
cP0clRNGLyx+3Nnj6XNYNI/p5iHwh5WT61oVt5DZUptKuEqx0dPtRFpXujYgZiIo
gx1PEPfXhohnmn61GswnK4U6ZXVFT6OWdprWfnbZ+zx8LYAaTK1pg/s2uoqhO+pO
/0j2WjGltfFAwdQBNlKgAGcb8DsiN7hCx15oTiLxkAHNVoIZIKUgEp1uk60uJP9E
covTAykn4OVJZCfI7DP6akzdHzebLnHtYmtMHV67muj28FH01bcK4s02M6RbWTFR
2po5tWKvAgMBAAECggEAEWxlQQF0NyhzfJu0EY7/HGP9boWsgBrT/1Kpxykam7ga
fqqCULL9nuHjfy7X8+fXkq9Sz9d32El8Bhh2zcCXD7I5YZBKlISZIrGhpMWZ6GMr
2GQ97rqb28zPNPsZIqqJrrWbZuEkTKi8Ce6KsGSWkOeo1h9OnwtSK6OzSiHYHqZW
HHWjJJINVKES6BVst/rOzKm6RpfPJtU45gl0BqfZqHZD8AvzOS1Wfic/0xnuOnUo
P5iqxxgqbObNpoKzART6XAvlDzw6DyTCXgw5PhYvLf6IHB5JdWg/6BE3kKX9mHWY
ufjJB///7alAxeWyvTsvtIUDKFKMCTUKRZ/WYlzxoQKBgQDTK48I1sNLCXR15Mns
XsweTyv7E/lv0TqO4BWG1wIAEhFh9fqelwavoS+sI3Hq39UyA0RfVYS5Jzmzy5E1
kyF/a7UuCDoiJIBt0g4U3jSMfaCZ7RXZ5nWhjo1gSlzTHPcS7tQznZ8GwLYjLFyY
L6n7dsMUAC2dr/ogOqji1ZlR0wKBgQD8ytihCuUoIuFN7HUeC48zr4sZvU3VIDW6
pldt9+TNJPGViryVep2bWi0DyjkP6fav6dLrowLwAUHNel4xO2Kn/n9qw/m9XphX
uGU+75kSRz/Sb6Q/38PteXYXrrx9n4on2aVzq9POFcQfB2w9R5rz4PJMUN8dHuK8
0SiNlnGGNQKBgQDQaKT57DtBy0sNL4e5qLV7FFgrrEL5gF1ytOWJ9pkayLovHD0E
V7lZjJMoKLM9Qzt96IuKKzSaJ4RjVf0yCst8nihqDeSR3cSCnlUXc1YZccMXJ03x
h+mAUNhmt/10vZl7LgpwBpf0ai1X+WhJKoFwlH1jN+nNPuh09m/Hr1dp0QKBgQCg
Mf+j1l6v16LFmdICLzsZeuYAcrlvFRFXbfA7zPsekYnSxW+KnoBgIX4jR7RvhEmC
4v95ufyzkWhcyW4FbuevJBUk2Hpb6iVKeZ0XjAiJz8L/HSaOH8RuqikPCvmB9mc7
p640pi/8CkkVjMOn9ceZQvTpLdql/pubIkS7rRnV/QKBgQDK68UzGJJrK2MWuecE
gv/IFroGyBkT+srvbFP9VVbS8GZgxU/Io88UnQz8j3NW96gvyIJha9JpjGhSt7fA
8FDgfgzg3Yk2dumXG51R/LpITxB9mwuqWPZZ/sTVK2OOoxXD3ooeyC257TltLJ5k
o6ioYnJQHPsfaym/DY0seYghtg==
-----END PRIVATE KEY-----
";

#[tokio::test(flavor = "multi_thread")]
async fn sni_proxy() {
    // 1. Initialize Sandhole
    let _ = env_logger::builder()
        .filter_module("sandhole", log::LevelFilter::Debug)
        .is_test(true)
        .try_init();
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

    // 2. Start SSH client that will be proxied with SNI
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
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
        .tcpip_forward("sandhole.com.br", 443)
        .await
        .expect("tcpip_forward failed");
    let channel = session
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

    // 3. Connect to the SNI-protected port of our proxy
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
    let tcp_stream = TcpStream::connect("127.0.0.1:18443")
        .await
        .expect("TCP connection failed");
    let tls_stream = connector
        .connect("sandhole.com.br".try_into().unwrap(), tcp_stream)
        .await
        .expect("TLS stream failed");
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls_stream))
        .await
        .expect("HTTP handshake failed");
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            eprintln!("Connection failed: {:?}", err);
        }
    });
    let request = Request::builder()
        .method("GET")
        .uri("/sni-proxy")
        .header("host", "sandhole.com.br")
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
    assert_eq!(response_body, "Hello from SNI proxy!");

    // 4. Attempt to close SNI proxy
    session
        .cancel_tcpip_forward("sandhole.com.br", 443)
        .await
        .expect("cancel_tcpip_forward failed");
}

struct SshClient(Option<oneshot::Sender<ChannelId>>);

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
        tokio::spawn(async move {
            let router = Router::new().route("/sni-proxy", get(async || "Hello from SNI proxy!"));
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
