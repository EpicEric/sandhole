use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::{
    extract::{Path, Request},
    routing::get,
    Router,
};
use http_body_util::BodyExt;
use hyper::{body::Incoming, service::service_fn, StatusCode};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use russh::{
    client::{self, Msg, Session},
    Channel,
};
use russh_keys::{key, load_secret_key};
use rustls::{
    pki_types::{pem::PemObject, CertificateDer},
    RootCertStore,
};
use sandhole::{
    config::{ApplicationConfig, BindHostnames},
    entrypoint,
};
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};
use tokio_rustls::TlsConnector;
use tower::Service;

#[tokio::test(flavor = "multi_thread")]
async fn bind_all_hostnames() {
    // 1. Initialize Sandhole
    let config = ApplicationConfig {
        domain: "foobar.tld".into(),
        domain_redirect: "https://tokio.rs/".into(),
        public_keys_directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/public_keys")
            .into(),
        certificates_directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/certificates")
            .into(),
        private_key_file: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/server_keys/ssh").into(),
        private_key_password: None,
        listen_address: "127.0.0.1".into(),
        ssh_port: 18022,
        http_port: 18080,
        https_port: 18443,
        force_https: false,
        acme_contact_email: None,
        acme_cache_directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/acme_cache").into(),
        acme_use_staging: true,
        bind_hostnames: BindHostnames::All,
        allow_provided_subdomains: false,
        random_subdomain_seed: None,
        txt_record_prefix: "_sandhole".into(),
        request_timeout: Duration::from_secs(5),
    };
    tokio::spawn(async move { entrypoint(config).await });
    if let Err(_) = timeout(Duration::from_secs(5), async {
        while let Err(_) = TcpStream::connect("127.0.0.1:18022").await {
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    {
        panic!("Timeout waiting for Sandhole to start.")
    };

    // 2. Start SSH client that will be proxied
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
        None,
    )
    .expect("Missing file key1");
    let ssh_config = Arc::new(russh::client::Config::default());
    let ssh_client = SshClient {
        router: Router::new().route(
            "/:user",
            get(|Path(user): Path<String>| async move { format!("Hello, {user}!") }),
        ),
    };
    let mut session = russh::client::connect(ssh_config, "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(session
        .authenticate_publickey("user", Arc::new(key))
        .await
        .expect("SSH authentication failed"));
    session
        .tcpip_forward("test.foobar.tld", 80)
        .await
        .expect("tcpip_forward failed");

    // 3. Connect to the HTTPS port of our proxy
    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(
        CertificateDer::pem_file_iter(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/ca/rootCA.pem"
        ))
        .and_then(|iter| iter.collect::<Result<Vec<_>, _>>())
        .unwrap(),
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
        .connect("test.foobar.tld".try_into().unwrap(), tcp_stream)
        .await
        .unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls_stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
    });
    let request = Request::builder()
        .method("GET")
        .uri("/world")
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
    assert_eq!(response_body, "Hello, world!");
}

struct SshClient {
    router: Router,
}

#[async_trait]
impl client::Handler for SshClient {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, _key: &key::PublicKey) -> Result<bool, Self::Error> {
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
        let router = self.router.clone().into_service();
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
