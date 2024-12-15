use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::{extract::Request, routing::get, Router};
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
use sandhole::{entrypoint, ApplicationConfig, BindHostnames, LoadBalancing};
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};
use tower::Service;

#[tokio::test(flavor = "multi_thread")]
async fn quota_maximum_per_user() {
    // 1. Initialize Sandhole
    let config = ApplicationConfig {
        domain: "foobar.tld".into(),
        domain_redirect: "https://tokio.rs/".into(),
        user_keys_directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/user_keys").into(),
        admin_keys_directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/admin_keys").into(),
        certificates_directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/certificates")
            .into(),
        private_key_file: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/server_keys/ssh").into(),
        disable_directory_creation: true,
        listen_address: "127.0.0.1".into(),
        password_authentication_url: None,
        ssh_port: 18022,
        http_port: 18080,
        https_port: 18443,
        force_https: false,
        disable_http_logs: false,
        disable_tcp_logs: false,
        acme_contact_email: None,
        acme_cache_directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/acme_cache").into(),
        acme_use_staging: true,
        bind_hostnames: BindHostnames::None,
        load_balancing: LoadBalancing::Allow,
        allow_provided_subdomains: false,
        allow_requested_ports: false,
        quota_per_user: Some(1usize.try_into().unwrap()),
        random_subdomain_seed: None,
        txt_record_prefix: "_sandhole".into(),
        idle_connection_timeout: Duration::from_secs(1),
        authentication_request_timeout: Duration::from_secs(5),
        http_request_timeout: Duration::from_secs(5),
        tcp_connection_timeout: None,
    };
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

    // 2. Start SSH client that will reach quota
    let key_1 = Arc::new(
        load_secret_key(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
            None,
        )
        .expect("Missing file key1"),
    );
    let ssh_client = SshClient;
    let mut session_1 = russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(session_1
        .authenticate_publickey(
            "user",
            PrivateKeyWithHashAlg::new(Arc::clone(&key_1), None).unwrap()
        )
        .await
        .expect("SSH authentication failed"));
    session_1
        .tcpip_forward("some.random.hostname", 80)
        .await
        .expect("tcpip_forward failed");
    assert!(session_1
        .tcpip_forward("another.random.hostname", 80)
        .await
        .is_err());

    // 3. Try to connect via different client with same credentials and reach quota again
    let ssh_client = SshClient;
    let mut session_2 = russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(session_2
        .authenticate_publickey(
            "user",
            PrivateKeyWithHashAlg::new(Arc::clone(&key_1), None).unwrap()
        )
        .await
        .expect("SSH authentication failed"));
    assert!(session_2
        .tcpip_forward("sneaky.random.hostname", 80)
        .await
        .is_err());

    // 4. Cancel first forwarding, then succeed on new one
    session_1
        .cancel_tcpip_forward("some.random.hostname", 80)
        .await
        .expect("cancel_tcpip_forward failed");
    session_2
        .tcpip_forward("new.random.hostname", 80)
        .await
        .expect("tcpip_forward failed");

    // 5. Admin user doesn't have quota limit
    let admin_key = Arc::new(
        load_secret_key(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/admin"),
            None,
        )
        .expect("Missing file admin"),
    );
    let ssh_client = SshClient;
    let mut session_admin =
        russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
            .await
            .expect("Failed to connect to SSH server");
    assert!(session_admin
        .authenticate_publickey(
            "admin",
            PrivateKeyWithHashAlg::new(Arc::clone(&admin_key), None).unwrap()
        )
        .await
        .expect("SSH authentication failed"));
    session_admin
        .tcpip_forward("some.random.hostname", 80)
        .await
        .expect("tcpip_forward failed");
    session_admin
        .tcpip_forward("another.random.hostname", 80)
        .await
        .expect("tcpip_forward failed");
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
            .route(
                "/",
                get(|| async move { format!("Max quota shenanigans.") }),
            )
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
