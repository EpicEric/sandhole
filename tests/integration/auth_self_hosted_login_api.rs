use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{Json, Router, extract::Request, response::IntoResponse, routing::post};
use clap::Parser;
use hyper::{StatusCode, body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use russh::{
    Channel,
    client::{Msg, Session},
};
use russh::{
    Disconnect,
    keys::{key::PrivateKeyWithHashAlg, load_secret_key},
};
use sandhole::{ApplicationConfig, entrypoint};
use serde::Deserialize;
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};
use tower::Service;

use crate::common::SandholeHandle;

/// This test ensures that it's possible to authenticate an SSH user + password
/// via the login API by a (TCP) service hosted on Sandhole itself.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn auth_self_hosted_login_api() {
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
        "--password-authentication-url=http://localhost:38080/authenticate",
        "--bind-hostnames=none",
        "--allow-requested-ports",
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

    // 2. Start SSH client that will start the login API
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
        .tcpip_forward("localhost", 38080)
        .await
        .expect("tcpip_forward failed");

    // 3. Succeed in user+password login, create remote forwardings, then disconnect
    let new_ssh_client = SshClient;
    let mut session = russh::client::connect(Default::default(), "127.0.0.1:18022", new_ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(
        session
            .authenticate_password("eric", "sandhole")
            .await
            .expect("password authentication failed")
            .success(),
        "authentication didn't succeed"
    );
    session
        .tcpip_forward("localhost", 0)
        .await
        .expect("tcpip_forward failed");
    session
        .disconnect(Disconnect::ByApplication, "", "English")
        .await
        .expect("disconnect failed");
    sleep(Duration::from_millis(500)).await;
    assert!(session.is_closed());

    // 4. Fail in user+password login
    let new_ssh_client = SshClient;
    let mut session = russh::client::connect(Default::default(), "127.0.0.1:18022", new_ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(
        !session
            .authenticate_password("eric", "invalid_password")
            .await
            .expect("password authentication failed")
            .success(),
        "authentication shouldn't have succeeded"
    );
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
        #[derive(Debug, Deserialize)]
        struct AuthenticationRequest {
            user: String,
            password: String,
            remote_address: SocketAddr,
        }
        async fn authentication_route(
            Json(body): Json<AuthenticationRequest>,
        ) -> impl IntoResponse {
            if body.user == "eric"
                && body.password == "sandhole"
                && body.remote_address.ip().to_canonical().is_loopback()
            {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            }
        }
        let router = Router::new().route("/authenticate", post(authentication_route));
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
