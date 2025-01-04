use std::{net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::{extract::Request, response::IntoResponse, routing::post, Json, Router};
use clap::Parser;
use http::StatusCode;
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use regex::Regex;
use russh::{
    client::{self, Msg, Session},
    Channel,
};
use russh_keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use sandhole::{entrypoint, ApplicationConfig};
use serde::Deserialize;
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
    sync::mpsc,
    time::{sleep, timeout},
};
use tower::Service;

#[tokio::test(flavor = "multi_thread")]
async fn admin_remove_user() {
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
        "--bind-hostnames=all",
        "--allow-requested-subdomains",
        "--allow-requested-ports",
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

    // 2. Start SSH client that will host the login API and not be removed
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
        None,
    )
    .expect("Missing file key1");
    let ssh_client = SshClient;
    let mut session_1 = russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(
        session_1
            .authenticate_publickey(
                "user",
                PrivateKeyWithHashAlg::new(Arc::new(key), None).unwrap()
            )
            .await
            .expect("SSH authentication failed"),
        "authentication didn't succeed"
    );
    session_1
        .tcpip_forward("localhost", 38080)
        .await
        .expect("tcpip_forward failed");

    // 3. Start SSH client that will be proxied and later removed by the admin
    let ssh_client = SshClient;
    let mut session_2 = russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(
        session_2
            .authenticate_password("custom_user", "password")
            .await
            .expect("SSH authentication failed"),
        "authentication didn't succeed"
    );
    session_2
        .tcpip_forward("aaa.foobar.tld", 443)
        .await
        .expect("tcpip_forward failed");
    session_2
        .tcpip_forward("localhost", 12345)
        .await
        .expect("tcpip_forward failed");
    // Required for updating the admin interface data
    sleep(Duration::from_secs(3)).await;

    // 4. Request admin pty
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/admin"),
        None,
    )
    .expect("Missing file admin");
    let ssh_client = SshClientAdmin;
    let mut session = client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(
        session
            .authenticate_publickey(
                "admin",
                PrivateKeyWithHashAlg::new(Arc::new(key), None).unwrap()
            )
            .await
            .expect("SSH authentication failed"),
        "authentication didn't succeed"
    );
    let mut channel = session
        .channel_open_session()
        .await
        .expect("channel_open_session failed");
    channel
        .request_pty(false, "xterm", 140, 30, 640, 480, &[])
        .await
        .expect("request_pty failed");
    channel
        .exec(false, "admin")
        .await
        .expect("exec admin failed");

    // 4. Interact with the admin interface and verify displayed data
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut writer = channel.make_writer();
    let jh = tokio::spawn(async move {
        let mut parser = vt100_ctt::Parser::new(30, 140, 0);
        let mut screen = Vec::new();
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { data } => {
                    parser.process(&data);
                    let new_screen = parser.screen();
                    let contents_formatted = new_screen.contents_formatted();
                    if contents_formatted != screen {
                        screen = contents_formatted;
                        tx.send(new_screen.contents()).unwrap();
                    }
                }
                _ => break,
            }
        }
    });
    if timeout(Duration::from_secs(5), async move {
        // 4a. Validate HTTP tab data
        let search_strings: Vec<Regex> = [
            r"Sandhole admin v\d+\.\d+\.\d+",
            r"HTTP services",
            r"aaa\.foobar\.tld",
            r"custom_user",
            r"127.0.0.1:\d{4,5}",
        ]
        .into_iter()
        .map(|re| Regex::new(re).expect("Invalid regex"))
        .collect();
        loop {
            let screen = rx.recv().await.unwrap();
            if search_strings.iter().all(|re| re.is_match(&screen)) {
                break;
            }
        }
        // 4b. Select user and open details
        writer
            .write(&b"\x1b[B"[..])
            .await
            .expect("channel write failed");
        writer
            .write(&b"\r"[..])
            .await
            .expect("channel write failed");
        let search_strings: Vec<Regex> = [
            r"Sandhole admin v\d+\.\d+\.\d+",
            r"User details",
            r"custom_user",
            r"Type: User",
            r"(authenticated with password)",
            r" <Esc> Close  <Delete> Remove ",
        ]
        .into_iter()
        .map(|re| Regex::new(re).expect("Invalid regex"))
        .collect();
        loop {
            let screen = rx.recv().await.unwrap();
            if search_strings.iter().all(|re| re.is_match(&screen)) {
                break;
            }
        }
        // 4c. Open removal prompt
        writer
            .write(&b"\x1b[3~"[..])
            .await
            .expect("channel write failed");
        let search_strings: Vec<Regex> = [
            r"Sandhole admin v\d+\.\d+\.\d+",
            r"Remove user?",
            r"Are you sure you want to remove the following user?",
            r"custom_user",
            r"They might still be able to reconnect via the login API!",
            r" <Esc> Cancel  <Enter> Confirm ",
        ]
        .into_iter()
        .map(|re| Regex::new(re).expect("Invalid regex"))
        .collect();
        loop {
            let screen = rx.recv().await.unwrap();
            if search_strings.iter().all(|re| re.is_match(&screen)) {
                break;
            }
        }
        // 4d. Confirm removal
        writer
            .write(&b"\r"[..])
            .await
            .expect("channel write failed");
        let search_strings: Vec<Regex> = [
            r"Sandhole admin v\d+\.\d+\.\d+",
            r"User removed successfully!",
            r" <Enter> Close ",
        ]
        .into_iter()
        .map(|re| Regex::new(re).expect("Invalid regex"))
        .collect();
        loop {
            let screen = rx.recv().await.unwrap();
            if search_strings.iter().all(|re| re.is_match(&screen)) {
                break;
            }
        }
        // Required for updating the admin interface data
        sleep(Duration::from_secs(3)).await;
        assert!(session_2.is_closed(), "user session wasn't terminated");
        // 4e. Close prompt, head to the TCP tab, and ensure that the window still displays the first service there
        assert!(
            !session_1.is_closed(),
            "proxy session shouldn't have been terminated"
        );
        writer
            .write(&b"\r"[..])
            .await
            .expect("channel write failed");
        writer
            .write(&b"\x1b[Z"[..])
            .await
            .expect("channel write failed");
        writer
            .write(&b"\x1b[Z"[..])
            .await
            .expect("channel write failed");
        let search_strings: Vec<Regex> = [
            r"Sandhole admin v\d+\.\d+\.\d+",
            r"TCP services",
            r"38080",
            r"SHA256:GehKyA21BBK6eJCouziacUmqYDNl8BPMGG0CTtLSrbQ",
            r"127.0.0.1:\d{4,5}",
        ]
        .into_iter()
        .map(|re| Regex::new(re).expect("Invalid regex"))
        .collect();
        loop {
            let screen = rx.recv().await.unwrap();
            if search_strings.iter().all(|re| re.is_match(&screen)) {
                break;
            }
        }
        // 4f. Select user and open details
        writer
            .write(&b"\x1b[B"[..])
            .await
            .expect("channel write failed");
        writer
            .write(&b"\r"[..])
            .await
            .expect("channel write failed");
        let search_strings: Vec<Regex> = [
            r"Sandhole admin v\d+\.\d+\.\d+",
            r"User details",
            r"SHA256:GehKyA21BBK6eJCouziacUmqYDNl8BPMGG0CTtLSrbQ",
            r"Type: User",
            r"Key comment: key1",
            r"Algorithm: ssh-ed25519",
            r" <Esc> Close  <Delete> Remove ",
        ]
        .into_iter()
        .map(|re| Regex::new(re).expect("Invalid regex"))
        .collect();
        loop {
            let screen = rx.recv().await.unwrap();
            if search_strings.iter().all(|re| re.is_match(&screen)) {
                break;
            }
        }
        // 4g. Quit the admin interface with Ctrl-C (ETX)
        writer
            .write(&b"\x03"[..])
            .await
            .expect("channel write failed");
    })
    .await
    .is_err()
    {
        panic!("Timed out waiting for admin interface.");
    }
    sleep(Duration::from_millis(200)).await;
    assert!(session.is_closed(), "session didn't close properly");
    jh.abort();
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
        #[derive(Debug, Deserialize)]
        struct AuthenticationRequest {
            user: String,
            password: String,
            remote_address: SocketAddr,
        }
        async fn authentication_route(
            Json(body): Json<AuthenticationRequest>,
        ) -> impl IntoResponse {
            if body.user == "custom_user"
                && body.password == "password"
                && body.remote_address.ip().is_loopback()
            {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            }
        }
        let router = Router::new()
            .route("/authenticate", post(authentication_route))
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

struct SshClientAdmin;

#[async_trait]
impl russh::client::Handler for SshClientAdmin {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, _key: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
