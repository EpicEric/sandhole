use std::{sync::Arc, time::Duration};

use clap::Parser;
use regex::Regex;
use russh::keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use russh::{
    Channel,
    client::{self, Msg, Session},
};
use sandhole::{ApplicationConfig, entrypoint};
use tokio::{
    net::TcpStream,
    sync::mpsc,
    time::{sleep, timeout},
};

use crate::common::SandholeHandle;

/// This test ensures that an admin user cannot access the admin interface and
/// perform remote forwarding at the same time.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn admin_no_interface_if_forwarding() {
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
        "--allow-requested-ports",
        "--idle-connection-timeout=800ms",
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

    // 2. Start SSH client that will be proxied
    let key = load_secret_key(
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("tests/data/private_keys/key2"),
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
        .tcpip_forward("http.aaa", 443)
        .await
        .expect("tcpip_forward failed");
    session
        .tcpip_forward("ssh.bbb", 22)
        .await
        .expect("tcpip_forward failed");
    session
        .tcpip_forward("proxy.ccc", 12345)
        .await
        .expect("tcpip_forward failed");
    session
        .tcpip_forward("", 23456)
        .await
        .expect("tcpip_forward failed");
    // Required for updating the admin interface data
    sleep(Duration::from_secs(3)).await;

    // 3. Request admin pty
    let key = load_secret_key(
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("tests/data/private_keys/admin"),
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
                        let _ = tx.send(new_screen.contents());
                    }
                }
                _ => break,
            }
        }
    });
    if timeout(Duration::from_secs(3), async move {
        let search_strings: Vec<Regex> = [
            r"Sandhole admin v\d+\.\d+\.\d+",
            r"System information",
            r"  CPU%  ",
            r" Memory ",
            r"   TX   ",
            r"   RX   ",
            r"HTTP services",
            r"http\.aaa",
            r"SHA256:F7r4la\S*",
            r"127\.0\.0\.1:\d{4,5}",
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
    })
    .await
    .is_err()
    {
        panic!("Timed out waiting for admin interface.");
    }

    // 5. Attempt to remote forward and get disconnected
    assert!(
        session.tcpip_forward("localhost", 80).await.is_err(),
        "tcpip_forward should've errored"
    );
    sleep(Duration::from_millis(200)).await;
    assert!(session.is_closed(), "session should've been closed");
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
        tokio::spawn(async move {
            channel.data(&b"Hello, world!"[..]).await.unwrap();
            channel.eof().await.unwrap();
        });
        Ok(())
    }
}

struct SshClientAdmin;

impl russh::client::Handler for SshClientAdmin {
    type Error = color_eyre::eyre::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
