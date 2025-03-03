use std::{sync::Arc, time::Duration};

use clap::Parser;
use regex::Regex;
use russh::keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use russh::{
    client::{self, Msg, Session},
    Channel,
};
use sandhole::{entrypoint, ApplicationConfig};
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
    sync::mpsc,
    time::{sleep, timeout},
};

#[tokio::test(flavor = "multi_thread")]
async fn admin_missing_pty() {
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
        "--allow-requested-ports",
        "--idle-connection-timeout=800ms",
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

    // 2. Start SSH client that will be proxied
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
    if timeout(Duration::from_secs(1), async move {
        // 4a. Validate header, system information, and HTTP tab data
        let search_strings: Vec<Regex> = [
            r#"PTY not detected! Make sure to connect with "ssh -t \.\.\. admin" instead\."#,
            r"Press Ctrl-C to close this connection\.",
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
        // 4b. Quit the admin interface with Ctrl-C (ETX)
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
            channel.data(&b"Hello, world!"[..]).await.unwrap();
            channel.eof().await.unwrap();
        });
        Ok(())
    }
}

struct SshClientAdmin;

impl russh::client::Handler for SshClientAdmin {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
