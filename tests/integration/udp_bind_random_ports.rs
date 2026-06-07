use std::{sync::Arc, time::Duration};

use clap::Parser;
use russh::keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use russh::{
    Channel,
    client::{Msg, Session},
};
use sandhole::{ApplicationConfig, entrypoint};
use tokio::net::UdpSocket;
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};

use crate::common::SandholeHandle;

/// This test ensures that random ports work for UDP connections.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn udp_bind_random_ports() {
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
        "--bind-hostnames=none",
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

    // 2. Start SSH client that will be proxied
    let key = load_secret_key(
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("tests/data/private_keys/key1"),
        None,
    )
    .expect("Missing file key1");
    let ssh_client = SshClient;
    let mut session_one = russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(
        session_one
            .authenticate_publickey(
                "user",
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
    let mut channel = session_one
        .channel_open_session()
        .await
        .expect("channel_open_session failed");
    session_one
        .tcpip_forward("udp.sandhole", 12345)
        .await
        .expect("tcpip_forward failed");
    let regex = regex::Regex::new(r"foobar\.tld:(\d+)").expect("Invalid regex");
    let Ok(port) = timeout(Duration::from_secs(3), async move {
        while let Some(message) = channel.wait().await {
            match message {
                russh::ChannelMsg::Data { data } => {
                    let data =
                        String::from_utf8(data.to_vec()).expect("Invalid UTF-8 from message");
                    if let Some(captures) = regex.captures(&data) {
                        let port = captures
                            .get(1)
                            .expect("Missing port capture group")
                            .as_str()
                            .to_string();
                        return port;
                    }
                }
                message => panic!("Unexpected message {message:?}"),
            }
        }
        panic!("Unexpected end of channel");
    })
    .await
    else {
        panic!("Timed out waiting for port allocation.");
    };
    assert!(
        port.parse::<u16>().expect("should be a valid port number") >= 1024,
        "random port must be greater than or equal to 1024"
    );

    // 3. Connect to the UDP port of our proxy
    let udp_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("UDP connection failed");
    udp_socket
        .connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    udp_socket.send(b"Ping").await.unwrap();
    let mut buf = [0u8; 32];
    if timeout(Duration::from_secs(5), async {
        assert_eq!(udp_socket.recv(&mut buf).await.unwrap(), 4);
    })
    .await
    .is_err()
    {
        panic!("Timeout waiting for UDP socket to reply.")
    };
    assert_eq!(&buf[..4], b"Pong");

    // 4. Attempt to close UDP forwarding
    session_one
        .cancel_tcpip_forward("udp.sandhole", 12345)
        .await
        .expect("cancel_tcpip_forward failed");
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
        mut channel: Channel<Msg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        tokio::spawn(async move {
            match &mut channel.wait().await.unwrap() {
                russh::ChannelMsg::Data { data } => {
                    assert_eq!(data.to_vec(), b"\x00\x04Ping");
                }
                msg => panic!("Unexpected message {msg:?}"),
            }
            channel.data(&b"\x00\x04Pong"[..]).await.unwrap();
        });
        Ok(())
    }
}
