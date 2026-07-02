use std::{sync::Arc, time::Duration};

use clap::Parser;
use russh::client::ChannelOpenHandle;
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

/// This test ensures that a UDP socket times out after a certain time
/// configured by the server.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn udp_timeout() {
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
        "--allow-requested-ports",
        "--idle-connection-timeout=1s",
        "--authentication-request-timeout=5s",
        "--http-request-timeout=5s",
        "--udp-timeout=500ms",
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
    session_one
        .tcpip_forward("udp.sandhole", 12345)
        .await
        .expect("tcpip_forward failed");

    // 3. Connect to the UDP port of our proxy
    let udp_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("UDP connection failed");
    udp_socket.connect("127.0.0.1:12345").await.unwrap();

    // 4. Send messages without timeout
    let mut buf = [0u8; 32];
    udp_socket.send(b"Some message").await.unwrap();
    if timeout(Duration::from_secs(5), async {
        assert_eq!(udp_socket.recv(&mut buf).await.unwrap(), 1);
    })
    .await
    .is_err()
    {
        panic!("Timeout waiting for UDP socket to reply.")
    };
    assert_eq!(&buf[..1], b"1");
    udp_socket.send(b"Another message").await.unwrap();
    let mut buf = [0u8; 32];
    if timeout(Duration::from_secs(5), async {
        assert_eq!(udp_socket.recv(&mut buf).await.unwrap(), 1);
    })
    .await
    .is_err()
    {
        panic!("Timeout waiting for UDP socket to reply.")
    };
    assert_eq!(&buf[..1], b"2");

    // 5. Wait for timeout then receive same messages again
    sleep(Duration::from_secs(1)).await;
    udp_socket.send(b"Some message again").await.unwrap();
    if timeout(Duration::from_secs(5), async {
        assert_eq!(udp_socket.recv(&mut buf).await.unwrap(), 1);
    })
    .await
    .is_err()
    {
        panic!("Timeout waiting for UDP socket to reply.")
    };
    assert_eq!(&buf[..1], b"1");
    udp_socket.send(b"Another message again").await.unwrap();
    let mut buf = [0u8; 32];
    if timeout(Duration::from_secs(5), async {
        assert_eq!(udp_socket.recv(&mut buf).await.unwrap(), 1);
    })
    .await
    .is_err()
    {
        panic!("Timeout waiting for UDP socket to reply.")
    };
    assert_eq!(&buf[..1], b"2");

    // 6. Attempt to close UDP forwarding
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
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        tokio::spawn(async move {
            let mut counter = 0;
            loop {
                while let Some(msg) = &mut channel.wait().await {
                    match msg {
                        russh::ChannelMsg::Data { .. } => {
                            counter += 1;
                            channel
                                .data(match counter {
                                    1 => &b"\x00\x011"[..],
                                    2 => &b"\x00\x012"[..],
                                    _ => &b"\x00\x00"[..],
                                })
                                .await
                                .unwrap();
                        }
                        russh::ChannelMsg::Close => break,
                        msg => panic!("Unexpected message {msg:?}"),
                    }
                }
            }
        });
        reply.accept().await;
        Ok(())
    }
}
