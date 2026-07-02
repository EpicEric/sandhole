use std::{sync::Arc, time::Duration};

use clap::Parser;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;
use russh::client::ChannelOpenHandle;
use russh::keys::ssh_key::private::Ed25519Keypair;
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

/// This test ensures that UDP works when binding for all ports is allowed.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn udp_allow_requested_ports() {
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

    // 4. Local-forward the UDP port for random user
    let key = russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(
        &ChaCha20Rng::from_rng(&mut rand::rng()).random(),
    ));
    let ssh_client = SshClient;
    let mut session_two = russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(
        session_two
            .authenticate_publickey(
                "user",
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
    let mut channel = session_two
        .channel_open_direct_tcpip("udp.sandhole", 12345, "::1", 23456)
        .await
        .expect("Local forwarding failed");
    if timeout(Duration::from_secs(5), async {
        channel.data(&b"\x00\x04Ping"[..]).await.unwrap();
        match &mut channel.wait().await.unwrap() {
            russh::ChannelMsg::Data { data } => {
                assert_eq!(data.to_vec(), b"\x00\x04Pong");
            }
            msg => panic!("Unexpected message {msg:?}"),
        }
    })
    .await
    .is_err()
    {
        panic!("Timeout waiting for proxy server to reply.")
    };

    // 5. Local-forward the UDP port for known user
    let key = load_secret_key(
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("tests/data/private_keys/key2"),
        None,
    )
    .expect("Missing file key2");
    let ssh_client = SshClient;
    let mut session_three =
        russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
            .await
            .expect("Failed to connect to SSH server");
    assert!(
        session_three
            .authenticate_publickey(
                "user",
                PrivateKeyWithHashAlg::new(
                    Arc::new(key),
                    session_three
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
    let mut channel = session_three
        .channel_open_direct_tcpip("udp.sandhole", 12345, "::1", 23456)
        .await
        .expect("Local forwarding failed");
    if timeout(Duration::from_secs(5), async {
        channel.data(&b"\x00\x04Ping"[..]).await.unwrap();
        match &mut channel.wait().await.unwrap() {
            russh::ChannelMsg::Data { data } => {
                assert_eq!(data.to_vec(), b"\x00\x04Pong");
            }
            msg => panic!("Unexpected message {msg:?}"),
        }
    })
    .await
    .is_err()
    {
        panic!("Timeout waiting for proxy server to reply.")
    };

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
            match &mut channel.wait().await.unwrap() {
                russh::ChannelMsg::Data { data } => {
                    assert_eq!(data.to_vec(), b"\x00\x04Ping");
                }
                msg => panic!("Unexpected message {msg:?}"),
            }
            channel.data(&b"\x00\x04Pong"[..]).await.unwrap();
        });
        reply.accept().await;
        Ok(())
    }
}
