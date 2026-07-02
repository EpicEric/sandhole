use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use clap::Parser;
use russh::{
    Channel,
    client::{Msg, Session},
};
use russh::{
    client::ChannelOpenHandle,
    keys::{key::PrivateKeyWithHashAlg, load_secret_key},
};
use sandhole::{ApplicationConfig, entrypoint};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::{sleep, timeout},
};

use crate::common::SandholeHandle;

/// This test ensures that no more UDP connections from the same IP
/// than the specified limit are able to connect at the same time.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn udp_ip_connections_limit() {
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
        "--listen-address=::",
        "--ssh-port=18022",
        "--http-port=18080",
        "--https-port=18443",
        "--acme-use-staging",
        "--allow-requested-ports",
        "--idle-connection-timeout=1s",
        "--authentication-request-timeout=5s",
        "--max-simultaneous-connections-per-ip=1",
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
        .tcpip_forward("udp.sandhole", 12345)
        .await
        .expect("tcpip_forward failed");

    // 3. Start long-running request that takes the spot for the IP
    tokio::time::sleep(Duration::from_millis(500)).await;
    let started = Instant::now();
    let udp_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("UDP connection failed");
    udp_socket
        .connect("127.0.0.1:12345".to_string())
        .await
        .unwrap();
    udp_socket.send(b"0123456789").await.unwrap();
    let jh = tokio::spawn(async move {
        let mut data = [0u8; 16];
        assert_eq!(
            timeout(Duration::from_secs(6), async {
                udp_socket.recv(&mut data).await.unwrap()
            })
            .await
            .unwrap(),
            2
        );
        assert_eq!(&data[..2], b"OK");
    });

    // 4. Start request that gets rate-limited from IP connection exhaustion
    tokio::time::sleep(Duration::from_millis(500)).await;
    let udp_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("UDP connection failed");
    udp_socket
        .connect("127.0.0.1:12345".to_string())
        .await
        .unwrap();
    udp_socket.send(b"0123456789").await.unwrap();
    let jh2 = tokio::spawn(async move {
        let mut data = [0u8; 16];
        assert!(
            timeout(Duration::from_secs(6), async {
                udp_socket.recv(&mut data).await.unwrap()
            })
            .await
            .is_err()
        );
    });

    // 5. Start request from different IP that succeeds
    let udp_socket = UdpSocket::bind("[::1]:0")
        .await
        .expect("UDP connection failed");
    udp_socket.connect("[::1]:12345".to_string()).await.unwrap();
    udp_socket.send(b"0123456789").await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    let mut data = [0u8; 16];
    assert_eq!(
        timeout(Duration::from_secs(6), async {
            udp_socket.recv(&mut data).await.unwrap()
        })
        .await
        .unwrap(),
        2
    );
    assert!(started.elapsed() > Duration::from_secs(5));
    assert_eq!(&data[..2], b"OK");

    timeout(Duration::from_secs(10), async move {
        jh.await.unwrap();
        jh2.await.unwrap();
    })
    .await
    .expect("timeout waiting for join handle to finish");
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
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        tokio::spawn(async move {
            let mut stream = channel.into_stream();
            let len = stream.read_u16().await.unwrap();
            let mut buf = [0; 32];
            stream.read_exact(&mut buf[..len as usize]).await.unwrap();
            assert_eq!(&buf[..len as usize], b"0123456789");
            tokio::time::sleep(Duration::from_secs(5)).await;
            stream.write_all(&b"\x00\x02OK"[..]).await.unwrap();
            stream.flush().await.unwrap();
        });
        reply.accept().await;
        Ok(())
    }
}
