use std::{
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

use clap::Parser;
use russh::{
    Channel,
    client::{Msg, Session},
    keys::{key::PrivateKeyWithHashAlg, load_secret_key},
};
use sandhole::{ApplicationConfig, entrypoint};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    net::TcpStream,
    time::{sleep, timeout},
};

use crate::common::SandholeHandle;

/// This test ensures that SSH clients that stop replying in the keepalive
/// interval get disconnected.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn ssh_client_timeout() {
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
        "--bind-hostnames=none",
        "--ssh-keepalive-interval=3s",
        "--ssh-keepalive-max=2",
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

    // 2. Start SSH client that should stay alive through keepalive timeout
    let key = Arc::new(
        load_secret_key(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
            None,
        )
        .expect("Missing file key1"),
    );
    let ssh_client = SshClient;
    let mut good_session =
        russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
            .await
            .expect("Failed to connect to SSH server");
    assert!(
        good_session
            .authenticate_publickey(
                "good-user",
                PrivateKeyWithHashAlg::new(
                    Arc::clone(&key),
                    good_session
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
    let good_port = good_session
        .tcpip_forward("localhost", 0)
        .await
        .expect("tcpip_forward failed");
    sleep(Duration::from_secs(1)).await;

    // 3. Start SSH client that will be disconnected by keepalive timeout
    let ssh_client = SshClient;
    let mut bad_session = russh::client::connect_stream(
        Default::default(),
        FailingSocket {
            inner: TcpStream::connect("127.0.0.1:18022").await.unwrap(),
            timer: Instant::now(),
        },
        ssh_client,
    )
    .await
    .expect("Failed to connect to SSH server");
    assert!(
        bad_session
            .authenticate_publickey(
                "user",
                PrivateKeyWithHashAlg::new(
                    key,
                    bad_session
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
    let bad_port = bad_session
        .tcpip_forward("localhost", 0)
        .await
        .expect("tcpip_forward failed");
    assert!(
        timeout(Duration::from_secs(30), &mut bad_session)
            .await
            .is_ok(),
        "Timeout waiting for client disconnection."
    );

    // 4. Ensure that only the good connection is still forwarding
    sleep(Duration::from_millis(500)).await;
    assert!(
        bad_session.is_closed(),
        "failing session should've been closed"
    );
    assert!(
        TcpStream::connect(format!("127.0.0.1:{bad_port}"))
            .await
            .is_err(),
        "TCP connection should've failed for bad session"
    );
    assert!(
        !good_session.is_closed(),
        "normal session shouldn't have been closed"
    );
    let mut tcp_stream = TcpStream::connect(format!("127.0.0.1:{good_port}"))
        .await
        .expect("TCP connection failed");
    let mut buf = String::with_capacity(12);
    tcp_stream.read_to_string(&mut buf).await.unwrap();
    assert_eq!(buf, "Hello world!");
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
            channel.data(&b"Hello world!"[..]).await.unwrap();
            channel.eof().await.unwrap();
        });
        Ok(())
    }
}

struct FailingSocket {
    inner: TcpStream,
    timer: Instant,
}

impl AsyncRead for FailingSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for FailingSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        if self.timer.elapsed() >= Duration::from_secs(2) {
            std::task::Poll::Ready(Ok(buf.len()))
        } else {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
