use std::{sync::Arc, time::Duration};

use clap::Parser;
use rand::RngCore;
use russh::{
    Channel, ChannelMsg, Preferred,
    client::{Msg, Session},
};
use russh::{
    client::Config,
    keys::{key::PrivateKeyWithHashAlg, load_secret_key},
};
use sandhole::{ApplicationConfig, entrypoint};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{sleep, timeout},
};

/// This test ensures that a TCP service can handle multiple big uploads at the
/// same time (mostly for profiling purposes).
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn tcp_multi_stream_download() {
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
        "--allow-requested-ports",
        "--idle-connection-timeout=1s",
        "--authentication-request-timeout=5s",
        "--http-request-timeout=60s",
    ]);
    tokio::spawn(async move { entrypoint(config).await });
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
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
        None,
    )
    .expect("Missing file key1");
    let ssh_client = SshClient;
    let mut session = russh::client::connect(
        Arc::new(Config {
            preferred: Preferred {
                cipher: std::borrow::Cow::Borrowed(&[
                    russh::cipher::CHACHA20_POLY1305,
                    // russh::cipher::AES_256_GCM,
                ]),
                ..Default::default()
            },
            ..Default::default()
        }),
        "127.0.0.1:18022",
        ssh_client,
    )
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
        .tcpip_forward("localhost", 12345)
        .await
        .expect("tcpip_forward failed");

    // 3. Connect to the TCP port of our proxy with out multiple streams
    let mut data = vec![0u8; 20_000_000];
    rand::rng().fill_bytes(&mut data);
    let data: &'static [u8] = data.leak();
    timeout(Duration::from_secs(30), async move {
        let mut jh_vec = vec![];
        for file_size in [7_500_000, 10_000_000, 15_000_000, 20_000_000] {
            let tcp_stream = TcpStream::connect("127.0.0.1:12345")
                .await
                .expect("TCP connection failed");
            let (mut read_half, mut write_half) = tcp_stream.into_split();
            tokio::spawn(async move {
                write_half.write_all(&data[..file_size]).await.unwrap();
            });
            let jh = tokio::spawn(async move {
                let mut buf = [0u8; size_of::<usize>()];
                let mut curr_len = 0;
                loop {
                    curr_len = read_half.read(&mut buf[curr_len..]).await.unwrap();
                    if curr_len == size_of::<usize>() {
                        let curr_size = usize::from_le_bytes(*&buf);
                        if curr_size == file_size {
                            break;
                        }
                        curr_len = 0;
                    }
                }
            });
            jh_vec.push(jh);
        }
        for jh in jh_vec.into_iter() {
            jh.await.expect("Join handle panicked");
        }
    })
    .await
    .expect("Timeout waiting for test to finish.");
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
            let mut size = 0usize;
            while let Some(ChannelMsg::Data { data }) = channel.wait().await {
                size += data.len();
                channel.data(&size.to_le_bytes()[..]).await.unwrap();
            }
            channel.close().await.unwrap();
        });
        Ok(())
    }
}
