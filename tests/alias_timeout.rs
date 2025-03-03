use std::{sync::Arc, time::Duration};

use clap::Parser;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use russh::{
    client::{Msg, Session},
    keys::{key::PrivateKeyWithHashAlg, load_secret_key, ssh_key::private::Ed25519Keypair},
    Channel,
};
use sandhole::{entrypoint, ApplicationConfig};
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};

#[tokio::test(flavor = "multi_thread")]
async fn alias_timeout() {
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
        "--idle-connection-timeout=500ms",
        "--http-request-timeout=500ms",
        "--tcp-connection-timeout=500ms",
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
    let mut proxy_session =
        russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
            .await
            .expect("Failed to connect to SSH server");
    assert!(
        proxy_session
            .authenticate_publickey(
                "user",
                PrivateKeyWithHashAlg::new(
                    Arc::new(key),
                    proxy_session
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
    proxy_session
        .tcpip_forward("ssh.tunnel", 22)
        .await
        .expect("tcpip_forward failed");
    proxy_session
        .tcpip_forward("http.foobar.tld", 80)
        .await
        .expect("tcpip_forward failed");
    proxy_session
        .tcpip_forward("alias.tunnel", 12345)
        .await
        .expect("tcpip_forward failed");
    proxy_session
        .tcpip_forward("", 23456)
        .await
        .expect("tcpip_forward failed");

    // 3. Start anonymous SSH client that will forward the proxies via aliasing
    let key = russh::keys::PrivateKey::from(Ed25519Keypair::from_seed(
        &ChaCha20Rng::try_from_os_rng().unwrap().random(),
    ));
    let ssh_client = SshClient;
    let mut client_session =
        russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
            .await
            .expect("Failed to connect to SSH server");
    assert!(
        client_session
            .authenticate_publickey(
                "user",
                PrivateKeyWithHashAlg::new(
                    Arc::new(key),
                    client_session
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
    let ssh_channel = client_session
        .channel_open_direct_tcpip("ssh.tunnel", 18022, "::1", 1234)
        .await
        .expect("ssh.tunnel forwarding failed");
    let http_channel = client_session
        .channel_open_direct_tcpip("http.foobar.tld", 18080, "::1", 2345)
        .await
        .expect("http.foobar.tld forwarding failed");
    let alias_channel = client_session
        .channel_open_direct_tcpip("alias.tunnel", 12345, "::1", 3456)
        .await
        .expect("alias.tunnel forwarding failed");
    let tcp_channel = client_session
        .channel_open_direct_tcpip("localhost", 23456, "::1", 4567)
        .await
        .expect("TCP forwarding failed");
    let Ok(()) = timeout(Duration::from_secs(3), async {
        for mut channel in [ssh_channel, alias_channel, tcp_channel] {
            assert!(
                channel.wait().await.is_none(),
                "channel should've been closed"
            );
        }
        http_channel
            .data(&b"GET / HTTP/1.0\r\nHost: http.foobar.tld\r\n\r\n"[..])
            .await
            .expect("blah");
    })
    .await
    else {
        panic!("Timeout waiting for channels to reply.");
    };
    assert!(
        !client_session.is_closed(),
        "session shouldn't have been closed yet"
    );
    sleep(Duration::from_secs(2)).await;
    assert!(client_session.is_closed(), "session should've been closed");

    // 3. Start authenticated SSH client that will forward the proxies via aliasing
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key2"),
        None,
    )
    .expect("Missing file key2");
    let ssh_client = SshClient;
    let mut client_session =
        russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
            .await
            .expect("Failed to connect to SSH server");
    assert!(
        client_session
            .authenticate_publickey(
                "user",
                PrivateKeyWithHashAlg::new(
                    Arc::new(key),
                    client_session
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
    let ssh_channel = client_session
        .channel_open_direct_tcpip("ssh.tunnel", 18022, "::1", 1234)
        .await
        .expect("ssh.tunnel forwarding failed");
    let http_channel = client_session
        .channel_open_direct_tcpip("http.foobar.tld", 18080, "::1", 2345)
        .await
        .expect("http.foobar.tld forwarding failed");
    let alias_channel = client_session
        .channel_open_direct_tcpip("alias.tunnel", 12345, "::1", 3456)
        .await
        .expect("alias.tunnel forwarding failed");
    let tcp_channel = client_session
        .channel_open_direct_tcpip("localhost", 23456, "::1", 4567)
        .await
        .expect("TCP forwarding failed");
    let Ok(()) = timeout(Duration::from_secs(3), async {
        for mut channel in [ssh_channel, alias_channel, tcp_channel] {
            assert!(
                channel.wait().await.is_none(),
                "channel should've been closed"
            );
        }
        http_channel
            .data(&b"GET / HTTP/1.0\r\nHost: http.foobar.tld\r\n\r\n"[..])
            .await
            .expect("blah");
    })
    .await
    else {
        panic!("Timeout waiting for channels to reply.");
    };
    assert!(
        !client_session.is_closed(),
        "session shouldn't have been closed"
    );
    sleep(Duration::from_secs(2)).await;
    assert!(
        !client_session.is_closed(),
        "session shouldn't have been closed"
    );
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
            sleep(Duration::from_secs(5)).await;
            channel.data(&b"Hello, world!\n"[..]).await.unwrap();
            channel.eof().await.unwrap();
        });
        Ok(())
    }
}
