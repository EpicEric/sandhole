use std::{sync::Arc, time::Duration};

use clap::Parser;
use russh::keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use russh::{
    Channel,
    client::{Msg, Session},
};
use sandhole::{ApplicationConfig, entrypoint};
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};

use crate::common::SandholeHandle;

/// This test ensures that `--load-balancing=deny` prevents more than one
/// service from remote forwarding to the same hosts/ports/aliases.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn connection_deny_load_balancing() {
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
        "--load-balancing=deny",
        "--allow-requested-subdomains",
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

    // 2. Start SSH clients that will take resources
    let key_1 = Arc::new(
        load_secret_key(
            std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
                .join("tests/data/private_keys/key1"),
            None,
        )
        .expect("Missing file key1"),
    );
    let ssh_client_a = SshClient;
    let mut session_a = russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client_a)
        .await
        .expect("Failed to connect to SSH server");
    assert!(
        session_a
            .authenticate_publickey(
                "user-a",
                PrivateKeyWithHashAlg::new(
                    Arc::clone(&key_1),
                    session_a.best_supported_rsa_hash().await.unwrap().flatten()
                )
            )
            .await
            .expect("SSH authentication failed")
            .success(),
        "authentication didn't succeed"
    );
    session_a
        .tcpip_forward("http.foobar.tld", 80)
        .await
        .expect("tcpip_forward failed");
    session_a
        .tcpip_forward("ssh.foobar.tld", 22)
        .await
        .expect("tcpip_forward failed");
    session_a
        .tcpip_forward("localhost", 12345)
        .await
        .expect("tcpip_forward failed");
    session_a
        .tcpip_forward("alias.foobar.tld", 42)
        .await
        .expect("tcpip_forward failed");
    let ssh_client_b = SshClient;
    let mut session_b = russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client_b)
        .await
        .expect("Failed to connect to SSH server");
    assert!(
        session_b
            .authenticate_publickey(
                "user-b",
                PrivateKeyWithHashAlg::new(
                    Arc::clone(&key_1),
                    session_b.best_supported_rsa_hash().await.unwrap().flatten()
                )
            )
            .await
            .expect("SSH authentication failed")
            .success(),
        "authentication didn't succeed"
    );
    let channel_b = session_b
        .channel_open_session()
        .await
        .expect("channel_open_session failed");
    channel_b
        .exec(false, "sni-proxy")
        .await
        .expect("exec failed");
    session_b
        .tcpip_forward("sni.foobar.tld", 443)
        .await
        .expect("tcpip_forward failed");
    let ssh_client_c = SshClient;
    let mut session_c = russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client_c)
        .await
        .expect("Failed to connect to SSH server");
    assert!(
        session_c
            .authenticate_publickey(
                "user-b",
                PrivateKeyWithHashAlg::new(
                    Arc::clone(&key_1),
                    session_c.best_supported_rsa_hash().await.unwrap().flatten()
                )
            )
            .await
            .expect("SSH authentication failed")
            .success(),
        "authentication didn't succeed"
    );
    let channel_b = session_c
        .channel_open_session()
        .await
        .expect("channel_open_session failed");
    channel_b
        .exec(false, "tcp-alias")
        .await
        .expect("exec failed");
    session_c
        .tcpip_forward("http-alias.foobar.tld", 80)
        .await
        .expect("tcpip_forward failed");

    // 3. Start SSH client that will be denied forwardings
    let key_2 = Arc::new(
        load_secret_key(
            std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
                .join("tests/data/private_keys/key2"),
            None,
        )
        .expect("Missing file key2"),
    );
    let ssh_client_fail = SshClient;
    let mut session_fail =
        russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client_fail)
            .await
            .expect("Failed to connect to SSH server");
    assert!(
        session_fail
            .authenticate_publickey(
                "user",
                PrivateKeyWithHashAlg::new(
                    Arc::clone(&key_2),
                    session_fail
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
    let channel_fail = session_fail
        .channel_open_session()
        .await
        .expect("channel_open_session failed");
    assert!(
        session_fail
            .tcpip_forward("http.foobar.tld", 80)
            .await
            .is_err(),
        "tcpip_forward should've failed for HTTP"
    );
    assert!(
        session_fail
            .tcpip_forward("ssh.foobar.tld", 22)
            .await
            .is_err(),
        "tcpip_forward should've failed for SSH"
    );
    assert!(
        session_fail
            .tcpip_forward("localhost", 12345)
            .await
            .is_err(),
        "tcpip_forward should've failed for TCP"
    );
    assert!(
        session_fail
            .tcpip_forward("alias.foobar.tld", 42)
            .await
            .is_err(),
        "tcpip_forward should've failed for alias"
    );
    channel_fail
        .exec(false, "tcp-alias")
        .await
        .expect("exec failed");
    sleep(Duration::from_millis(200)).await;
    assert!(
        session_fail
            .tcpip_forward("http-alias.foobar.tld", 80)
            .await
            .is_err(),
        "tcpip_forward should've failed for HTTP alias"
    );
    let ssh_client_fail = SshClient;
    let mut session_fail =
        russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client_fail)
            .await
            .expect("Failed to connect to SSH server");
    assert!(
        session_fail
            .authenticate_publickey(
                "user",
                PrivateKeyWithHashAlg::new(
                    Arc::clone(&key_2),
                    session_fail
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
    let channel_fail = session_fail
        .channel_open_session()
        .await
        .expect("channel_open_session failed");
    channel_fail
        .exec(false, "sni-proxy")
        .await
        .expect("exec failed");
    sleep(Duration::from_millis(200)).await;
    assert!(
        session_fail
            .tcpip_forward("sni.foobar.tld", 443)
            .await
            .is_err(),
        "tcpip_forward should've failed for SNI proxy"
    );
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
            channel.data(&b"Data"[..]).await.unwrap();
            channel.eof().await.unwrap();
        });
        Ok(())
    }
}
