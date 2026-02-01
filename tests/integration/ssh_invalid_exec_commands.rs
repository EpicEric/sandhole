use std::{sync::Arc, time::Duration};

use clap::Parser;
use russh::keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use russh::{ChannelId, client};
use sandhole::{ApplicationConfig, entrypoint};
use tokio::sync::mpsc;
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};

use crate::common::SandholeHandle;

/// This test ensures that invalid exec options or combinations result in
/// disconnection errors.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn ssh_invalid_exec_commands() {
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
        "--idle-connection-timeout=2s",
        "--authentication-request-timeout=5s",
        "--http-request-timeout=5s",
        "--pool-size=64",
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

    // 2. Start SSH user client that will fail to run user commands
    for invalid_exec in [
        // Admin console as non-admin
        vec!["admin"],
        // No fingerprints
        vec!["allowed-fingerprints="],
        // Invalid fingerprints
        vec!["allowed-fingerprints=SHA256:blah"],
        // Fingerprints incompatible with SNI proxy
        vec![
            "sni-proxy",
            "allowed-fingerprints=SHA256:GehKyA21BBK6eJCouziacUmqYDNl8BPMGG0CTtLSrbQ",
        ],
        // `allowed-fingerprints` twice
        vec![
            "allowed-fingerprints=SHA256:GehKyA21BBK6eJCouziacUmqYDNl8BPMGG0CTtLSrbQ allowed-fingerprints=SHA256:bwf4FDtNeZzFv8xHBzHJwRpDRxssCll8w2tCHFC9n1o",
        ],
        vec![
            "allowed-fingerprints=SHA256:GehKyA21BBK6eJCouziacUmqYDNl8BPMGG0CTtLSrbQ",
            "allowed-fingerprints=SHA256:bwf4FDtNeZzFv8xHBzHJwRpDRxssCll8w2tCHFC9n1o",
        ],
        // TCP alias incompatible with SNI proxy
        vec!["sni-proxy", "tcp-alias"],
        // `tcp-alias` twice
        vec!["tcp-alias tcp-alias"],
        vec!["tcp-alias", "tcp-alias"],
        // `force-https` twice
        vec!["force-https force-https"],
        vec!["force-https", "force-https"],
        // `http2` twice
        vec!["http2 http2"],
        vec!["http2", "http2"],
        // SNI proxy incompatible with TCP alias
        vec!["tcp-alias", "sni-proxy"],
        // `sni-proxy` twice
        vec!["sni-proxy sni-proxy"],
        vec!["sni-proxy", "sni-proxy"],
        // Invalid CIDR in IP allowlist
        vec!["ip-allowlist=10.0.0"],
        // No CIDRs in IP allowlist
        vec!["ip-allowlist="],
        // `ip-allowlist` twice
        vec!["ip-allowlist=192.168.0.0/16 ip-allowlist=dead:beef::/32"],
        vec!["ip-allowlist=192.168.0.0/16", "ip-allowlist=dead:beef::/32"],
        // Invalid CIDR in IP blocklist
        vec!["ip-blocklist=10.0.0"],
        // No CIDRs in IP blocklist
        vec!["ip-blocklist="],
        // `ip-blocklist` twice
        vec!["ip-blocklist=192.168.0.0/16 ip-blocklist=dead:beef::/32"],
        vec!["ip-blocklist=192.168.0.0/16", "ip-blocklist=dead:beef::/32"],
        // Invalid `host`
        vec!["host=?/:"],
        // No `host`
        vec!["host="],
        // `host` twice
        vec!["host=hello.world host=goodbye.world"],
        vec!["host=hello.world", "host=goodbye.world"],
        // Invalid `pool`
        vec!["pool=hello"],
        // No `pool`
        vec!["pool="],
        // `pool` greater than the default
        vec!["pool=65"],
        // `pool` twice
        vec!["pool=10 pool=10"],
        vec!["pool=10", "pool=10"],
        // Unknown command
        vec!["unknown"],
    ] {
        let key = load_secret_key(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
            None,
        )
        .expect("Missing file key1");
        let (tx, mut rx) = mpsc::unbounded_channel();
        let ssh_client = SshClient(tx);
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
        let channel = session
            .channel_open_session()
            .await
            .expect("channel_open_session failed");
        for exec in invalid_exec.clone() {
            channel.exec(true, exec).await.expect("exec failed");
        }
        let Ok(channel_id) =
            timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
        else {
            panic!("Timeout waiting for server to reply.");
        };
        assert_eq!(channel_id, channel.id());
        assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
        assert!(
            timeout(Duration::from_secs(1), session).await.is_ok(),
            "Didn't remove connection after runnning commands: {invalid_exec:?}"
        );
    }

    // 3. Start SSH admin client that will fail to run admin commands
    for invalid_exec in [
        // `admin` twice
        vec!["admin admin"],
        vec!["admin", "admin"],
    ] {
        let key = load_secret_key(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/admin"),
            None,
        )
        .expect("Missing file admin");
        let (tx, mut rx) = mpsc::unbounded_channel();
        let ssh_client = SshClient(tx);
        let mut session = client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
            .await
            .expect("Failed to connect to SSH server");
        assert!(
            session
                .authenticate_publickey(
                    "admin",
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
        let channel = session
            .channel_open_session()
            .await
            .expect("channel_open_session failed");
        for exec in invalid_exec {
            channel.exec(true, exec).await.expect("exec failed");
        }
        let Ok(channel_id) =
            timeout(Duration::from_secs(2), async { rx.recv().await.unwrap() }).await
        else {
            panic!("Timeout waiting for server to reply.");
        };
        assert_eq!(channel_id, channel.id());
        assert!(rx.is_empty(), "rx shouldn't have any remaining messages");
        assert!(timeout(Duration::from_secs(1), session).await.is_ok());
    }
}

struct SshClient(mpsc::UnboundedSender<ChannelId>);

impl client::Handler for SshClient {
    type Error = color_eyre::eyre::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn channel_failure(
        &mut self,
        channel: russh::ChannelId,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.0.send(channel).unwrap();
        Ok(())
    }
}
