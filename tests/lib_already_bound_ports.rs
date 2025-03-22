use std::time::Duration;

use clap::Parser;
use sandhole::{ApplicationConfig, entrypoint};
use tokio::{
    net::TcpListener,
    time::{sleep, timeout},
};

#[tokio::test(flavor = "multi_thread")]
async fn lib_already_bound_ports() {
    let _ = env_logger::builder()
        .filter_module("sandhole", log::LevelFilter::Debug)
        .is_test(true)
        .try_init();
    for (i, port) in [18022, 18080, 18443].into_iter().enumerate() {
        if i > 0 {
            sleep(Duration::from_millis(200)).await;
        }
        // 1. Bind the specific port before Sandhole does
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("should be able to bind open port");
        // 2. Fail to initialize Sandhole
        if timeout(Duration::from_secs(2), async {
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
                "--idle-connection-timeout=1s",
                "--authentication-request-timeout=5s",
                "--http-request-timeout=5s",
            ]);
            assert!(
                entrypoint(config).await.is_err(),
                "should've failed to start server"
            )
        })
        .await
        .is_err()
        {
            panic!("Timeout waiting for Sandhole to start.")
        };
        // 3. Unbind the port
        drop(listener);
    }
}
