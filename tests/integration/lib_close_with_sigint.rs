#![cfg(unix)]

use std::time::Duration;

use clap::Parser;
use nix::libc::{SIGINT, pthread_kill};
use sandhole::{ApplicationConfig, entrypoint};
use std::os::unix::thread::JoinHandleExt;
use tokio::runtime::Handle;
use tokio::task::spawn_blocking;
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};

/// This test ensures that Sandhole properly shuts down when receiving a SIGINT
/// or SIGTERM on Unix.
#[cfg(unix)]
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn lib_close_with_sigint() {
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
        "--tcp-connection-timeout=500ms",
    ]);
    let rt = Handle::current();
    let jh = std::thread::spawn(move || rt.block_on(async { entrypoint(config).await }));
    if timeout(Duration::from_secs(5), async {
        while TcpStream::connect("127.0.0.1:18022").await.is_err() {
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .is_err()
    {
        jh.join().unwrap().unwrap();
        panic!("Timeout waiting for Sandhole to start.")
    };

    // 2. Shutdown Sandhole with signal
    let pthread = jh.as_pthread_t();
    spawn_blocking(move || unsafe { pthread_kill(pthread, SIGINT) });
    assert!(jh.join().is_ok(), "signal wasn't captured successfully");
}
