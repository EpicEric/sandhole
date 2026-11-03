// sandhole: Expose HTTP/SSH/TCP services through SSH port forwarding
// Copyright (C) 2024-2026 Eric Rodrigues Pires
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for
// more details.
//
// You should have received a copy of the GNU Affero General Public License along
// with this program. If not, see <https://www.gnu.org/licenses/>.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{Router, extract::Request, routing::get};
use clap::Parser;
use http::{StatusCode, header::HOST};
use http_body_util::BodyExt;
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
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
    net::TcpStream,
    time::{sleep, timeout},
};
use tower::Service;

use crate::common::SandholeHandle;

/// This test ensures that pooled HTTP requests don't leave channels open
/// on the SSH session. When a pooled connection is available, sandhole must
/// not open (and abandon) a fresh channel to the target.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn http_pool_leak() {
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
        "--bind-hostnames=all",
        "--idle-connection-timeout=10s",
        "--authentication-request-timeout=5s",
        "--http-request-timeout=10s",
        "--pool-size=8",
        "--pool-timeout=3s",
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
    let open_channels = Arc::new(AtomicUsize::new(0));
    let ssh_client = SshClient(Arc::clone(&open_channels));
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
        .tcpip_forward("test.foobar.tld", 80)
        .await
        .expect("tcpip_forward failed");

    // 3. Send repeated requests, each over its own client connection, so that
    // every request after the first should reuse the pooled target connection
    let request_count = 20;
    for _ in 0..request_count {
        let tcp_stream = TcpStream::connect("127.0.0.1:18080")
            .await
            .expect("TCP connection failed");
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp_stream))
            .await
            .expect("HTTP handshake failed");
        let jh = tokio::spawn(async move {
            let _ = conn.await;
        });
        let request = Request::builder()
            .method("GET")
            .uri("/")
            .header(HOST, "test.foobar.tld")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let response = timeout(Duration::from_secs(10), sender.send_request(request))
            .await
            .expect("Timeout waiting for request to finish.")
            .expect("Error sending HTTP request");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("Error collecting response")
            .to_bytes();
        assert_eq!(body.as_ref(), b"Processed");
        jh.abort();
    }

    // 4. Give any abandoned channel time to be visibly left open
    sleep(Duration::from_secs(1)).await;

    // At most one target channel should be kept alive by the pool.
    let open = open_channels.load(Ordering::SeqCst);
    assert!(
        open <= 2,
        "Expected at most 2 open channels after {request_count} pooled requests, found {open}"
    );
}

struct SshClient(Arc<AtomicUsize>);

impl russh::client::Handler for SshClient {
    type Error = color_eyre::eyre::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKeyOrCertificate,
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
        let open_channels = Arc::clone(&self.0);
        open_channels.fetch_add(1, Ordering::SeqCst);
        let router = Router::new().route("/", get(async || "Processed"));
        let service = service_fn(move |req: Request<Incoming>| router.clone().call(req));
        tokio::spawn(async move {
            let _ = Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(channel.into_stream()), service)
                .await;
            open_channels.fetch_sub(1, Ordering::SeqCst);
        });
        reply.accept().await;
        Ok(())
    }
}
