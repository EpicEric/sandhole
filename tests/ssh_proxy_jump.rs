use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use clap::Parser;
use rand::rngs::OsRng;
use russh::{
    client::{self, Msg},
    server::{self, Auth, Server},
    Channel, MethodSet,
};
use russh::{
    keys::{key::PrivateKeyWithHashAlg, load_secret_key},
    MethodKind,
};
use sandhole::{entrypoint, ApplicationConfig};
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};

#[tokio::test(flavor = "multi_thread")]
async fn ssh_proxy_jump() {
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

    // 2. Start SSH client that will be proxied via HTTPS
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
        None,
    )
    .expect("Missing file key1");
    let ssh_client = SshClient { server: Honeypot };
    let mut session_one = client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
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
        .tcpip_forward("test.foobar.tld", 22)
        .await
        .expect("tcpip_forward failed");

    // 3. Connect to the SSH port of our proxy with anonymous user
    let key = russh::keys::PrivateKey::random(&mut OsRng, russh::keys::Algorithm::Ed25519).unwrap();
    let ssh_client = ProxyClient;
    let mut session_two = client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(
        session_two
            .authenticate_publickey(
                "user1",
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
    let channel = session_two
        .channel_open_direct_tcpip("test.foobar.tld", 18022, "::1", 12345)
        .await
        .expect("Local forwarding failed");
    let fake_socket = channel.into_stream();
    let new_ssh_client = ProxyClient;
    let mut proxy_session = client::connect_stream(Default::default(), fake_socket, new_ssh_client)
        .await
        .expect("Failed to connect to proxied SSH server");
    assert!(
        proxy_session
            .authenticate_password("user", "password")
            .await
            .expect("Proxy SSH authentication failed")
            .success(),
        "authentication didn't succeed"
    );
    let mut session_channel = proxy_session
        .channel_open_session()
        .await
        .expect("Failed to open session to proxied SSH server");
    if timeout(Duration::from_secs(5), async {
        match session_channel.wait().await.unwrap() {
            russh::ChannelMsg::Data { data } => {
                assert_eq!(data.to_vec(), b"Hello, world!");
            }
            msg => panic!("Unexpected message {:?}", msg),
        }
    })
    .await
    .is_err()
    {
        panic!("Timeout waiting for proxy server to reply.")
    };

    // 3. Connect to the SSH port of our proxy with known user
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key2"),
        None,
    )
    .expect("Missing file key2");
    let ssh_client = ProxyClient;
    let mut session_two = client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(
        session_two
            .authenticate_publickey(
                "user2",
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
    let channel = session_two
        .channel_open_direct_tcpip("test.foobar.tld", 18022, "::1", 12345)
        .await
        .expect("Local forwarding failed");
    let fake_socket = channel.into_stream();
    let new_ssh_client = ProxyClient;
    let mut proxy_session = client::connect_stream(Default::default(), fake_socket, new_ssh_client)
        .await
        .expect("Failed to connect to proxied SSH server");
    assert!(
        proxy_session
            .authenticate_password("user", "password")
            .await
            .expect("Proxy SSH authentication failed")
            .success(),
        "authentication didn't succeed"
    );
    let mut session_channel = proxy_session
        .channel_open_session()
        .await
        .expect("Failed to open session to proxied SSH server");
    if timeout(Duration::from_secs(5), async {
        match session_channel.wait().await.unwrap() {
            russh::ChannelMsg::Data { data } => {
                assert_eq!(data.to_vec(), b"Hello, world!");
            }
            msg => panic!("Unexpected message {:?}", msg),
        }
    })
    .await
    .is_err()
    {
        panic!("Timeout waiting for proxy server to reply.")
    };

    // 5. Attempt to close SSH aliasing
    session_one
        .cancel_tcpip_forward("test.foobar.tld", 22)
        .await
        .expect("cancel_tcpip_forward failed");
}

struct SshClient {
    server: Honeypot,
}

impl client::Handler for SshClient {
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
        connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let handler = self.server.new_client(
            IpAddr::from_str(connected_address)
                .ok()
                .map(|addr| SocketAddr::new(addr, connected_port as u16)),
        );
        let stream = channel.into_stream();
        tokio::spawn(async move {
            let session = match server::run_stream(
                Arc::new(server::Config {
                    keys: vec![russh::keys::PrivateKey::random(
                        &mut OsRng,
                        russh::keys::Algorithm::Ed25519,
                    )
                    .unwrap()],
                    ..Default::default()
                }),
                stream,
                handler,
            )
            .await
            {
                Ok(session) => session,
                Err(_) => {
                    // Connection setup failed
                    return;
                }
            };
            match session.await {
                Ok(_) => (),
                Err(_) => {
                    // Connection closed with error
                }
            }
        });
        Ok(())
    }
}

struct Honeypot;

impl server::Server for Honeypot {
    type Handler = HoneypotHandler;

    fn new_client(&mut self, _peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        HoneypotHandler
    }
}

struct HoneypotHandler;

impl server::Handler for HoneypotHandler {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::from([MethodKind::Password].as_slice())),
        })
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if user == "user" && password == "password" {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::Reject {
                proceed_with_methods: None,
            })
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<server::Msg>,
        _session: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        let _ = channel.data(&b"Hello, world!"[..]).await;
        let _ = channel.eof().await;
        Ok(true)
    }
}

struct ProxyClient;

impl client::Handler for ProxyClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let handler = Honeypot.new_client(
            IpAddr::from_str(connected_address)
                .ok()
                .map(|addr| SocketAddr::new(addr, connected_port as u16)),
        );
        let stream = channel.into_stream();
        tokio::spawn(async move {
            let session = match server::run_stream(Default::default(), stream, handler).await {
                Ok(session) => session,
                Err(_) => {
                    // Connection setup failed
                    return;
                }
            };
            match session.await {
                Ok(_) => (),
                Err(_) => {
                    // Connection closed with error
                }
            }
        });
        Ok(())
    }
}
