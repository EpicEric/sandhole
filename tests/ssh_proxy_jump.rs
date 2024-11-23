use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use russh::{
    client::{self, Msg},
    server::{self, Auth, Server},
    Channel, MethodSet,
};
use russh_keys::{key, load_secret_key};
use sandhole::{
    config::{ApplicationConfig, BindHostnames},
    entrypoint,
};
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};

#[tokio::test(flavor = "multi_thread")]
async fn ssh_proxy_jump() {
    // 1. Initialize Sandhole
    let config = ApplicationConfig {
        domain: "foobar.tld".into(),
        domain_redirect: "https://tokio.rs/".into(),
        user_keys_directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/user_keys").into(),
        admin_keys_directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/admin_keys").into(),
        password_authentication_url: None,
        certificates_directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/certificates")
            .into(),
        private_key_file: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/server_keys/ssh").into(),
        disable_directory_creation: true,
        listen_address: "127.0.0.1".into(),
        ssh_port: 18022,
        http_port: 18080,
        https_port: 18443,
        force_https: false,
        acme_contact_email: None,
        acme_cache_directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/acme_cache").into(),
        acme_use_staging: true,
        bind_hostnames: BindHostnames::All,
        allow_provided_subdomains: false,
        allow_requested_ports: false,
        random_subdomain_seed: None,
        txt_record_prefix: "_sandhole".into(),
        idle_connection_timeout: Duration::from_secs(2),
        authentication_request_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(5),
    };
    tokio::spawn(async move { entrypoint(config).await });
    if let Err(_) = timeout(Duration::from_secs(5), async {
        while let Err(_) = TcpStream::connect("127.0.0.1:18022").await {
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
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
    let mut session = client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(session
        .authenticate_publickey("user", Arc::new(key))
        .await
        .expect("SSH authentication failed"));
    session
        .tcpip_forward("test.foobar.tld", 22)
        .await
        .expect("tcpip_forward failed");

    // 3. Connect to the SSH port of our proxy
    let key = russh_keys::key::KeyPair::generate_ed25519();
    let ssh_client = ProxyClient;
    let mut session = client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(session
        .authenticate_publickey("user", Arc::new(key))
        .await
        .expect("SSH authentication failed"));
    let channel = session
        .channel_open_direct_tcpip("test.foobar.tld", 18022, "::1", 12345)
        .await
        .expect("Local forwarding failed");
    let fake_socket = channel.into_stream();
    let new_ssh_client = ProxyClient;
    let mut proxy_session = client::connect_stream(Default::default(), fake_socket, new_ssh_client)
        .await
        .expect("Failed to connect to proxied SSH server");
    assert!(proxy_session
        .authenticate_password("user", "password")
        .await
        .expect("Proxy SSH authentication failed"));
    let mut session_channel = proxy_session
        .channel_open_session()
        .await
        .expect("Failed to open session to proxied SSH server");
    if let Err(_) = timeout(Duration::from_secs(5), async {
        match session_channel.wait().await.unwrap() {
            russh::ChannelMsg::Data { data } => {
                assert_eq!(String::from_utf8(data.to_vec()).unwrap(), "Hello, world!");
            }
            msg => panic!("Unexpected message {:?}", msg),
        }
    })
    .await
    {
        panic!("Timeout waiting for proxy server to reply.")
    };
}

struct SshClient {
    server: Honeypot,
}

#[async_trait]
impl client::Handler for SshClient {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, _key: &key::PublicKey) -> Result<bool, Self::Error> {
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
                    keys: vec![russh_keys::key::KeyPair::generate_ed25519()],
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
                    return;
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

#[async_trait]
impl server::Handler for HoneypotHandler {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: &key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::PASSWORD),
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

#[async_trait]
impl client::Handler for ProxyClient {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &key::PublicKey) -> Result<bool, Self::Error> {
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
                    return;
                }
            }
        });
        Ok(())
    }
}
