use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use russh::{
    client::{Msg, Session},
    Channel,
};
use russh_keys::{key::PrivateKeyWithHashAlg, load_secret_key};
use sandhole::{entrypoint, ApplicationConfig, BindHostnames, LoadBalancing};
use tokio::{
    io::AsyncReadExt,
    net::TcpStream,
    time::{sleep, timeout},
};

#[tokio::test(flavor = "multi_thread")]
async fn tcp_bind_random_ports() {
    // 1. Initialize Sandhole
    let config = ApplicationConfig {
        domain: "foobar.tld".into(),
        domain_redirect: "https://tokio.rs/".into(),
        user_keys_directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/user_keys").into(),
        admin_keys_directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/admin_keys").into(),
        certificates_directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/certificates")
            .into(),
        private_key_file: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/server_keys/ssh").into(),
        disable_directory_creation: true,
        listen_address: "127.0.0.1".into(),
        password_authentication_url: None,
        ssh_port: 18022,
        http_port: 18080,
        https_port: 18443,
        connect_ssh_on_https_port: false,
        force_https: false,
        disable_http_logs: false,
        disable_tcp_logs: false,
        acme_contact_email: None,
        acme_cache_directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/acme_cache").into(),
        acme_use_staging: true,
        bind_hostnames: BindHostnames::None,
        load_balancing: LoadBalancing::Allow,
        allow_requested_subdomains: false,
        allow_requested_ports: false,
        quota_per_user: None,
        random_subdomain_seed: None,
        txt_record_prefix: "_sandhole".into(),
        idle_connection_timeout: Duration::from_secs(1),
        authentication_request_timeout: Duration::from_secs(5),
        http_request_timeout: Duration::from_secs(5),
        tcp_connection_timeout: None,
    };
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
    let mut session = russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(
        session
            .authenticate_publickey(
                "user",
                PrivateKeyWithHashAlg::new(Arc::new(key), None).unwrap()
            )
            .await
            .expect("SSH authentication failed"),
        "authentication didn't succeed"
    );
    let mut channel = session
        .channel_open_session()
        .await
        .expect("channel_open_session failed");
    session
        .tcpip_forward("", 12345)
        .await
        .expect("tcpip_forward failed");
    let regex = regex::Regex::new(r"foobar.tld:(\d+)").unwrap();
    let Ok(port) = timeout(Duration::from_secs(3), async move {
        while let Some(message) = channel.wait().await {
            match message {
                russh::ChannelMsg::Data { data } => {
                    let data =
                        String::from_utf8(data.to_vec()).expect("Invalid UTF-8 from message");
                    if let Some(captures) = regex.captures(&data) {
                        let port = captures.get(1).unwrap().as_str().to_string();
                        return port;
                    }
                }
                message => panic!("Unexpected message {:?}", message),
            }
        }
        panic!("Unexpected end of channel");
    })
    .await
    else {
        panic!("Timed out waiting for port allocation.");
    };
    assert!(
        port.parse::<u16>().expect("should be a valid port number") >= 1024,
        "random port must be greater than or equal to 1024"
    );

    // 3. Connect to the TCP port of our proxy
    let mut tcp_stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("TCP connection failed");
    let mut buf = String::with_capacity(13);
    tcp_stream.read_to_string(&mut buf).await.unwrap();
    assert_eq!(buf, "Hello, world!");
}

struct SshClient;

#[async_trait]
impl russh::client::Handler for SshClient {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, _key: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
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
        channel.data(&b"Hello, world!"[..]).await.unwrap();
        channel.eof().await.unwrap();
        Ok(())
    }
}
