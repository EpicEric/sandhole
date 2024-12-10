use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use russh::{
    client::{self, Msg, Session},
    Channel,
};
use russh_keys::load_secret_key;
use sandhole::{
    config::{ApplicationConfig, BindHostnames, LoadBalancing},
    entrypoint,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::{sleep, timeout},
};

#[tokio::test(flavor = "multi_thread")]
async fn admin_interface() {
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
        disable_http_logs: false,
        disable_tcp_logs: false,
        acme_contact_email: None,
        acme_cache_directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/acme_cache").into(),
        acme_use_staging: true,
        bind_hostnames: BindHostnames::All,
        load_balancing: LoadBalancing::Allow,
        allow_provided_subdomains: false,
        allow_requested_ports: true,
        random_subdomain_seed: None,
        txt_record_prefix: "_sandhole".into(),
        idle_connection_timeout: Duration::from_millis(800),
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

    // 2. Start SSH client that will be proxied via alias
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/key1"),
        None,
    )
    .expect("Missing file key1");
    let ssh_client = SshClient;
    let mut session = russh::client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(session
        .authenticate_publickey("user", Arc::new(key))
        .await
        .expect("SSH authentication failed"));
    // NOTE: Due to how simple the test is, there cannot be character collisions between
    // the different hosts/aliases, otherwise Ratatui's diffing optimizes away part of them.
    session
        .tcpip_forward("http.aaa", 443)
        .await
        .expect("tcpip_forward failed");
    session
        .tcpip_forward("ssh.bbb", 22)
        .await
        .expect("tcpip_forward failed");
    session
        .tcpip_forward("proxy.ccc", 12345)
        .await
        .expect("tcpip_forward failed");
    // Required for updating the admin interface data
    sleep(Duration::from_secs(3)).await;

    // 3. Request admin pty
    let key = load_secret_key(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/private_keys/admin"),
        None,
    )
    .expect("Missing file admin");
    let ssh_client = SshClient;
    let mut session = client::connect(Default::default(), "127.0.0.1:18022", ssh_client)
        .await
        .expect("Failed to connect to SSH server");
    assert!(session
        .authenticate_publickey("user", Arc::new(key))
        .await
        .expect("SSH authentication failed"));
    let mut channel = session
        .channel_open_session()
        .await
        .expect("channel_open_session failed");
    channel
        .request_pty(false, "xterm", 40, 30, 640, 480, &[])
        .await
        .expect("request_pty failed");
    channel
        .exec(false, "admin")
        .await
        .expect("exec admin failed");

    // 4. Interact with the admin interface and verify displayed data
    if timeout(Duration::from_secs(3), async move {
        let mut writer = channel.make_writer();
        let reader = BufReader::new(channel.make_reader());
        let mut segments = reader.split(b'\x1b');
        // 4a. Validate header, system information, and HTTP tab data
        let mut search_strings = vec![
            "Sandhole admin",
            "  CPU%  ",
            " Memory ",
            "   TX   ",
            "   RX   ",
            "HTTP services",
            "http.aaa",
        ];
        while let Some(segment) = segments.next_segment().await.unwrap() {
            let segment = String::from_utf8_lossy(&segment);
            let mut remove_index = None;
            for (i, needle) in search_strings.iter().enumerate() {
                if segment.contains(needle) {
                    remove_index = Some(i);
                    break;
                }
            }
            if let Some(i) = remove_index {
                search_strings.remove(i);
                if search_strings.is_empty() {
                    break;
                }
            }
        }
        // 4b. Switch tabs and validate SSH tab data
        writer
            .write(&b"\t"[..])
            .await
            .expect("channel write failed");
        let mut search_strings = vec!["SSH services", "ssh.bbb"];
        while let Some(segment) = segments.next_segment().await.unwrap() {
            let segment = String::from_utf8_lossy(&segment);
            let mut remove_index = None;
            for (i, needle) in search_strings.iter().enumerate() {
                if segment.contains(needle) {
                    remove_index = Some(i);
                    break;
                }
            }
            if let Some(i) = remove_index {
                search_strings.remove(i);
                if search_strings.is_empty() {
                    break;
                }
            }
        }
        // 4c. Switch tabs again and validate TCP tab data
        writer
            .write(&b"\t"[..])
            .await
            .expect("channel write failed");
        let mut search_strings = vec!["TCP services", "proxy.ccc"];
        while let Some(segment) = segments.next_segment().await.unwrap() {
            let segment = String::from_utf8_lossy(&segment);
            let mut remove_index = None;
            for (i, needle) in search_strings.iter().enumerate() {
                if segment.contains(needle) {
                    remove_index = Some(i);
                    break;
                }
            }
            if let Some(i) = remove_index {
                search_strings.remove(i);
                if search_strings.is_empty() {
                    break;
                }
            }
        }
        // 4d. Select line with TCP alias in table by pressing Down
        writer
            .write(&b"\x1b[B"[..])
            .await
            .expect("channel write failed");
        while let Some(segment) = segments.next_segment().await.unwrap() {
            if String::from_utf8_lossy(&segment).contains("proxy.ccc") {
                break;
            }
        }
        // 4e. Go back one tab
        writer
            .write(&b"\x1b[Z"[..])
            .await
            .expect("channel write failed");
        let mut search_strings = vec!["SSH services", "ssh.bbb"];
        while let Some(segment) = segments.next_segment().await.unwrap() {
            let segment = String::from_utf8_lossy(&segment);
            let mut remove_index = None;
            for (i, needle) in search_strings.iter().enumerate() {
                if segment.contains(needle) {
                    remove_index = Some(i);
                    break;
                }
            }
            if let Some(i) = remove_index {
                search_strings.remove(i);
                if search_strings.is_empty() {
                    break;
                }
            }
        }
        // 4f. Quit the admin interface with Ctrl-C (ETX)
        writer
            .write(&b"\x03"[..])
            .await
            .expect("channel write failed");
    })
    .await
    .is_err()
    {
        panic!("Timed out waiting for admin interface.");
    }
    sleep(Duration::from_millis(200)).await;
    assert!(session.is_closed());
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
