use tokio_rustls::LazyConfigAcceptor;

pub(crate) struct TlsPeekData {
    pub(crate) sni: String,
    pub(crate) alpn: Vec<Vec<u8>>,
}

// Get the SNI and ALPN from a peeked ClientHello if it's valid.
pub(crate) async fn peek_sni_and_alpn(buf: &[u8]) -> Option<TlsPeekData> {
    let handshake =
        LazyConfigAcceptor::new(Default::default(), tokio::io::join(buf, tokio::io::empty()))
            .await
            .ok()?;
    let client_hello = handshake.client_hello();
    client_hello.server_name().map(|sni| TlsPeekData {
        sni: sni.to_owned(),
        alpn: client_hello
            .alpn()
            .map(|alpn_iter| alpn_iter.into_iter().map(|alpn| alpn.to_vec()).collect())
            .unwrap_or_default(),
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod peek_sni_and_alpn_tests {
    use std::sync::Arc;

    use rustls_pki_types::pem::PemObject;
    use tokio::io::{AsyncReadExt, duplex};
    use tokio_rustls::TlsConnector;

    use crate::peek_sni_and_alpn;

    #[test_log::test(tokio::test)]
    async fn fails_on_empty_buffer() {
        assert!(peek_sni_and_alpn(b"").await.is_none());
    }

    #[test_log::test(tokio::test)]
    async fn fails_on_plain_message() {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_parsable_certificates(
            rustls_pki_types::CertificateDer::pem_file_iter(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/data/ca/rootCA.pem"
            ))
            .and_then(|iter| iter.collect::<Result<Vec<_>, _>>())
            .expect("Failed to parse client certificates"),
        );
        let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
        client_config.enable_sni = false;
        let connector = TlsConnector::from(Arc::new(client_config));
        let (mut server, client) = duplex(4096);
        let jh = tokio::spawn(async move {
            connector
                .connect("plain.msg".try_into().unwrap(), client)
                .await
        });
        let mut buf = [0u8; 4096];
        let size = server
            .read(&mut buf)
            .await
            .expect("Failed to read from duplex stream");
        jh.abort();
        let peek_data = peek_sni_and_alpn(&buf[..size]).await;
        assert!(peek_data.is_none());
    }

    #[test_log::test(tokio::test)]
    async fn fails_on_missing_sni() {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_parsable_certificates(
            rustls_pki_types::CertificateDer::pem_file_iter(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/data/ca/rootCA.pem"
            ))
            .and_then(|iter| iter.collect::<Result<Vec<_>, _>>())
            .expect("Failed to parse client certificates"),
        );
        let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
        client_config.enable_sni = false;
        client_config.alpn_protocols.push(b"useless-alpn".to_vec());
        let connector = TlsConnector::from(Arc::new(client_config));
        let (mut server, client) = duplex(4096);
        let jh = tokio::spawn(async move {
            connector
                .connect("sni.was.disabled".try_into().unwrap(), client)
                .await
        });
        let mut buf = [0u8; 4096];
        let size = server
            .read(&mut buf)
            .await
            .expect("Failed to read from duplex stream");
        jh.abort();
        let peek_data = peek_sni_and_alpn(&buf[..size]).await;
        assert!(peek_data.is_none());
    }

    #[test_log::test(tokio::test)]
    async fn returns_sni_data() {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_parsable_certificates(
            rustls_pki_types::CertificateDer::pem_file_iter(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/data/ca/rootCA.pem"
            ))
            .and_then(|iter| iter.collect::<Result<Vec<_>, _>>())
            .expect("Failed to parse client certificates"),
        );
        let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let (mut server, client) = duplex(4096);
        let jh = tokio::spawn(async move {
            connector
                .connect("sandhole.com.br".try_into().unwrap(), client)
                .await
        });
        let mut buf = [0u8; 4096];
        let size = server
            .read(&mut buf)
            .await
            .expect("Failed to read from duplex stream");
        jh.abort();
        let peek_data = peek_sni_and_alpn(&buf[..size]).await;
        assert!(peek_data.is_some());
        let peek_data = peek_data.unwrap();
        assert_eq!(peek_data.sni, "sandhole.com.br");
        assert_eq!(peek_data.alpn, Vec::<Vec<u8>>::new());
    }

    #[test_log::test(tokio::test)]
    async fn returns_sni_and_alpn_data() {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_parsable_certificates(
            rustls_pki_types::CertificateDer::pem_file_iter(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/data/ca/rootCA.pem"
            ))
            .and_then(|iter| iter.collect::<Result<Vec<_>, _>>())
            .expect("Failed to parse client certificates"),
        );
        let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
        client_config.alpn_protocols.push(b"example-alpn".to_vec());
        let connector = TlsConnector::from(Arc::new(client_config));
        let (mut server, client) = duplex(4096);
        let jh = tokio::spawn(async move {
            connector
                .connect("foobar.tld".try_into().unwrap(), client)
                .await
        });
        let mut buf = [0u8; 4096];
        let size = server
            .read(&mut buf)
            .await
            .expect("Failed to read from duplex stream");
        jh.abort();
        let peek_data = peek_sni_and_alpn(&buf[..size]).await;
        assert!(peek_data.is_some());
        let peek_data = peek_data.unwrap();
        assert_eq!(peek_data.sni, "foobar.tld");
        assert_eq!(peek_data.alpn, vec![b"example-alpn".to_vec()]);
    }
}
