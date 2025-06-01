use rustls::internal::msgs::{
    codec::{Codec, Reader},
    handshake::{ClientExtension, HandshakePayload},
    message::{Message, MessagePayload, OutboundOpaqueMessage},
};

pub(crate) struct TlsPeekData {
    pub(crate) sni: String,
    pub(crate) alpn: Vec<Vec<u8>>,
}

// Get the SNI and ALPN from a peeked ClientHello if it's valid.
pub(crate) fn peek_sni_and_alpn(buf: &[u8]) -> Option<TlsPeekData> {
    let opaque_message = OutboundOpaqueMessage::read(&mut Reader::init(buf)).ok()?;
    let message = Message::try_from(opaque_message.into_plain_message()).ok()?;
    if let MessagePayload::Handshake { parsed, .. } = &message.payload {
        if let HandshakePayload::ClientHello(client_hello) = &parsed.payload {
            let mut sni = None;
            let mut alpn = vec![];
            for extension in client_hello.extensions.iter() {
                match extension {
                    ClientExtension::ServerName(ext) => {
                        sni = ext.first().and_then(|name| {
                            // Do some freaky encoding stuff just to read the server name indicator
                            let mut buffer = vec![];
                            name.encode(&mut buffer);
                            let end =
                                (<u16>::read(&mut Reader::init(&buffer[1..3])).ok()? + 3) as usize;
                            if buffer.len() != end {
                                return None;
                            }
                            String::from_utf8(buffer[3..end].to_vec()).ok()
                        })
                    }
                    ClientExtension::Protocols(ext) => {
                        alpn = ext.iter().map(|name| name.as_ref().to_vec()).collect()
                    }
                    _ => {}
                }
            }
            return sni.map(|sni| TlsPeekData { sni, alpn });
        }
    }
    None
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod peek_sni_and_alpn_tests {
    use std::sync::Arc;

    use rustls_pki_types::pem::PemObject;
    use tokio::io::{AsyncReadExt, duplex};
    use tokio_rustls::TlsConnector;

    use crate::peek_sni_and_alpn;

    #[test]
    fn fails_on_empty_buffer() {
        assert!(peek_sni_and_alpn(b"").is_none());
    }

    #[tokio::test]
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
        let peek_data = peek_sni_and_alpn(&buf[..size]);
        assert!(peek_data.is_none());
    }

    #[tokio::test]
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
        let peek_data = peek_sni_and_alpn(&buf[..size]);
        assert!(peek_data.is_some());
        let peek_data = peek_data.unwrap();
        assert_eq!(peek_data.sni, "sandhole.com.br");
        assert_eq!(peek_data.alpn, Vec::<Vec<u8>>::new());
    }

    #[tokio::test]
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
        let peek_data = peek_sni_and_alpn(&buf[..size]);
        assert!(peek_data.is_some());
        let peek_data = peek_data.unwrap();
        assert_eq!(peek_data.sni, "foobar.tld");
        assert_eq!(peek_data.alpn, vec![b"example-alpn".to_vec()]);
    }
}
