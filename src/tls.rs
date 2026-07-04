use std::{
    io::Cursor,
    pin::Pin,
    task::{Context, Poll},
};

use rustls::server::Acceptor;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) struct TlsPeekData {
    pub(crate) sni: String,
    pub(crate) alpn: Vec<Vec<u8>>,
}

pub(crate) enum ClientHelloStatus {
    Ready(TlsPeekData),
    Incomplete,
    Invalid(Vec<u8>),
}

// Classify the bytes received since the start of the connection,
// extracting the SNI and ALPN from the ClientHello once it is complete
pub(crate) fn parse_client_hello(buf: &[u8]) -> ClientHelloStatus {
    let mut acceptor = Acceptor::default();
    let mut cursor = Cursor::new(buf);
    loop {
        match acceptor.read_tls(&mut cursor) {
            Ok(0) => break ClientHelloStatus::Incomplete,
            Ok(_) => match acceptor.accept() {
                Ok(Some(accepted)) => {
                    let client_hello = accepted.client_hello();
                    break match client_hello.server_name() {
                        Some(sni) => ClientHelloStatus::Ready(TlsPeekData {
                            sni: sni.to_owned(),
                            alpn: client_hello
                                .alpn()
                                .map(|alpn_iter| {
                                    alpn_iter.into_iter().map(|alpn| alpn.to_vec()).collect()
                                })
                                .unwrap_or_default(),
                        }),
                        None => ClientHelloStatus::Invalid(Vec::new()),
                    };
                }
                Ok(None) => continue,
                Err((_error, mut alert)) => {
                    let mut alert_bytes = Vec::new();
                    while let Ok(n) = alert.write(&mut alert_bytes) {
                        if n == 0 {
                            break;
                        }
                    }
                    break ClientHelloStatus::Invalid(alert_bytes);
                }
            },
            Err(_) => break ClientHelloStatus::Invalid(Vec::new()),
        }
    }
}

// Wraps a stream. On read, replays any bytes that were consumed,
// then yields data from the underlying stream
pub(crate) struct RewindStream<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> RewindStream<S> {
    pub(crate) fn new(prefix: Vec<u8>, inner: S) -> Self {
        RewindStream {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RewindStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.offset < this.prefix.len() {
            let len = (this.prefix.len() - this.offset).min(buf.remaining());
            buf.put_slice(&this.prefix[this.offset..this.offset + len]);
            this.offset += len;
            // Free the replay buffer once drained
            if this.offset == this.prefix.len() {
                this.prefix = Vec::new();
                this.offset = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RewindStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod parse_client_hello_tests {
    use std::{path::PathBuf, sync::Arc};

    use rustls_pki_types::pem::PemObject;
    use tokio::io::{AsyncReadExt, duplex};
    use tokio_rustls::TlsConnector;

    use super::{ClientHelloStatus, parse_client_hello};

    fn root_store() -> rustls::RootCertStore {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_parsable_certificates(
            rustls_pki_types::CertificateDer::pem_file_iter(
                PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("tests/data/ca/rootCA.pem"),
            )
            .and_then(|iter| iter.collect::<Result<Vec<_>, _>>())
            .expect("Failed to parse client certificates"),
        );
        root_store
    }

    fn client_config() -> rustls::ClientConfig {
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store())
        .with_no_client_auth()
    }

    async fn client_hello_bytes(config: rustls::ClientConfig, domain: &'static str) -> Vec<u8> {
        let connector = TlsConnector::from(Arc::new(config));
        let (mut server, client) = duplex(8192);
        let jh =
            tokio::spawn(
                async move { connector.connect(domain.try_into().unwrap(), client).await },
            );
        let mut buf = [0u8; 8192];
        let size = server
            .read(&mut buf)
            .await
            .expect("Failed to read from duplex stream");
        jh.abort();
        buf[..size].to_vec()
    }

    #[test_log::test(tokio::test)]
    async fn empty_buffer_is_incomplete() {
        assert!(matches!(
            parse_client_hello(b""),
            ClientHelloStatus::Incomplete
        ));
    }

    #[test_log::test(tokio::test)]
    async fn truncated_client_hello_is_incomplete() {
        let buf = client_hello_bytes(client_config(), "sandhole.com.br").await;
        for len in [1, 5, buf.len() / 2, buf.len() - 1] {
            assert!(matches!(
                parse_client_hello(&buf[..len]),
                ClientHelloStatus::Incomplete
            ));
        }
    }

    #[test_log::test(tokio::test)]
    async fn fails_on_missing_sni() {
        let mut config = client_config();
        config.enable_sni = false;
        config.alpn_protocols.push(b"useless-alpn".to_vec());
        let buf = client_hello_bytes(config, "sni.was.disabled").await;
        assert!(matches!(
            parse_client_hello(&buf),
            ClientHelloStatus::Invalid(_)
        ));
    }

    #[test_log::test(tokio::test)]
    async fn fails_on_plain_message() {
        assert!(matches!(
            parse_client_hello(b"GET / HTTP/1.1\r\nHost: not.tls\r\n\r\n"),
            ClientHelloStatus::Invalid(_)
        ));
    }

    #[test_log::test(tokio::test)]
    async fn returns_sni_data() {
        let buf = client_hello_bytes(client_config(), "sandhole.com.br").await;
        let ClientHelloStatus::Ready(peek_data) = parse_client_hello(&buf) else {
            panic!("Expected complete ClientHello");
        };
        assert_eq!(peek_data.sni, "sandhole.com.br");
        assert_eq!(peek_data.alpn, Vec::<Vec<u8>>::new());
    }

    #[test_log::test(tokio::test)]
    async fn returns_sni_and_alpn_data() {
        let mut config = client_config();
        config.alpn_protocols.push(b"example-alpn".to_vec());
        let buf = client_hello_bytes(config, "foobar.tld").await;
        let ClientHelloStatus::Ready(peek_data) = parse_client_hello(&buf) else {
            panic!("Expected complete ClientHello");
        };
        assert_eq!(peek_data.sni, "foobar.tld");
        assert_eq!(peek_data.alpn, vec![b"example-alpn".to_vec()]);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod rewind_stream_tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::RewindStream;

    #[test_log::test(tokio::test)]
    async fn replays_prefix_then_reads_inner() {
        let (client, mut server) = duplex(64);
        let mut rewind = RewindStream::new(b"hello ".to_vec(), client);
        server.write_all(b"world").await.unwrap();
        drop(server);
        let mut out = Vec::new();
        rewind.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"hello world");
    }
}
