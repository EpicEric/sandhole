use rustls::internal::msgs::{
    codec::{Codec, Reader},
    handshake::{ClientExtension, HandshakePayload},
    message::{Message, MessagePayload, OutboundOpaqueMessage},
};

// Get the SNI and ALPN from a peeked ClientHello if it's valid.
pub(crate) fn peek_sni_and_alpn(buf: &[u8]) -> Option<(String, Vec<Vec<u8>>)> {
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
            return sni.map(|sni| (sni, alpn));
        }
    }
    None
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod peek_sni_and_alpn_tests {
    use crate::peek_sni_and_alpn;

    #[test]
    fn fails_on_empty_buffer() {
        assert!(peek_sni_and_alpn(b"").is_none());
    }
}
