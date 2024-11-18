use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};

use crate::directory::watch_directory;
use notify::RecommendedWatcher;
use rustls::{
    client::verify_server_name,
    crypto::aws_lc_rs::sign::any_supported_type,
    pki_types::{pem::PemObject, DnsName, PrivateKeyDer, ServerName},
    server::{ClientHello, ParsedCertificate, ResolvesServerCert},
    sign::CertifiedKey,
};
use tokio::{fs::read_dir, sync::oneshot};
use trie_rs::map::{Trie, TrieBuilder};
use webpki::{types::CertificateDer, EndEntityCert};

#[derive(Debug)]
pub(crate) struct CertificateResolver {
    pub(crate) certificates: Arc<RwLock<Trie<String, Arc<CertifiedKey>>>>,
    _watcher: RecommendedWatcher,
}

impl CertificateResolver {
    pub(crate) async fn watch(directory: PathBuf) -> anyhow::Result<Self> {
        let certificates = Arc::new(RwLock::new(TrieBuilder::new().build()));
        let (watcher, mut certificates_rx) =
            watch_directory::<RecommendedWatcher>(directory.as_path())?;
        certificates_rx.mark_changed();
        let certs_clone = Arc::clone(&certificates);
        let (init_tx, init_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let mut init_tx = Some(init_tx);
            while let Ok(_) = certificates_rx.changed().await {
                let mut builder = TrieBuilder::new();
                match read_dir(directory.as_path()).await {
                    Ok(mut read_dir) => {
                        while let Ok(Some(entry)) = read_dir.next_entry().await {
                            if entry
                                .file_type()
                                .await
                                .is_ok_and(|filetype| filetype.is_dir())
                            {
                                let cert = match CertificateDer::pem_file_iter(
                                    entry.path().join("fullchain.pem"),
                                )
                                .and_then(|iter| iter.collect::<Result<Vec<_>, _>>())
                                {
                                    Ok(cert) => cert,
                                    Err(err) => {
                                        eprintln!(
                                            "Unable to load certificate chain in {:?}: {}",
                                            entry.path().join("fullchain.pem"),
                                            err
                                        );
                                        continue;
                                    }
                                };
                                let key = match PrivateKeyDer::from_pem_file(
                                    entry.path().join("privkey.pem"),
                                ) {
                                    Ok(key) => key,
                                    Err(err) => {
                                        eprintln!(
                                            "Unable to load certficate key in {:?}: {}",
                                            entry.path().join("privkey.pem"),
                                            err
                                        );
                                        continue;
                                    }
                                };
                                let Ok(key) = any_supported_type(&key) else {
                                    eprintln!(
                                        "Invalid key in {:?}: no supported type",
                                        entry.path().join("privkey.pem")
                                    );
                                    continue;
                                };
                                let ck = Arc::new(CertifiedKey::new(cert, key));
                                for eec in ck
                                    .end_entity_cert()
                                    .iter()
                                    .filter_map(|&cert| EndEntityCert::try_from(cert).ok())
                                {
                                    for name in eec.valid_dns_names() {
                                        let path = name
                                            .trim_start_matches("*.")
                                            .split('.')
                                            .rev()
                                            .map(String::from)
                                            .collect::<Vec<_>>();
                                        builder.push(path, ck.clone());
                                    }
                                }
                            }
                        }
                        let trie = builder.build();
                        *certs_clone.write().unwrap() = trie;
                    }
                    Err(err) => {
                        eprintln!(
                            "Unable to read certificates directory {:?}: {}",
                            &directory, err
                        );
                    }
                }
                init_tx.take().map(|tx| tx.send(()));
                // TO-DO: Better debouncing
                tokio::time::sleep(Duration::from_secs(2)).await
            }
        });
        init_rx.await.unwrap();
        Ok(CertificateResolver {
            certificates,
            _watcher: watcher,
        })
    }
}

impl ResolvesServerCert for CertificateResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(server_name_str) = client_hello.server_name() {
            let Ok(server_name) = DnsName::try_from(server_name_str).map(ServerName::DnsName)
            else {
                return None;
            };
            self.certificates
                .read()
                .unwrap()
                .common_prefix_search(
                    &server_name_str
                        .split('.')
                        .rev()
                        .map(String::from)
                        .collect::<Vec<_>>(),
                )
                .find(|(_, ck): &(String, &Arc<CertifiedKey>)| {
                    ck.end_entity_cert().is_ok_and(|eec| {
                        ParsedCertificate::try_from(eec)
                            .is_ok_and(|cert| verify_server_name(&cert, &server_name).is_ok())
                    })
                })
                .map(|(_, ck)| ck.clone())
        } else {
            None
        }
    }
}
