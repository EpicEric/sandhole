use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
};

use notify::{Event, EventKind, INotifyWatcher, RecommendedWatcher, RecursiveMode, Watcher};
use rustls::{
    client::verify_server_name,
    crypto::aws_lc_rs::sign::any_supported_type,
    pki_types::{pem::PemObject, DnsName, PrivateKeyDer, ServerName},
    server::{ClientHello, ParsedCertificate, ResolvesServerCert},
    sign::CertifiedKey,
};
use tokio::{fs::read_dir, sync::watch};
use trie_rs::map::{Trie, TrieBuilder};
use webpki::{types::CertificateDer, EndEntityCert};

#[derive(Debug)]
pub(crate) struct CertificateResolver {
    pub(crate) certificates: Arc<RwLock<Trie<String, Arc<CertifiedKey>>>>,
    _watcher: INotifyWatcher,
}

impl TryFrom<PathBuf> for CertificateResolver {
    type Error = anyhow::Error;

    fn try_from(directory: PathBuf) -> Result<Self, Self::Error> {
        let certificates = Arc::new(RwLock::new(TrieBuilder::new().build()));
        let (certificates_tx, mut certificates_rx) = watch::channel(());
        certificates_rx.mark_changed();
        let mut watcher = RecommendedWatcher::new(
            move |res: notify::Result<Event>| {
                if let Ok(res) = res {
                    match res.kind {
                        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => {
                            certificates_tx.send_replace(());
                        }
                        _ => (),
                    }
                };
            },
            notify::Config::default(),
        )?;
        watcher.watch(directory.as_path(), RecursiveMode::Recursive)?;
        let certs_clone = Arc::clone(&certificates);
        tokio::spawn(async move {
            while let Ok(_) = certificates_rx.changed().await {
                let mut builder = TrieBuilder::new();
                if let Ok(mut read_dir) = read_dir(directory.as_path()).await {
                    while let Ok(Some(entry)) = read_dir.next_entry().await {
                        if entry
                            .file_type()
                            .await
                            .is_ok_and(|filetype| filetype.is_dir())
                        {
                            let path = entry.path();
                            let Ok(Ok(Ok(cert))) = tokio::task::spawn_blocking(move || {
                                CertificateDer::pem_file_iter(path.join("fullchain.pem"))
                                    .map(|iter| iter.collect::<Result<Vec<_>, _>>())
                            })
                            .await
                            else {
                                eprintln!(
                                    "Unable to load certificate in {:?}",
                                    entry.path().join("fullchain.pem")
                                );
                                continue;
                            };
                            let path = entry.path();
                            let Ok(Ok(key)) = tokio::task::spawn_blocking(move || {
                                PrivateKeyDer::from_pem_file(path.join("privkey.pem"))
                            })
                            .await
                            else {
                                eprintln!(
                                    "Unable to load key in {:?}",
                                    entry.path().join("privkey.pem")
                                );
                                continue;
                            };
                            let Ok(key) = any_supported_type(&key) else {
                                eprintln!("Invalid key in {:?}", entry.path().join("privkey.pem"));
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
            }
        });
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
