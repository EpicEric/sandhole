use std::{
    collections::HashSet,
    path::PathBuf,
    sync::{Arc, RwLock},
};

use notify::{Event, EventKind, INotifyWatcher, RecommendedWatcher, RecursiveMode, Watcher};
use russh_keys::load_public_key;
use tokio::{
    fs::read_dir,
    sync::{oneshot, watch},
};

#[derive(Debug)]
pub(crate) struct FingerprintsValidator {
    pub(crate) fingerprints: Arc<RwLock<HashSet<String>>>,
    _watcher: INotifyWatcher,
}

impl FingerprintsValidator {
    pub(crate) async fn watch(directory: PathBuf) -> anyhow::Result<Self> {
        let fingerprints = Arc::new(RwLock::new(HashSet::new()));
        let (pubkeys_tx, mut pubkeys_rx) = watch::channel(());
        pubkeys_rx.mark_changed();
        let mut watcher = RecommendedWatcher::new(
            move |res: notify::Result<Event>| {
                if let Ok(res) = res {
                    match res.kind {
                        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => {
                            pubkeys_tx.send_replace(());
                        }
                        _ => (),
                    }
                };
            },
            notify::Config::default(),
        )?;
        watcher.watch(directory.as_path(), RecursiveMode::Recursive)?;
        let fingerprints_clone = Arc::clone(&fingerprints);
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let mut tx = Some(tx);
            while let Ok(_) = pubkeys_rx.changed().await {
                // TO-DO: Improve set re-population according to different Notify.rs events
                // (maybe create a separate HashMap to store "file name => fingerprint(s)" mappings...)
                let mut set = HashSet::new();
                if let Ok(mut read_dir) = read_dir(directory.as_path()).await {
                    while let Ok(Some(entry)) = read_dir.next_entry().await {
                        // TO-DO: Load multiple keys from single file
                        match load_public_key(entry.path()) {
                            Ok(data) => {
                                set.insert(data.fingerprint());
                            }
                            Err(e) => {
                                eprintln!(
                                    "Unable to load public key in {:?}: {}",
                                    entry.file_name(),
                                    e
                                );
                            }
                        }
                    }
                    *fingerprints_clone.write().unwrap() = set;
                    tx.take().map(|tx| tx.send(()));
                }
            }
        });
        rx.await.unwrap();
        Ok(FingerprintsValidator {
            fingerprints,
            _watcher: watcher,
        })
    }

    pub(crate) fn is_key_allowed(&self, fingerprint: &str) -> bool {
        self.fingerprints.read().unwrap().contains(fingerprint)
    }
}
