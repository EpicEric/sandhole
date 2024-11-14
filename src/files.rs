use std::{path::PathBuf, sync::Arc};

use dashmap::DashSet;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use russh_keys::load_public_key;
use tokio::{fs::read_dir, sync::watch};

pub fn watch_public_keys_directory(
    directory: PathBuf,
    fingerprint_set: Arc<DashSet<String>>,
) -> anyhow::Result<()> {
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
    tokio::spawn(async move {
        // Keep watcher alive in spawned task
        let _watcher = watcher;
        while let Ok(_) = pubkeys_rx.changed().await {
            // TO-DO: Improve set re-population according to different Notify.rs events
            // (maybe create a separate HashMap to store "file name => fingerprint(s)" mappings...)
            fingerprint_set.clear();
            if let Ok(mut read_dir) = read_dir(directory.as_path()).await {
                while let Ok(Some(entry)) = read_dir.next_entry().await {
                    match load_public_key(entry.path()) {
                        Ok(data) => {
                            fingerprint_set.insert(data.fingerprint());
                        }
                        Err(e) => {
                            eprintln!("Unable to load public key {:?}: {}", entry.file_name(), e);
                        }
                    }
                }
            }
        }
    });
    Ok(())
}
