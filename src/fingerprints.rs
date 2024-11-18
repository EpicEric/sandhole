use std::{
    collections::HashSet,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};

use crate::directory::watch_directory;
use notify::RecommendedWatcher;
use russh_keys::{key::PublicKey, load_public_key};
use tokio::{fs::read_dir, sync::oneshot, task::JoinHandle};

#[derive(Debug)]
pub(crate) struct FingerprintsValidator {
    pub(crate) fingerprints: Arc<RwLock<HashSet<String>>>,
    join_handle: JoinHandle<()>,
    _watcher: RecommendedWatcher,
}

impl FingerprintsValidator {
    pub(crate) async fn watch(directory: PathBuf) -> anyhow::Result<Self> {
        let fingerprints = Arc::new(RwLock::new(HashSet::new()));
        let (watcher, mut pubkeys_rx) = watch_directory::<RecommendedWatcher>(directory.as_path())?;
        pubkeys_rx.mark_changed();
        let fingerprints_clone = Arc::clone(&fingerprints);
        let (init_tx, init_rx) = oneshot::channel::<()>();
        let join_handle = tokio::spawn(async move {
            let mut init_tx = Some(init_tx);
            while let Ok(_) = pubkeys_rx.changed().await {
                let mut set = HashSet::new();
                match read_dir(directory.as_path()).await {
                    Ok(mut read_dir) => {
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
                    }
                    Err(err) => {
                        eprintln!(
                            "Unable to read public keys directory {:?}: {}",
                            &directory, err
                        );
                    }
                }
                init_tx.take().map(|tx| tx.send(()));
                // TO-DO: Better debouncing
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
        init_rx.await.unwrap();
        Ok(FingerprintsValidator {
            fingerprints,
            join_handle,
            _watcher: watcher,
        })
    }

    pub(crate) fn is_key_allowed(&self, key: &PublicKey) -> bool {
        self.fingerprints
            .read()
            .unwrap()
            .contains(&key.fingerprint())
    }
}

impl Drop for FingerprintsValidator {
    fn drop(&mut self) {
        self.join_handle.abort();
    }
}

#[cfg(test)]
mod fingerprints_validator_tests {
    use std::sync::LazyLock;

    use super::FingerprintsValidator;
    use russh_keys::{key::PublicKey, parse_public_key_base64};

    static PUBLIC_KEYS_DIRECTORY: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/test_data/public_keys");
    static KEY_ONE: LazyLock<PublicKey> = LazyLock::new(|| {
        parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAIMYVfXHTqf3/0W8ZQ/I8zmMirvmosV78n1qtYgVQX58W",
        )
        .unwrap()
    });
    static KEY_TWO: LazyLock<PublicKey> = LazyLock::new(|| {
        parse_public_key_base64(
            "AAAAB3NzaC1yc2EAAAADAQABAAABgQCUdw1f/va/ax8L/5qoZw37+76psjybsY7qNJMxOhwqKQ6fKiLu2xv+uFQxdEbNitXbcC8zZ2m98XzEPlNoY3DTqw5RAt2qZQMMXFLzDNHCpY6xT1DxLFTYxczXj9Xk4Ms7/RQP6pxLV5PIVc06HXBThCzcLMDdnl9n0jEWu1CwSGtsc87/Gvbnr3QrfrnK40IS7c5SIfbI5yN7pfnCEkRf637EGzc11Tq4e2/ujweETZ1C+KcJZapVVHTvFfITyOqLeqrgXgsMQUML48SfDUl/RsY4nk6aFKwK7f0oGzykqLTX0YHS1wxLOnPSkK33ohvtjvcUzA/eAmjUiQquJQ7DW6RPvW57lozzIxwFvO4O/j398r3W1de3R7Q3rmAwKbujFSJlZb4OvS1ZLS8md8TwCO1xwE+4aY3xvsmeHpfBcEjhTmEYEEY630hbiMgHsbH1M7uAZkbXUgw7R6cLPCndc4GiDOLN/bkKwa55evbOS1J1cD4pi5lUSnzZzk9lYrU="
        ).unwrap()
    });
    static UNKNOWN_KEY: LazyLock<PublicKey> = LazyLock::new(|| {
        parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAIFlIvi8Fw1QvxpkRuAMiBKGL84r2wlgxTj7iOzXWBeU4",
        )
        .unwrap()
    });

    #[tokio::test]
    async fn allows_known_keys() {
        let validator = FingerprintsValidator::watch(PUBLIC_KEYS_DIRECTORY.parse().unwrap())
            .await
            .unwrap();
        assert!(validator.is_key_allowed(&KEY_ONE));
        assert!(validator.is_key_allowed(&KEY_TWO));
    }

    #[tokio::test]
    async fn forbids_unknown_keys() {
        let validator = FingerprintsValidator::watch(PUBLIC_KEYS_DIRECTORY.parse().unwrap())
            .await
            .unwrap();
        assert!(!validator.is_key_allowed(&UNKNOWN_KEY));
    }
}
