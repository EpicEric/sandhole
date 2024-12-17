use std::{collections::BTreeSet, path::PathBuf, sync::Arc, time::Duration};

use crate::{directory::watch_directory, droppable_handle::DroppableHandle};
use log::{error, warn};
use notify::RecommendedWatcher;
use ssh_key::{Fingerprint, HashAlg, PublicKey};
use tokio::{
    fs::{read_dir, read_to_string},
    sync::{oneshot, RwLock},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum AuthenticationType {
    /// Not authenticated.
    None,
    /// Authenticated as a valid user.
    User,
    /// Authenticated as an admin.
    Admin,
}

#[derive(Debug)]
pub(crate) struct FingerprintsValidator {
    user_fingerprints: Arc<RwLock<BTreeSet<Fingerprint>>>,
    admin_fingerprints: Arc<RwLock<BTreeSet<Fingerprint>>>,
    _user_join_handle: DroppableHandle<()>,
    _admin_join_handle: DroppableHandle<()>,
    _watchers: [RecommendedWatcher; 2],
}

impl FingerprintsValidator {
    // Start watching on the directories, waiting for user/admin keys that get added or removed.
    pub(crate) async fn watch(
        user_keys_directory: PathBuf,
        admin_keys_directory: PathBuf,
    ) -> anyhow::Result<Self> {
        let user_fingerprints = Arc::new(RwLock::new(BTreeSet::new()));
        let (user_watcher, mut user_rx) =
            watch_directory::<RecommendedWatcher>(user_keys_directory.as_path())?;
        user_rx.mark_changed();
        let admin_fingerprints = Arc::new(RwLock::new(BTreeSet::new()));
        let (admin_watcher, mut admin_rx) =
            watch_directory::<RecommendedWatcher>(admin_keys_directory.as_path())?;
        admin_rx.mark_changed();
        // Populate user keys
        let user_fingerprints_clone = Arc::clone(&user_fingerprints);
        let (user_init_tx, user_init_rx) = oneshot::channel::<()>();
        let user_join_handle = DroppableHandle(tokio::spawn(async move {
            let mut user_init_tx = Some(user_init_tx);
            loop {
                if user_rx.changed().await.is_err() {
                    break;
                }
                let mut user_set = BTreeSet::new();
                match read_dir(user_keys_directory.as_path()).await {
                    Ok(mut read_dir) => {
                        while let Ok(Some(entry)) = read_dir.next_entry().await {
                            match read_to_string(entry.path()).await {
                                Ok(data) => {
                                    user_set.extend(
                                        data.lines()
                                            .flat_map(|line| PublicKey::from_openssh(line).ok())
                                            .map(|key| key.fingerprint(HashAlg::Sha256)),
                                    );
                                }
                                Err(err) => {
                                    warn!(
                                        "Unable to load user key in {:?}: {}",
                                        entry.file_name(),
                                        err
                                    );
                                }
                            }
                        }
                        *user_fingerprints_clone.write().await = user_set;
                    }
                    Err(err) => {
                        error!(
                            "Unable to read user keys directory {:?}: {}",
                            &user_keys_directory, err
                        );
                    }
                }
                if let Some(tx) = user_init_tx.take() {
                    let _ = tx.send(());
                };
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }));
        // Populate admin keys
        let admin_fingerprints_clone = Arc::clone(&admin_fingerprints);
        let (admin_init_tx, admin_init_rx) = oneshot::channel::<()>();
        let admin_join_handle = DroppableHandle(tokio::spawn(async move {
            let mut admin_init_tx = Some(admin_init_tx);
            loop {
                if admin_rx.changed().await.is_err() {
                    break;
                }
                let mut admin_set = BTreeSet::new();
                match read_dir(admin_keys_directory.as_path()).await {
                    Ok(mut read_dir) => {
                        while let Ok(Some(entry)) = read_dir.next_entry().await {
                            match read_to_string(entry.path()).await {
                                Ok(data) => {
                                    admin_set.extend(
                                        data.lines()
                                            .flat_map(|line| PublicKey::from_openssh(line).ok())
                                            .map(|key| key.fingerprint(HashAlg::Sha256)),
                                    );
                                }
                                Err(err) => {
                                    warn!(
                                        "Unable to load admin key in {:?}: {}",
                                        entry.file_name(),
                                        err
                                    );
                                }
                            }
                        }
                        *admin_fingerprints_clone.write().await = admin_set;
                    }
                    Err(err) => {
                        error!(
                            "Unable to read admin keys directory {:?}: {}",
                            &admin_keys_directory, err
                        );
                    }
                }
                if let Some(tx) = admin_init_tx.take() {
                    let _ = tx.send(());
                };
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }));
        tokio::try_join!(user_init_rx, admin_init_rx)?;
        Ok(FingerprintsValidator {
            user_fingerprints,
            admin_fingerprints,
            _user_join_handle: user_join_handle,
            _admin_join_handle: admin_join_handle,
            _watchers: [user_watcher, admin_watcher],
        })
    }

    // Find the right authentication type for a given fingerprint
    pub(crate) async fn authenticate_fingerprint(
        &self,
        fingerprint: &Fingerprint,
    ) -> AuthenticationType {
        if self.admin_fingerprints.read().await.contains(fingerprint) {
            AuthenticationType::Admin
        } else if self.user_fingerprints.read().await.contains(fingerprint) {
            AuthenticationType::User
        } else {
            AuthenticationType::None
        }
    }
}

#[cfg(test)]
mod fingerprints_validator_tests {
    use russh_keys::parse_public_key_base64;
    use ssh_key::HashAlg;

    use super::{AuthenticationType, FingerprintsValidator};

    static USER_KEYS_DIRECTORY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/user_keys");
    static ADMIN_KEYS_DIRECTORY: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/admin_keys");

    #[tokio::test]
    async fn authenticates_user_keys() {
        let validator = FingerprintsValidator::watch(
            USER_KEYS_DIRECTORY.parse().unwrap(),
            ADMIN_KEYS_DIRECTORY.parse().unwrap(),
        )
        .await
        .unwrap();

        let admin_key = parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAIDpmDGLbC68yM87r+fD/aoEimDdnzZtmnZXCnxkIGHMq",
        )
        .unwrap();
        let key_one = parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAIMYVfXHTqf3/0W8ZQ/I8zmMirvmosV78n1qtYgVQX58W",
        )
        .unwrap();
        let key_two =
            parse_public_key_base64(
                "AAAAB3NzaC1yc2EAAAADAQABAAABgQCUdw1f/va/ax8L/5qoZw37+76psjybsY7qNJMxOhwqKQ6fKiLu2xv+uFQxdEbNitXbcC8zZ2m98XzEPlNoY3DTqw5RAt2qZQMMXFLzDNHCpY6xT1DxLFTYxczXj9Xk4Ms7/RQP6pxLV5PIVc06HXBThCzcLMDdnl9n0jEWu1CwSGtsc87/Gvbnr3QrfrnK40IS7c5SIfbI5yN7pfnCEkRf637EGzc11Tq4e2/ujweETZ1C+KcJZapVVHTvFfITyOqLeqrgXgsMQUML48SfDUl/RsY4nk6aFKwK7f0oGzykqLTX0YHS1wxLOnPSkK33ohvtjvcUzA/eAmjUiQquJQ7DW6RPvW57lozzIxwFvO4O/j398r3W1de3R7Q3rmAwKbujFSJlZb4OvS1ZLS8md8TwCO1xwE+4aY3xvsmeHpfBcEjhTmEYEEY630hbiMgHsbH1M7uAZkbXUgw7R6cLPCndc4GiDOLN/bkKwa55evbOS1J1cD4pi5lUSnzZzk9lYrU="
            ).unwrap();
        let unknown_key = parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAIFlIvi8Fw1QvxpkRuAMiBKGL84r2wlgxTj7iOzXWBeU4",
        )
        .unwrap();

        assert_eq!(
            validator
                .authenticate_fingerprint(&admin_key.fingerprint(HashAlg::Sha256))
                .await,
            AuthenticationType::Admin
        );
        assert_eq!(
            validator
                .authenticate_fingerprint(&key_one.fingerprint(HashAlg::Sha256))
                .await,
            AuthenticationType::User
        );
        assert_eq!(
            validator
                .authenticate_fingerprint(&key_two.fingerprint(HashAlg::Sha256))
                .await,
            AuthenticationType::User
        );
        assert_eq!(
            validator
                .authenticate_fingerprint(&unknown_key.fingerprint(HashAlg::Sha256))
                .await,
            AuthenticationType::None
        );
    }
}
