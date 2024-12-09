use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};

use crate::{directory::watch_directory, droppable_handle::DroppableHandle};
use log::{error, warn};
use notify::RecommendedWatcher;
use ssh_key::{Fingerprint, HashAlg, PublicKey};
use tokio::{
    fs::{read_dir, read_to_string},
    sync::oneshot,
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
    _join_handle: DroppableHandle<()>,
    _watchers: [RecommendedWatcher; 2],
}

impl FingerprintsValidator {
    pub(crate) async fn watch(
        user_keys_directory: PathBuf,
        admin_keys_directory: PathBuf,
    ) -> anyhow::Result<Self> {
        let user_fingerprints = Arc::new(RwLock::new(BTreeSet::new()));
        let admin_fingerprints = Arc::new(RwLock::new(BTreeSet::new()));
        let (user_watcher, mut user_rx) =
            watch_directory::<RecommendedWatcher>(user_keys_directory.as_path())?;
        let (admin_watcher, mut admin_rx) =
            watch_directory::<RecommendedWatcher>(admin_keys_directory.as_path())?;
        user_rx.mark_changed();
        let user_fingerprints_clone = Arc::clone(&user_fingerprints);
        let admin_fingerprints_clone = Arc::clone(&admin_fingerprints);
        let (init_tx, init_rx) = oneshot::channel::<()>();
        let join_handle = DroppableHandle(tokio::spawn(async move {
            let mut init_tx = Some(init_tx);
            loop {
                if async {
                    tokio::select! {
                        change = user_rx.changed() => change.is_err(),
                        change = admin_rx.changed() => change.is_err(),
                    }
                }
                .await
                {
                    break;
                }
                tokio::join!(
                    async {
                        let mut user_set = BTreeSet::new();
                        match read_dir(user_keys_directory.as_path()).await {
                            Ok(mut read_dir) => {
                                while let Ok(Some(entry)) = read_dir.next_entry().await {
                                    match read_to_string(entry.path()).await {
                                        Ok(data) => {
                                            user_set.extend(
                                                data.lines()
                                                    .flat_map(|line| {
                                                        PublicKey::from_openssh(line).ok()
                                                    })
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
                                *user_fingerprints_clone.write().unwrap() = user_set;
                            }
                            Err(err) => {
                                error!(
                                    "Unable to read user keys directory {:?}: {}",
                                    &user_keys_directory, err
                                );
                            }
                        }
                    },
                    async {
                        let mut admin_set = BTreeSet::new();
                        match read_dir(admin_keys_directory.as_path()).await {
                            Ok(mut read_dir) => {
                                while let Ok(Some(entry)) = read_dir.next_entry().await {
                                    match read_to_string(entry.path()).await {
                                        Ok(data) => {
                                            admin_set.extend(
                                                data.lines()
                                                    .flat_map(|line| {
                                                        PublicKey::from_openssh(line).ok()
                                                    })
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
                                *admin_fingerprints_clone.write().unwrap() = admin_set;
                            }
                            Err(err) => {
                                error!(
                                    "Unable to read admin keys directory {:?}: {}",
                                    &admin_keys_directory, err
                                );
                            }
                        }
                    }
                );
                init_tx.take().map(|tx| tx.send(()));
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }));
        init_rx.await.unwrap();
        Ok(FingerprintsValidator {
            user_fingerprints,
            admin_fingerprints,
            _join_handle: join_handle,
            _watchers: [user_watcher, admin_watcher],
        })
    }

    pub(crate) fn authenticate_fingerprint(&self, fingerprint: &Fingerprint) -> AuthenticationType {
        if self
            .admin_fingerprints
            .read()
            .unwrap()
            .contains(fingerprint)
        {
            AuthenticationType::Admin
        } else if self.user_fingerprints.read().unwrap().contains(fingerprint) {
            AuthenticationType::User
        } else {
            AuthenticationType::None
        }
    }
}

#[cfg(test)]
mod fingerprints_validator_tests {
    use super::{AuthenticationType, FingerprintsValidator};
    use russh_keys::parse_public_key_base64;
    use ssh_key::HashAlg;

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
            validator.authenticate_fingerprint(&admin_key.fingerprint(HashAlg::Sha256)),
            AuthenticationType::Admin
        );
        assert_eq!(
            validator.authenticate_fingerprint(&key_one.fingerprint(HashAlg::Sha256)),
            AuthenticationType::User
        );
        assert_eq!(
            validator.authenticate_fingerprint(&key_two.fingerprint(HashAlg::Sha256)),
            AuthenticationType::User
        );
        assert_eq!(
            validator.authenticate_fingerprint(&unknown_key.fingerprint(HashAlg::Sha256)),
            AuthenticationType::None
        );
    }
}
