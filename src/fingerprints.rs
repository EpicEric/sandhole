use std::{
    collections::BTreeMap,
    fs::remove_file,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};

use crate::{directory::watch_directory, droppable_handle::DroppableHandle, error::ServerError};
use notify::RecommendedWatcher;
use russh::keys::{Algorithm, HashAlg, PublicKey, ssh_key::Fingerprint};
use tokio::{
    fs::{read_dir, read_to_string},
    sync::oneshot,
};

// Authentication identified for a given fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum AuthenticationType {
    /// Not authenticated.
    None,
    /// Authenticated as a valid user.
    User,
    /// Authenticated as an admin.
    Admin,
}

impl std::fmt::Display for AuthenticationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AuthenticationType::None => "None",
            AuthenticationType::User => "User",
            AuthenticationType::Admin => "Admin",
        })
    }
}

// Data related to a given key.
#[derive(Debug, Clone)]
pub(crate) struct KeyData {
    // File associated with the key.
    pub(crate) file: PathBuf,
    // The key's comment.
    pub(crate) comment: String,
    // The key's algorithm.
    pub(crate) algorithm: Algorithm,
    // Authentication type associated with the key.
    pub(crate) auth: AuthenticationType,
}

// Service that validates fingerprints from directories of public key files.
#[derive(Debug)]
pub(crate) struct FingerprintsValidator {
    // Data for fingerprints with user authorization.
    user_fingerprints: Arc<RwLock<BTreeMap<Fingerprint, KeyData>>>,
    // Data for fingerprints with admin authorization.
    admin_fingerprints: Arc<RwLock<BTreeMap<Fingerprint, KeyData>>>,
    // Task that updates user keys data upon filesystem changes.
    _user_join_handle: DroppableHandle<()>,
    // Task that updates admin keys data upon filesystem changes.
    _admin_join_handle: DroppableHandle<()>,
    // Filesystem change watchers.
    _watchers: [RecommendedWatcher; 2],
}

// Helper function with duplicated functionality for user and admin keys
async fn load_fingerprints_data(
    directory: &Path,
    fingerprints_data: &RwLock<BTreeMap<Fingerprint, KeyData>>,
    auth: AuthenticationType,
) {
    let mut fingerprints_map = BTreeMap::new();
    match read_dir(directory).await {
        Ok(mut read_dir) => {
            // For each file in the admin keys directory
            while let Ok(Some(entry)) = read_dir.next_entry().await {
                match read_to_string(entry.path()).await {
                    Ok(data) => {
                        fingerprints_map.extend(
                            // Try to find a key for each line
                            data.lines()
                                .filter(|line| !line.trim().is_empty())
                                .flat_map(|line| match PublicKey::from_openssh(line) {
                                    Ok(key) => Some(key),
                                    Err(error) => {
                                        #[cfg(not(coverage_nightly))]
                                        tracing::warn!(path=?entry, %error, "Unable to parse key.");
                                        None
                                    }
                                })
                                // Generate the SHA256 fingerprint and metadata for the given key
                                .map(|key| {
                                    (
                                        key.fingerprint(HashAlg::Sha256),
                                        KeyData {
                                            file: entry.path(),
                                            comment: key.comment().into(),
                                            algorithm: key.algorithm(),
                                            auth,
                                        },
                                    )
                                }),
                        );
                    }
                    Err(error) => {
                        #[cfg(not(coverage_nightly))]
                        tracing::warn!(path = ?entry.file_name(),%error, "Unable to load key.");
                    }
                }
            }
            *fingerprints_data.write().unwrap() = fingerprints_map;
        }
        Err(error) => {
            #[cfg(not(coverage_nightly))]
            tracing::error!(?directory, %error, "Unable to read keys directory.");
        }
    }
}

impl FingerprintsValidator {
    // Start watching on the directories, waiting for user/admin keys that get added or removed.
    pub(crate) async fn watch(
        user_keys_directory: PathBuf,
        admin_keys_directory: PathBuf,
    ) -> color_eyre::Result<Self> {
        if !user_keys_directory.as_path().is_dir() {
            return Err(ServerError::MissingDirectory(user_keys_directory).into());
        }
        let user_fingerprints = Arc::new(RwLock::new(BTreeMap::new()));
        let (user_watcher, mut user_rx) =
            watch_directory::<RecommendedWatcher>(user_keys_directory.as_path())?;
        if !admin_keys_directory.as_path().is_dir() {
            return Err(ServerError::MissingDirectory(admin_keys_directory).into());
        }
        let admin_fingerprints = Arc::new(RwLock::new(BTreeMap::new()));
        let (admin_watcher, mut admin_rx) =
            watch_directory::<RecommendedWatcher>(admin_keys_directory.as_path())?;
        // Populate user keys
        let user_fingerprints_clone = Arc::clone(&user_fingerprints);
        let (user_init_tx, user_init_rx) = oneshot::channel::<()>();
        let user_join_handle = DroppableHandle(tokio::spawn(async move {
            let mut user_init_tx = Some(user_init_tx);
            loop {
                if user_init_tx.is_none() {
                    // Wait and debounce
                    loop {
                        if user_rx.changed().await.is_err() {
                            return;
                        }
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        let Ok(changed) = user_rx.has_changed() else {
                            return;
                        };
                        if !changed {
                            break;
                        }
                    }
                }
                load_fingerprints_data(
                    user_keys_directory.as_path(),
                    &user_fingerprints_clone,
                    AuthenticationType::User,
                )
                .await;
                // Notify about initial keys population
                if let Some(tx) = user_init_tx.take() {
                    let _ = tx.send(());
                };
            }
        }));
        // Populate admin keys
        let admin_fingerprints_clone = Arc::clone(&admin_fingerprints);
        let (admin_init_tx, admin_init_rx) = oneshot::channel::<()>();
        let admin_join_handle = DroppableHandle(tokio::spawn(async move {
            let mut admin_init_tx = Some(admin_init_tx);
            loop {
                if admin_init_tx.is_none() {
                    // Wait and debounce
                    loop {
                        if admin_rx.changed().await.is_err() {
                            return;
                        }
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        let Ok(changed) = admin_rx.has_changed() else {
                            return;
                        };
                        if !changed {
                            break;
                        }
                    }
                }
                load_fingerprints_data(
                    admin_keys_directory.as_path(),
                    &admin_fingerprints_clone,
                    AuthenticationType::Admin,
                )
                .await;
                // Notify about initial keys population
                if let Some(tx) = admin_init_tx.take() {
                    let _ = tx.send(());
                };
            }
        }));
        // Wait until the user and admin keys have been populated once
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
    pub(crate) fn authenticate_fingerprint(&self, fingerprint: &Fingerprint) -> AuthenticationType {
        // Check admin keys first
        if self
            .admin_fingerprints
            .read()
            .unwrap()
            .contains_key(fingerprint)
        {
            AuthenticationType::Admin
        // Check user keys next
        } else if self
            .user_fingerprints
            .read()
            .unwrap()
            .contains_key(fingerprint)
        {
            AuthenticationType::User
        // No authentication match
        } else {
            AuthenticationType::None
        }
    }

    // Return the key data related to a given fingerprint
    pub(crate) fn get_data_for_fingerprint(&self, fingerprint: &Fingerprint) -> Option<KeyData> {
        // Check admin keys first
        match self.admin_fingerprints.read().unwrap().get(fingerprint) {
            Some(key_data) => {
                Some(key_data.clone())
                // Check user keys next
            }
            _ => self
                .user_fingerprints
                .read()
                .unwrap()
                .get(fingerprint)
                .cloned(),
        }
    }

    // Delete a user key from the fingerprints matcher and the filesystem
    pub(crate) fn remove_user_key(&self, fingerprint: &Fingerprint) -> color_eyre::Result<()> {
        match self.user_fingerprints.write().unwrap().remove(fingerprint) {
            Some(KeyData { file, .. }) => Ok(remove_file(file)?),
            _ => Err(ServerError::NoMatchingUserKey.into()),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod fingerprints_validator_tests {
    use russh::keys::{HashAlg, parse_public_key_base64};

    use super::{AuthenticationType, FingerprintsValidator};

    static USER_KEYS_DIRECTORY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/user_keys");
    static ADMIN_KEYS_DIRECTORY: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/admin_keys");

    #[test_log::test(tokio::test)]
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

    #[test_log::test(tokio::test)]
    async fn gets_data_for_fingerprints() {
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

        let admin_key_data = validator
            .get_data_for_fingerprint(&admin_key.fingerprint(HashAlg::Sha256))
            .unwrap();
        assert_eq!(admin_key_data.auth, AuthenticationType::Admin);
        assert_eq!(admin_key_data.comment, "admin");
        assert_eq!(admin_key_data.algorithm.as_str(), "ssh-ed25519");
        assert_eq!(
            admin_key_data.file.to_string_lossy(),
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/data/admin_keys/admin.pub"
            )
        );

        let user_one_key_data = validator
            .get_data_for_fingerprint(&key_one.fingerprint(HashAlg::Sha256))
            .unwrap();
        assert_eq!(user_one_key_data.auth, AuthenticationType::User);
        assert_eq!(user_one_key_data.comment, "key1");
        assert_eq!(user_one_key_data.algorithm.as_str(), "ssh-ed25519");
        assert_eq!(
            user_one_key_data.file.to_string_lossy(),
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/data/user_keys/keys_1_2.pub"
            )
        );

        let user_two_key_data = validator
            .get_data_for_fingerprint(&key_two.fingerprint(HashAlg::Sha256))
            .unwrap();
        assert_eq!(user_two_key_data.auth, AuthenticationType::User);
        assert_eq!(user_two_key_data.comment, "key2");
        assert_eq!(user_two_key_data.algorithm.as_str(), "ssh-rsa");
        assert_eq!(
            user_two_key_data.file.to_string_lossy(),
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/data/user_keys/keys_1_2.pub"
            )
        );

        assert!(
            validator
                .get_data_for_fingerprint(&unknown_key.fingerprint(HashAlg::Sha256))
                .is_none(),
            "shouldn't have data for unknown key"
        );
    }
}
