use std::{hash::Hash, num::NonZero, sync::Arc};

use dashmap::DashMap;
#[cfg(test)]
use mockall::automock;
use ssh_key::Fingerprint;

// The unique identifications for each user, to discriminate across multiple sessions.
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum UserIdentification {
    PublicKey(Fingerprint),
    Username(String),
}

impl Hash for UserIdentification {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
        match self {
            UserIdentification::PublicKey(fingerprint) => {
                fingerprint.algorithm().hash(state);
                fingerprint.as_bytes().hash(state);
            }
            UserIdentification::Username(user) => user.hash(state),
        }
    }
}

// Which kind of user the quota token will be generated for.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub(crate) enum TokenHolder {
    User(UserIdentification),
    Admin(UserIdentification),
}

// Return a string representation of the user identifier.
impl TokenHolder {
    pub(crate) fn get_user(&self) -> String {
        match self {
            TokenHolder::User(user) | TokenHolder::Admin(user) => match user {
                UserIdentification::PublicKey(fingerprint) => fingerprint.to_string(),
                UserIdentification::Username(username) => username.clone(),
            },
        }
    }
}

// A token that represents a unit of the user-allowed quota.
pub(crate) struct QuotaToken {
    // A function to call when the token is dropped.
    callback: Option<Box<dyn FnOnce() + Send + Sync>>,
}

impl Drop for QuotaToken {
    fn drop(&mut self) {
        if let Some(callback) = self.callback.take() {
            (callback)()
        }
    }
}

#[cfg(test)]
pub(crate) fn get_test_token() -> QuotaToken {
    QuotaToken { callback: None }
}

#[cfg_attr(test, automock)]
// A trait for handlers that generate a token, indicating that some of the holder's quota is in use.
// To get a new token once the maximum quota is reached, old tokens must be dropped
// (which automatically cleans them up).
pub(crate) trait QuotaHandler {
    fn get_token(&self, holder: TokenHolder) -> Option<QuotaToken>;
}

pub(crate) struct DummyQuotaHandler;

impl QuotaHandler for DummyQuotaHandler {
    fn get_token(&self, _: TokenHolder) -> Option<QuotaToken> {
        Some(QuotaToken { callback: None })
    }
}

// A map tracking the quota for each user.
// The tokens it generates keep track of when they're dropped, and update the underlying entry accordingly.
pub(crate) struct QuotaMap {
    // The maximum quota for each user.
    max_quota: NonZero<u32>,
    // The structure storing data for each user.
    map: DashMap<UserIdentification, u32>,
}

impl QuotaMap {
    pub(crate) fn new(max_quota: NonZero<u32>) -> Self {
        QuotaMap {
            max_quota,
            map: DashMap::new(),
        }
    }
}

impl QuotaHandler for Arc<QuotaMap> {
    fn get_token(&self, holder: TokenHolder) -> Option<QuotaToken> {
        match holder {
            // If the holder is a user, generate a limited amount of tokens
            TokenHolder::User(holder) => {
                let mut entry = self.map.entry(holder.clone()).or_default();
                // If the max quota is reached, don't return a new token
                if *entry >= self.max_quota.into() {
                    return None;
                }
                *entry += 1;
                drop(entry);
                let this = Arc::clone(self);
                // Add a callback to decrease the token count on drop
                let callback = move || {
                    this.map.remove_if_mut(&holder, |_, entry| {
                        *entry -= 1;
                        *entry == 0
                    });
                };
                // Return the token instance
                Some(QuotaToken {
                    callback: Some(Box::new(callback)),
                })
            }
            // If the holder is an admin, generate a new token indiscriminately
            TokenHolder::Admin(_) => Some(QuotaToken { callback: None }),
        }
    }
}

#[cfg(test)]
mod quota_map_tests {
    use std::sync::Arc;

    use rand::rngs::OsRng;
    use ssh_key::HashAlg;

    use super::{QuotaHandler, QuotaMap, TokenHolder, UserIdentification};

    #[test]
    fn returns_tokens_while_under_quota() {
        let user = UserIdentification::Username("a".into());
        let map = Arc::new(QuotaMap::new(3.try_into().unwrap()));
        let token_1 = map.get_token(TokenHolder::User(user.clone())).unwrap();
        let _token_2 = map.get_token(TokenHolder::User(user.clone())).unwrap();
        let _token_3 = map.get_token(TokenHolder::User(user.clone())).unwrap();
        assert!(
            map.get_token(TokenHolder::User(user.clone())).is_none(),
            "shouldn't create token for quota-reaching user"
        );
        drop(token_1);
        let _token_4 = map.get_token(TokenHolder::User(user.clone())).unwrap();
        assert!(
            map.get_token(TokenHolder::User(user.clone())).is_none(),
            "shouldn't create token for quota-reaching user"
        );
    }

    #[test]
    fn returns_unlimited_tokens_for_admin_holder() {
        let key =
            russh_keys::PrivateKey::random(&mut OsRng, russh_keys::Algorithm::Ed25519).unwrap();
        let map = Arc::new(QuotaMap::new(3.try_into().unwrap()));
        let mut tokens = Vec::with_capacity(5);
        for _ in 0..5 {
            tokens.push(
                map.get_token(TokenHolder::Admin(UserIdentification::PublicKey(
                    key.fingerprint(HashAlg::Sha256),
                )))
                .unwrap(),
            );
        }
    }

    #[test]
    fn returns_tokens_for_different_holders() {
        let key =
            russh_keys::PrivateKey::random(&mut OsRng, russh_keys::Algorithm::Ed25519).unwrap();
        let fingerprint = key.fingerprint(HashAlg::Sha256);
        let user_a = UserIdentification::Username("a".into());
        let user_b = UserIdentification::PublicKey(fingerprint);
        let map = Arc::new(QuotaMap::new(3.try_into().unwrap()));
        let token_a_1 = map.get_token(TokenHolder::User(user_a.clone())).unwrap();
        let _token_a_2 = map.get_token(TokenHolder::User(user_a.clone())).unwrap();
        let _token_a_3 = map.get_token(TokenHolder::User(user_a.clone())).unwrap();
        assert!(
            map.get_token(TokenHolder::User(user_a.clone())).is_none(),
            "shouldn't create token for quota-reaching user"
        );
        let _token_b_1 = map.get_token(TokenHolder::User(user_b.clone())).unwrap();
        let _token_b_2 = map.get_token(TokenHolder::User(user_b.clone())).unwrap();
        let _token_b_3 = map.get_token(TokenHolder::User(user_b.clone())).unwrap();
        assert!(
            map.get_token(TokenHolder::User(user_b.clone())).is_none(),
            "shouldn't create token for quota-reaching user"
        );
        assert!(
            map.get_token(TokenHolder::User(user_a.clone())).is_none(),
            "shouldn't create token for quota-reaching user"
        );
        drop(token_a_1);
        assert!(
            map.get_token(TokenHolder::User(user_b.clone())).is_none(),
            "shouldn't create token for quota-reaching user"
        );
        assert!(
            map.get_token(TokenHolder::User(user_a.clone())).is_some(),
            "should create token for user below quota"
        );
    }
}
