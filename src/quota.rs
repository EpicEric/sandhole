use std::{num::NonZero, sync::Arc};

use dashmap::DashMap;
#[cfg(test)]
use mockall::automock;

pub(crate) struct QuotaMap {
    max_quota: NonZero<usize>,
    map: DashMap<String, usize>,
}

#[cfg_attr(test, automock)]
// A trait for handlers that generate a token, indicating that some of the holder's quota is in use.
// To get a new token once the maximum quota is reached, old tokens must be dropped
// (which automatically cleans them up).
pub(crate) trait QuotaHandler {
    fn get_token(&self, holder: Option<String>) -> Option<QuotaToken>;
}

pub(crate) struct DummyQuotaHandler;

impl QuotaHandler for DummyQuotaHandler {
    fn get_token(&self, _: Option<String>) -> Option<QuotaToken> {
        Some(QuotaToken { callback: None })
    }
}

impl QuotaMap {
    pub(crate) fn new(max_quota: NonZero<usize>) -> Self {
        QuotaMap {
            max_quota,
            map: DashMap::new(),
        }
    }
}

impl QuotaHandler for Arc<QuotaMap> {
    fn get_token(&self, mut holder: Option<String>) -> Option<QuotaToken> {
        if let Some(holder) = holder.take() {
            let mut entry = self.map.entry(holder.clone()).or_default();
            if *entry >= self.max_quota.into() {
                return None;
            }
            *entry += 1;
            drop(entry);
            let this = Arc::clone(self);
            let callback = move || {
                this.map.remove_if_mut(&holder, |_, entry| {
                    *entry -= 1;
                    *entry == 0
                });
            };
            Some(QuotaToken {
                callback: Some(Box::new(callback)),
            })
        } else {
            Some(QuotaToken { callback: None })
        }
    }
}

pub(crate) struct QuotaToken {
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
mod quota_map_tests {
    use std::sync::Arc;

    use super::{QuotaHandler, QuotaMap};

    #[test]
    fn returns_tokens_while_under_quota() {
        let map = Arc::new(QuotaMap::new(3.try_into().unwrap()));
        let token_1 = map.get_token(Some("a".into())).unwrap();
        let _token_2 = map.get_token(Some("a".into())).unwrap();
        let _token_3 = map.get_token(Some("a".into())).unwrap();
        assert!(map.get_token(Some("a".into())).is_none());
        drop(token_1);
        let _token_4 = map.get_token(Some("a".into())).unwrap();
        assert!(map.get_token(Some("a".into())).is_none());
    }

    #[test]
    fn returns_unlimited_tokens_for_unspecified_holder() {
        let map = Arc::new(QuotaMap::new(3.try_into().unwrap()));
        let mut tokens = Vec::with_capacity(5);
        for _ in 0..5 {
            tokens.push(map.get_token(None).unwrap());
        }
    }

    #[test]
    fn returns_tokens_for_different_holders() {
        let map = Arc::new(QuotaMap::new(3.try_into().unwrap()));
        let token_a_1 = map.get_token(Some("a".into())).unwrap();
        let _token_a_2 = map.get_token(Some("a".into())).unwrap();
        let _token_a_3 = map.get_token(Some("a".into())).unwrap();
        assert!(map.get_token(Some("a".into())).is_none());
        let _token_b_1 = map.get_token(Some("b".into())).unwrap();
        let _token_b_2 = map.get_token(Some("b".into())).unwrap();
        let _token_b_3 = map.get_token(Some("b".into())).unwrap();
        assert!(map.get_token(Some("b".into())).is_none());
        assert!(map.get_token(Some("a".into())).is_none());
        drop(token_a_1);
        assert!(map.get_token(Some("b".into())).is_none());
        assert!(map.get_token(Some("a".into())).is_some());
    }
}
