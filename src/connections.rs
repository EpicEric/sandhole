use std::{
    borrow::Borrow,
    collections::BTreeMap,
    hash::Hash,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use dashmap::DashMap;
#[cfg(test)]
use mockall::automock;
use rand::seq::SliceRandom;

use crate::{
    config::LoadBalancing,
    error::ServerError,
    quota::{QuotaHandler, QuotaToken, TokenHolder},
};

#[cfg_attr(test, automock)]
pub(crate) trait ConnectionMapReactor<K> {
    fn call(&self, identifiers: Vec<K>);
}

pub(crate) struct DummyConnectionMapReactor;

impl<K> ConnectionMapReactor<K> for DummyConnectionMapReactor {
    fn call(&self, _: Vec<K>) {}
}

struct ConnectionMapEntry<H> {
    user: String,
    address: SocketAddr,
    handler: H,
    _token: QuotaToken,
}

pub(crate) struct ConnectionMap<K, H, R = DummyConnectionMapReactor> {
    load_balancing: LoadBalancing,
    map: DashMap<K, Vec<ConnectionMapEntry<H>>>,
    quota_handler: Arc<Box<dyn QuotaHandler + Send + Sync>>,
    reactor: RwLock<Option<R>>,
}

impl<K, H, R> ConnectionMap<K, H, R>
where
    K: Eq + Hash + Clone + Ord + PartialOrd,
    H: Clone,
    R: ConnectionMapReactor<K> + Send + 'static,
{
    pub(crate) fn new(
        load_balancing: LoadBalancing,
        quota_handler: Arc<Box<dyn QuotaHandler + Send + Sync>>,
        reactor: Option<R>,
    ) -> Self {
        ConnectionMap {
            load_balancing,
            map: DashMap::new(),
            quota_handler,
            reactor: RwLock::new(reactor),
        }
    }

    pub(crate) fn insert(
        &self,
        key: K,
        address: SocketAddr,
        holder: TokenHolder,
        handler: H,
    ) -> anyhow::Result<()> {
        let len = self.map.len();
        let user = holder.get_user();
        match self.load_balancing {
            LoadBalancing::Allow => {
                let Some(token) = self.quota_handler.get_token(holder) else {
                    return Err(ServerError::QuotaReached.into());
                };
                self.map.entry(key).or_default().push(ConnectionMapEntry {
                    user,
                    address,
                    handler,
                    _token: token,
                });
            }
            LoadBalancing::Replace => {
                let Some(token) = self.quota_handler.get_token(holder) else {
                    return Err(ServerError::QuotaReached.into());
                };
                self.map.insert(
                    key,
                    vec![ConnectionMapEntry {
                        user,
                        address,
                        handler,
                        _token: token,
                    }],
                );
            }
            LoadBalancing::Deny => {
                if self.map.contains_key(&key) {
                    return Err(ServerError::LoadBalancingAlreadyBound.into());
                }
                let Some(token) = self.quota_handler.get_token(holder) else {
                    return Err(ServerError::QuotaReached.into());
                };
                self.map.insert(
                    key,
                    vec![ConnectionMapEntry {
                        user,
                        address,
                        handler,
                        _token: token,
                    }],
                );
            }
        }
        if self.map.len() > len {
            if let Some(reactor) = self.reactor.read().unwrap().as_ref() {
                reactor.call(self.map.iter().map(|entry| entry.key().clone()).collect())
            }
        }
        Ok(())
    }

    pub(crate) fn get<Q>(&self, key: &Q) -> Option<H>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let mut rng = rand::thread_rng();
        self.map.get(key).and_then(|handler| {
            handler
                .value()
                .as_slice()
                .choose(&mut rng)
                .map(|ConnectionMapEntry { handler, .. }| Clone::clone(handler))
        })
    }

    pub(crate) fn remove<Q>(&self, key: &Q, address: &SocketAddr)
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let len = self.map.len();
        self.map.remove_if_mut(key, |_, value| {
            value.retain(|ConnectionMapEntry { address: addr, .. }| addr != address);
            value.is_empty()
        });
        if self.map.len() < len {
            if let Some(reactor) = self.reactor.read().unwrap().as_ref() {
                reactor.call(self.map.iter().map(|entry| entry.key().clone()).collect())
            }
        }
    }

    pub(crate) fn remove_by_address(&self, address: &SocketAddr) {
        let len = self.map.len();
        self.map.retain(|_, value| {
            value.retain(|ConnectionMapEntry { address: addr, .. }| addr != address);
            !value.is_empty()
        });
        if self.map.len() < len {
            if let Some(reactor) = self.reactor.read().unwrap().as_ref() {
                reactor.call(self.map.iter().map(|entry| entry.key().clone()).collect())
            }
        }
    }

    pub(crate) fn update_reactor(&self, reactor: Option<R>) {
        *self.reactor.write().unwrap() = reactor;
    }

    pub(crate) fn data(&self) -> BTreeMap<K, BTreeMap<SocketAddr, String>> {
        self.map
            .iter()
            .map(|entry| {
                (
                    entry.key().clone(),
                    entry
                        .value()
                        .iter()
                        .map(|ConnectionMapEntry { address, user, .. }| (*address, user.clone()))
                        .collect(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod connection_map_tests {
    use std::sync::Arc;

    use mockall::predicate::eq;

    use crate::{
        config::LoadBalancing,
        quota::{
            DummyQuotaHandler, MockQuotaHandler, QuotaHandler, TokenHolder, UserIdentification,
        },
    };

    use super::{ConnectionMap, MockConnectionMapReactor};

    #[test]
    fn inserts_and_removes_one_handler() {
        let mut mock_reactor = MockConnectionMapReactor::new();
        mock_reactor.expect_call().times(2).returning(|_| {});
        let mut mock_quota = MockQuotaHandler::new();
        mock_quota.expect_get_token().once().returning(|_| {
            DummyQuotaHandler.get_token(TokenHolder::Admin(UserIdentification::Username("".into())))
        });
        let map = ConnectionMap::<String, usize, _>::new(
            LoadBalancing::Allow,
            Arc::new(Box::new(mock_quota)),
            Some(mock_reactor),
        );
        map.insert(
            "host".into(),
            "127.0.0.1:1".parse().unwrap(),
            TokenHolder::User(UserIdentification::Username("user1".into())),
            1,
        )
        .unwrap();
        assert_eq!(map.get("host"), Some(1));
        let data = map.data();
        insta::assert_yaml_snapshot!(data, @r###"
        host:
          "127.0.0.1:1": user1
        "###);
        map.remove("host", &"127.0.0.1:1".parse().unwrap());
        assert_eq!(map.get("host"), None);
        let data = map.data();
        assert!(data.is_empty());
    }

    #[test]
    fn removes_all_handlers_from_address() {
        let mut mock_reactor = MockConnectionMapReactor::new();
        mock_reactor.expect_call().times(3).returning(|_| {});
        let mut mock_quota = MockQuotaHandler::new();
        mock_quota.expect_get_token().times(2).returning(|_| {
            DummyQuotaHandler.get_token(TokenHolder::Admin(UserIdentification::Username("".into())))
        });
        let map = ConnectionMap::<String, usize, _>::new(
            LoadBalancing::Allow,
            Arc::new(Box::new(mock_quota)),
            Some(mock_reactor),
        );
        map.insert(
            "host1".into(),
            "127.0.0.1:2".parse().unwrap(),
            TokenHolder::User(UserIdentification::Username("user1".into())),
            1,
        )
        .unwrap();
        map.insert(
            "host2".into(),
            "127.0.0.1:2".parse().unwrap(),
            TokenHolder::User(UserIdentification::Username("user2".into())),
            2,
        )
        .unwrap();
        assert_eq!(map.get("host1"), Some(1));
        assert_eq!(map.get("host2"), Some(2));
        let data = map.data();
        insta::assert_yaml_snapshot!(data, @r###"
        host1:
          "127.0.0.1:2": user1
        host2:
          "127.0.0.1:2": user2
        "###);
        map.remove_by_address(&"127.0.0.1:2".parse().unwrap());
        assert_eq!(map.get("host1"), None);
        assert_eq!(map.get("host2"), None);
        let data = map.data();
        assert!(data.is_empty());
    }

    #[test]
    fn removes_only_handlers_from_specific_address() {
        let mut mock_reactor = MockConnectionMapReactor::new();
        mock_reactor.expect_call().times(4).returning(|_| {});
        let mut mock_quota = MockQuotaHandler::new();
        mock_quota.expect_get_token().times(4).returning(|_| {
            DummyQuotaHandler.get_token(TokenHolder::Admin(UserIdentification::Username("".into())))
        });
        let map = ConnectionMap::<String, usize, _>::new(
            LoadBalancing::Allow,
            Arc::new(Box::new(mock_quota)),
            Some(mock_reactor),
        );
        map.insert(
            "host1".into(),
            "127.0.0.1:2".parse().unwrap(),
            TokenHolder::User(UserIdentification::Username("user1".into())),
            1,
        )
        .unwrap();
        map.insert(
            "host2".into(),
            "127.0.0.1:2".parse().unwrap(),
            TokenHolder::User(UserIdentification::Username("user1".into())),
            2,
        )
        .unwrap();
        map.insert(
            "host2".into(),
            "127.0.0.1:3".parse().unwrap(),
            TokenHolder::User(UserIdentification::Username("user2".into())),
            3,
        )
        .unwrap();
        map.insert(
            "host3".into(),
            "127.0.0.1:3".parse().unwrap(),
            TokenHolder::User(UserIdentification::Username("user2".into())),
            4,
        )
        .unwrap();
        map.remove_by_address(&"127.0.0.1:2".parse().unwrap());
        assert_eq!(map.get("host1"), None);
        assert_eq!(map.get("host2"), Some(3));
        assert_eq!(map.get("host3"), Some(4));
        let data = map.data();
        insta::assert_yaml_snapshot!(data, @r###"
        host2:
          "127.0.0.1:3": user2
        host3:
          "127.0.0.1:3": user2
        "###);
    }

    #[test]
    fn returns_none_for_missing_host() {
        let mut mock_reactor = MockConnectionMapReactor::new();
        mock_reactor.expect_call().times(2).returning(|_| {});
        let mut mock_quota = MockQuotaHandler::new();
        mock_quota.expect_get_token().times(2).returning(|_| {
            DummyQuotaHandler.get_token(TokenHolder::Admin(UserIdentification::Username("".into())))
        });
        let map = ConnectionMap::<String, usize, _>::new(
            LoadBalancing::Allow,
            Arc::new(Box::new(mock_quota)),
            Some(mock_reactor),
        );
        map.insert(
            "host".into(),
            "127.0.0.1:1".parse().unwrap(),
            TokenHolder::User(UserIdentification::Username("user1".into())),
            1,
        )
        .unwrap();
        map.insert(
            "other".into(),
            "127.0.0.1:2".parse().unwrap(),
            TokenHolder::User(UserIdentification::Username("user2".into())),
            2,
        )
        .unwrap();
        assert_eq!(map.get("unknown"), None);
    }

    #[test]
    fn returns_one_of_several_load_balanced_handlers() {
        let mut mock_reactor = MockConnectionMapReactor::new();
        mock_reactor
            .expect_call()
            .times(1)
            .with(eq(vec![String::from("host")]))
            .returning(|_| {});
        let mut mock_quota = MockQuotaHandler::new();
        mock_quota.expect_get_token().times(3).returning(|_| {
            DummyQuotaHandler.get_token(TokenHolder::Admin(UserIdentification::Username("".into())))
        });
        let map = ConnectionMap::<String, usize, _>::new(
            LoadBalancing::Allow,
            Arc::new(Box::new(mock_quota)),
            Some(mock_reactor),
        );
        map.insert(
            "host".into(),
            "127.0.0.1:1".parse().unwrap(),
            TokenHolder::User(UserIdentification::Username("user1".into())),
            1,
        )
        .unwrap();
        map.insert(
            "host".into(),
            "127.0.0.1:2".parse().unwrap(),
            TokenHolder::User(UserIdentification::Username("user2".into())),
            2,
        )
        .unwrap();
        map.insert(
            "host".into(),
            "127.0.0.1:3".parse().unwrap(),
            TokenHolder::User(UserIdentification::Username("user3".into())),
            3,
        )
        .unwrap();
        let mut results: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
        for _ in 0..10_000 {
            let map_item = map.get("host");
            match map_item {
                Some(key @ 1) | Some(key @ 2) | Some(key @ 3) => {
                    *results.entry(key).or_default() += 1;
                }
                unknown => panic!("Unexpected {:?}", unknown),
            }
        }
        assert_eq!(results.len(), 3);
        assert_eq!(
            results.into_iter().fold(0usize, |acc, (_, i)| acc + i),
            10_000
        );
        let data = map.data();
        insta::assert_yaml_snapshot!(data, @r###"
        host:
          "127.0.0.1:1": user1
          "127.0.0.1:2": user2
          "127.0.0.1:3": user3
        "###);
        map.remove("host", &"127.0.0.1:2".parse().unwrap());
        let mut results: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
        for _ in 0..10_000 {
            let map_item = map.get("host");
            match map_item {
                Some(key @ 1) | Some(key @ 3) => {
                    *results.entry(key).or_default() += 1;
                }
                unknown => panic!("Unexpected {:?}", unknown),
            }
        }
        assert_eq!(results.len(), 2);
        assert_eq!(
            results.into_iter().fold(0usize, |acc, (_, i)| acc + i),
            10_000
        );
        let data = map.data();
        insta::assert_yaml_snapshot!(data, @r###"
        host:
          "127.0.0.1:1": user1
          "127.0.0.1:3": user3
        "###);
    }

    #[test]
    fn returns_single_host_when_replacing() {
        let mut mock_reactor = MockConnectionMapReactor::new();
        mock_reactor.expect_call().times(1).returning(|_| {});
        let mut mock_quota = MockQuotaHandler::new();
        mock_quota.expect_get_token().times(2).returning(|_| {
            DummyQuotaHandler.get_token(TokenHolder::Admin(UserIdentification::Username("".into())))
        });
        let map = ConnectionMap::<String, usize, _>::new(
            LoadBalancing::Replace,
            Arc::new(Box::new(mock_quota)),
            Some(mock_reactor),
        );
        map.insert(
            "host".into(),
            "127.0.0.1:1".parse().unwrap(),
            TokenHolder::User(UserIdentification::Username("user1".into())),
            1,
        )
        .unwrap();
        map.insert(
            "host".into(),
            "127.0.0.1:2".parse().unwrap(),
            TokenHolder::User(UserIdentification::Username("user2".into())),
            2,
        )
        .unwrap();
        for _ in 0..1_000 {
            assert_eq!(map.get("host"), Some(2));
        }
        let data = map.data();
        insta::assert_yaml_snapshot!(data, @r###"
        host:
          "127.0.0.1:2": user2
        "###);
    }

    #[test]
    fn errors_when_rejecting_new_host() {
        let mut mock_reactor = MockConnectionMapReactor::new();
        mock_reactor.expect_call().times(1).returning(|_| {});
        let mut mock_quota = MockQuotaHandler::new();
        mock_quota.expect_get_token().once().returning(|_| {
            DummyQuotaHandler.get_token(TokenHolder::Admin(UserIdentification::Username("".into())))
        });
        let map = ConnectionMap::<String, usize, _>::new(
            LoadBalancing::Deny,
            Arc::new(Box::new(mock_quota)),
            Some(mock_reactor),
        );
        map.insert(
            "host".into(),
            "127.0.0.1:1".parse().unwrap(),
            TokenHolder::User(UserIdentification::Username("user1".into())),
            1,
        )
        .unwrap();
        assert!(
            map.insert(
                "host".into(),
                "127.0.0.1:2".parse().unwrap(),
                TokenHolder::User(UserIdentification::Username("user2".into())),
                2
            )
            .is_err(),
            "shouldn't be allowed to add connection with deny policy"
        );
        for _ in 0..1_000 {
            assert_eq!(map.get("host"), Some(1));
        }
        let data = map.data();
        insta::assert_yaml_snapshot!(data, @r###"
        host:
          "127.0.0.1:1": user1
        "###);
    }

    #[test]
    fn reaching_quota_limits_load_balancing() {
        let mut mock_reactor = MockConnectionMapReactor::new();
        mock_reactor
            .expect_call()
            .times(1)
            .with(eq(vec![String::from("host")]))
            .returning(|_| {});
        let mut mock_quota = MockQuotaHandler::new();
        let mut quota_count = 0usize;
        mock_quota
            .expect_get_token()
            .times(3)
            .returning(move |holder| {
                assert_eq!(
                    holder,
                    TokenHolder::User(UserIdentification::Username("user1".into()))
                );
                if quota_count < 2 {
                    quota_count += 1;
                    DummyQuotaHandler
                        .get_token(TokenHolder::Admin(UserIdentification::Username("".into())))
                } else {
                    None
                }
            });
        let map = ConnectionMap::<String, usize, _>::new(
            LoadBalancing::Allow,
            Arc::new(Box::new(mock_quota)),
            Some(mock_reactor),
        );
        // Accepted and added
        map.insert(
            "host".into(),
            "127.0.0.1:1".parse().unwrap(),
            TokenHolder::User(UserIdentification::Username("user1".into())),
            1,
        )
        .unwrap();
        // Accepted and load-balanced
        map.insert(
            "host".into(),
            "127.0.0.1:2".parse().unwrap(),
            TokenHolder::User(UserIdentification::Username("user1".into())),
            2,
        )
        .unwrap();
        // Denied by quota
        assert!(
            map.insert(
                "host".into(),
                "127.0.0.1:3".parse().unwrap(),
                TokenHolder::User(UserIdentification::Username("user1".into())),
                3,
            )
            .is_err(),
            "shouldn't be allowed to add connection denied by quota"
        );
        let mut results: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
        for _ in 0..10_000 {
            let map_item = map.get("host");
            match map_item {
                Some(key @ 1) | Some(key @ 2) => {
                    *results.entry(key).or_default() += 1;
                }
                unknown => panic!("Unexpected {:?}", unknown),
            }
        }
        assert_eq!(results.len(), 2);
        assert_eq!(
            results.into_iter().fold(0usize, |acc, (_, i)| acc + i),
            10_000
        );
        let data = map.data();
        insta::assert_yaml_snapshot!(data, @r###"
        host:
          "127.0.0.1:1": user1
          "127.0.0.1:2": user1
        "###);
    }

    #[test]
    fn reaching_quota_prevents_replacing() {
        let mut mock_reactor = MockConnectionMapReactor::new();
        mock_reactor.expect_call().times(1).returning(|_| {});
        let mut mock_quota = MockQuotaHandler::new();
        let mut quota_count = 0usize;
        mock_quota
            .expect_get_token()
            .times(2)
            .returning(move |holder| {
                assert_eq!(
                    holder,
                    TokenHolder::User(UserIdentification::Username("user1".into()))
                );
                if quota_count < 1 {
                    quota_count += 1;
                    DummyQuotaHandler
                        .get_token(TokenHolder::Admin(UserIdentification::Username("".into())))
                } else {
                    None
                }
            });
        let map = ConnectionMap::<String, usize, _>::new(
            LoadBalancing::Replace,
            Arc::new(Box::new(mock_quota)),
            Some(mock_reactor),
        );
        // Accepted and added
        map.insert(
            "host".into(),
            "127.0.0.1:1".parse().unwrap(),
            TokenHolder::User(UserIdentification::Username("user1".into())),
            1,
        )
        .unwrap();
        // Denied by quota
        assert!(
            map.insert(
                "host".into(),
                "127.0.0.1:2".parse().unwrap(),
                TokenHolder::User(UserIdentification::Username("user1".into())),
                2,
            )
            .is_err(),
            "shouldn't be allowed to add connection denied by quota"
        );
        for _ in 0..1_000 {
            assert_eq!(map.get("host"), Some(1));
        }
        let data = map.data();
        insta::assert_yaml_snapshot!(data, @r###"
        host:
          "127.0.0.1:1": user1
        "###);
    }

    #[test]
    fn reaching_quota_doesnt_deny_by_policy() {
        let mut mock_reactor = MockConnectionMapReactor::new();
        mock_reactor.expect_call().times(1).returning(|_| {});
        let mut mock_quota = MockQuotaHandler::new();
        let mut quota_count = 0usize;
        mock_quota
            .expect_get_token()
            .times(2)
            .returning(move |holder| {
                assert_eq!(
                    holder,
                    TokenHolder::User(UserIdentification::Username("user1".into()))
                );
                if quota_count < 1 {
                    quota_count += 1;
                    None
                } else {
                    DummyQuotaHandler
                        .get_token(TokenHolder::Admin(UserIdentification::Username("".into())))
                }
            });
        let map = ConnectionMap::<String, usize, _>::new(
            LoadBalancing::Deny,
            Arc::new(Box::new(mock_quota)),
            Some(mock_reactor),
        );
        // Denied by quota
        assert!(
            map.insert(
                "host".into(),
                "127.0.0.1:1".parse().unwrap(),
                TokenHolder::User(UserIdentification::Username("user1".into())),
                1,
            )
            .is_err(),
            "shouldn't be allowed to add connection denied by quota"
        );
        // Accepted
        map.insert(
            "host".into(),
            "127.0.0.1:2".parse().unwrap(),
            TokenHolder::User(UserIdentification::Username("user1".into())),
            2,
        )
        .unwrap();
        // Denied by policy (shouldn't invoke quota handler)
        assert!(
            map.insert(
                "host".into(),
                "127.0.0.1:3".parse().unwrap(),
                TokenHolder::User(UserIdentification::Username("user1".into())),
                3
            )
            .is_err(),
            "shouldn't be allowed to add connection with deny policy"
        );
        for _ in 0..1_000 {
            assert_eq!(map.get("host"), Some(2));
        }
        let data = map.data();
        insta::assert_yaml_snapshot!(data, @r###"
        host:
          "127.0.0.1:2": user1
        "###);
    }
}
