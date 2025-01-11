use std::{
    borrow::Borrow,
    collections::BTreeMap,
    hash::Hash,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use dashmap::DashMap;
use rand::{seq::SliceRandom, thread_rng};

use crate::{
    config::LoadBalancing,
    error::ServerError,
    quota::{QuotaHandler, QuotaToken, TokenHolder},
    reactor::{AliasReactor, ConnectionMapReactor, DummyConnectionMapReactor, HttpReactor},
    ssh::SshTunnelHandler,
    tcp_alias::{BorrowedTcpAlias, TcpAlias, TcpAliasKey},
};

// Data stored for a connection map entry.
struct ConnectionMapEntry<H> {
    // The user that created this connection.
    user: String,
    // The IP and socket for the SSH connection.
    address: SocketAddr,
    // Handler randomly selected for a given key (usually SshTunnelHandler).
    handler: H,
    // Quota token for the user, to limit their maximum amount of connections.
    _token: QuotaToken,
}

// Map that stores handlers to be randomly selected and returned.
pub(crate) struct ConnectionMap<K, H, R = DummyConnectionMapReactor> {
    // Policy on how to handle new services getting added to this map.
    load_balancing: LoadBalancing,
    // The actual data structure storing connections, selected by key.
    map: DashMap<K, Vec<ConnectionMapEntry<H>>>,
    // Service to generate new QuotaTokens.
    quota_handler: Arc<Box<dyn QuotaHandler + Send + Sync>>,
    // Optional callable to send data to when the list of connection keys changes.
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

    // Add an entry to this map.
    // This may fail if the LoadBalancing::Deny policy is in place, and an entry already exists for the given key.
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
            // Add this entry to the list of possible handlers returned for this key.
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
            // Replace the existing handler entry if it exists.
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
            // Reject the new handler if an entry already exists.
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
        // If the entry count increased, notify the reactor.
        if self.map.len() > len {
            if let Some(reactor) = self.reactor.read().unwrap().as_ref() {
                reactor.call(self.map.iter().map(|entry| entry.key().clone()).collect())
            }
        }
        Ok(())
    }

    // Return a random handler for the given key.
    pub(crate) fn get<Q>(&self, key: &Q) -> Option<H>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.get(key).and_then(|handler| {
            handler
                .value()
                .as_slice()
                .choose(&mut thread_rng())
                .map(|ConnectionMapEntry { handler, .. }| Clone::clone(handler))
        })
    }

    // Remove the handler under the given key and SSH connection address.
    // Called when the client closes a remote forwarding session.
    pub(crate) fn remove<Q>(&self, key: &Q, address: &SocketAddr) -> Option<(K, H)>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let len = self.map.len();
        let mut element = None;
        // Find the entry and store it under the element variable if it exists.
        self.map.remove_if_mut(key, |inner_key, value| {
            let mut i = 0;
            while i < value.len() {
                if value[i].address == *address {
                    element = Some((inner_key.clone(), value.swap_remove(i).handler));
                    break;
                }
                i += 1;
            }
            // If the entry is empty, remove it
            value.is_empty()
        });
        // If the entry was removed, notify the reactor.
        if self.map.len() < len {
            if let Some(reactor) = self.reactor.read().unwrap().as_ref() {
                reactor.call(self.map.iter().map(|entry| entry.key().clone()).collect())
            }
        }
        element
    }

    // Remove every handler under the given SSH connection address.
    // Called when the client disconnects, or when HTTP connections are flushed to TCP alias connections.
    pub(crate) fn remove_by_address(&self, address: &SocketAddr) -> Vec<(K, H)> {
        let len = self.map.len();
        let mut elements = Vec::new();
        // Find the entries with the address and store them in the elements Vec.
        self.map.retain(|key, value| {
            let mut i = 0;
            while i < value.len() {
                if value[i].address == *address {
                    elements.push((key.clone(), value.swap_remove(i).handler));
                    break;
                }
                i += 1;
            }
            // If the entries are empty, remove them
            !value.is_empty()
        });
        // If one or more entries were removed, notify the reactor.
        if self.map.len() < len {
            if let Some(reactor) = self.reactor.read().unwrap().as_ref() {
                reactor.call(self.map.iter().map(|entry| entry.key().clone()).collect())
            }
        }
        elements
    }

    // Update the reactor value.
    // This should only be called near the connection map's initialization, not during its lifetime.
    pub(crate) fn update_reactor(&self, reactor: Option<R>) {
        *self.reactor.write().unwrap() = reactor;
    }

    // Return tabular data from all the existing connections.
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

// Helper trait for getting HTTP-specific entries via the hostname.
pub(crate) trait ConnectionGetByHttpHost<H> {
    fn get_by_http_host(&self, host: &str) -> Option<H>;
}

impl<H, R> ConnectionGetByHttpHost<H> for Arc<ConnectionMap<String, H, R>>
where
    H: Clone,
    R: ConnectionMapReactor<String> + Send + 'static,
{
    fn get_by_http_host(&self, host: &str) -> Option<H> {
        self.get(host)
    }
}

// Struct that can select HTTP hosts from HTTP forwardings or TCP alias forwardings under port 80.
pub(crate) struct HttpAliasingConnection {
    http: Arc<ConnectionMap<String, Arc<SshTunnelHandler>, HttpReactor>>,
    alias: Arc<ConnectionMap<TcpAlias, Arc<SshTunnelHandler>, AliasReactor>>,
}

impl HttpAliasingConnection {
    pub(crate) fn new(
        http: Arc<ConnectionMap<String, Arc<SshTunnelHandler>, HttpReactor>>,
        tcp: Arc<ConnectionMap<TcpAlias, Arc<SshTunnelHandler>, AliasReactor>>,
    ) -> Self {
        HttpAliasingConnection { http, alias: tcp }
    }
}

impl ConnectionGetByHttpHost<Arc<SshTunnelHandler>> for Arc<HttpAliasingConnection> {
    fn get_by_http_host(&self, host: &str) -> Option<Arc<SshTunnelHandler>> {
        self.http.get(host).or_else(|| {
            self.alias
                .get(&BorrowedTcpAlias(host, &80) as &dyn TcpAliasKey)
        })
    }
}

#[cfg(test)]
mod connection_map_tests {
    use std::sync::Arc;

    use mockall::predicate::eq;

    use crate::{
        config::LoadBalancing,
        quota::{get_test_token, MockQuotaHandler, TokenHolder, UserIdentification},
        reactor::MockConnectionMapReactor,
    };

    use super::ConnectionMap;

    #[test]
    fn inserts_and_removes_one_handler() {
        let mut mock_reactor = MockConnectionMapReactor::new();
        mock_reactor.expect_call().times(2).returning(|_| {});
        let mut mock_quota = MockQuotaHandler::new();
        mock_quota
            .expect_get_token()
            .once()
            .returning(|_| Some(get_test_token()));
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
        mock_quota
            .expect_get_token()
            .times(2)
            .returning(|_| Some(get_test_token()));
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
        mock_quota
            .expect_get_token()
            .times(4)
            .returning(|_| Some(get_test_token()));
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
        mock_quota
            .expect_get_token()
            .times(2)
            .returning(|_| Some(get_test_token()));
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
        mock_quota
            .expect_get_token()
            .times(3)
            .returning(|_| Some(get_test_token()));
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
        mock_quota
            .expect_get_token()
            .times(2)
            .returning(|_| Some(get_test_token()));
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
        mock_quota
            .expect_get_token()
            .once()
            .returning(|_| Some(get_test_token()));
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
                    Some(get_test_token())
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
                    Some(get_test_token())
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
                    Some(get_test_token())
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
