use std::{
    borrow::Borrow,
    collections::{BTreeMap, BTreeSet},
    hash::Hash,
    net::SocketAddr,
    sync::RwLock,
};

use dashmap::DashMap;
#[cfg(test)]
use mockall::automock;
use rand::seq::SliceRandom;

use crate::{config::LoadBalancing, error::ServerError};

#[cfg_attr(test, automock)]
pub(crate) trait ConnectionMapReactor<K> {
    fn call(&self, identifiers: Vec<K>);
}

pub(crate) struct DummyConnectionMapReactor;

impl<K> ConnectionMapReactor<K> for DummyConnectionMapReactor {
    fn call(&self, _: Vec<K>) {}
}

struct ConnectionMapEntry<H> {
    address: SocketAddr,
    handler: H,
}

pub(crate) struct ConnectionMap<K, H, R = DummyConnectionMapReactor> {
    load_balancing: LoadBalancing,
    map: DashMap<K, Vec<ConnectionMapEntry<H>>>,
    reactor: RwLock<Option<R>>,
}

impl<K, H, R> ConnectionMap<K, H, R>
where
    K: Eq + Hash + Clone + Ord + PartialOrd,
    H: Clone,
    R: ConnectionMapReactor<K> + Send + 'static,
{
    pub(crate) fn new(load_balancing: LoadBalancing, reactor: Option<R>) -> Self {
        ConnectionMap {
            load_balancing,
            map: DashMap::new(),
            reactor: RwLock::new(reactor),
        }
    }

    pub(crate) fn insert(&self, key: K, address: SocketAddr, handler: H) -> anyhow::Result<()> {
        let len = self.map.len();
        match self.load_balancing {
            LoadBalancing::Allow => {
                self.map
                    .entry(key)
                    .or_default()
                    .push(ConnectionMapEntry { address, handler });
            }
            LoadBalancing::Replace => {
                self.map
                    .insert(key, vec![ConnectionMapEntry { address, handler }]);
            }
            LoadBalancing::Deny => {
                if self.map.contains_key(&key) {
                    Err(ServerError::LoadBalancingAlreadyBound)?;
                }
                self.map
                    .insert(key, vec![ConnectionMapEntry { address, handler }]);
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
            value.is_empty()
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

    pub(crate) fn data(&self) -> BTreeMap<K, BTreeSet<SocketAddr>> {
        self.map
            .iter()
            .map(|entry| {
                (
                    entry.key().clone(),
                    entry
                        .value()
                        .iter()
                        .map(|ConnectionMapEntry { address, .. }| address)
                        .copied()
                        .collect(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod connection_map_tests {
    use mockall::predicate::eq;

    use crate::config::LoadBalancing;

    use super::{ConnectionMap, MockConnectionMapReactor};

    #[test]
    fn inserts_and_removes_one_handler() {
        let mut mock = MockConnectionMapReactor::new();
        mock.expect_call().times(2).returning(|_| {});
        let map = ConnectionMap::<String, usize, _>::new(LoadBalancing::Allow, Some(mock));
        map.insert("host".into(), "127.0.0.1:1".parse().unwrap(), 1)
            .unwrap();
        assert_eq!(map.get("host"), Some(1));
        map.remove("host", &"127.0.0.1:1".parse().unwrap());
        assert_eq!(map.get("host"), None);
    }

    #[test]
    fn removes_all_handlers_from_address() {
        let mut mock = MockConnectionMapReactor::new();
        mock.expect_call().times(2).returning(|_| {});
        let map = ConnectionMap::<String, usize, _>::new(LoadBalancing::Allow, Some(mock));
        map.insert("host1".into(), "127.0.0.1:2".parse().unwrap(), 1)
            .unwrap();
        map.insert("host2".into(), "127.0.0.1:2".parse().unwrap(), 2)
            .unwrap();
        assert_eq!(map.get("host1"), Some(1));
        assert_eq!(map.get("host2"), Some(2));
        map.remove_by_address(&"127.0.0.1:2".parse().unwrap());
        assert_eq!(map.get("host1"), None);
        assert_eq!(map.get("host2"), None);
    }

    #[test]
    fn returns_none_for_missing_host() {
        let mut mock = MockConnectionMapReactor::new();
        mock.expect_call().times(2).returning(|_| {});
        let map = ConnectionMap::<String, usize, _>::new(LoadBalancing::Allow, Some(mock));
        map.insert("host".into(), "127.0.0.1:1".parse().unwrap(), 1)
            .unwrap();
        map.insert("other".into(), "127.0.0.1:2".parse().unwrap(), 2)
            .unwrap();
        assert_eq!(map.get("unknown"), None);
    }

    #[test]
    fn returns_one_of_several_load_balanced_handlers() {
        let mut mock = MockConnectionMapReactor::new();
        mock.expect_call()
            .times(1)
            .with(eq(vec![String::from("host")]))
            .returning(|_| {});
        let map = ConnectionMap::<String, usize, _>::new(LoadBalancing::Allow, Some(mock));
        map.insert("host".into(), "127.0.0.1:1".parse().unwrap(), 1)
            .unwrap();
        map.insert("host".into(), "127.0.0.1:2".parse().unwrap(), 2)
            .unwrap();
        map.insert("host".into(), "127.0.0.1:3".parse().unwrap(), 3)
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
    }

    #[test]
    fn returns_single_host_when_replacing() {
        let mut mock = MockConnectionMapReactor::new();
        mock.expect_call().times(1).returning(|_| {});
        let map = ConnectionMap::<String, usize, _>::new(LoadBalancing::Replace, Some(mock));
        map.insert("host".into(), "127.0.0.1:1".parse().unwrap(), 1)
            .unwrap();
        map.insert("host".into(), "127.0.0.1:2".parse().unwrap(), 2)
            .unwrap();
        for _ in 0..1_000 {
            assert_eq!(map.get("host"), Some(2));
        }
    }

    #[test]
    fn errors_when_rejecting_new_host() {
        let mut mock = MockConnectionMapReactor::new();
        mock.expect_call().times(1).returning(|_| {});
        let map = ConnectionMap::<String, usize, _>::new(LoadBalancing::Deny, Some(mock));
        map.insert("host".into(), "127.0.0.1:1".parse().unwrap(), 1)
            .unwrap();
        assert!(map
            .insert("host".into(), "127.0.0.1:2".parse().unwrap(), 2)
            .is_err());
        for _ in 0..1_000 {
            assert_eq!(map.get("host"), Some(1));
        }
    }
}
