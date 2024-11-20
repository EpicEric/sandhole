use std::{borrow::Borrow, hash::Hash, net::SocketAddr};

use dashmap::DashMap;
#[cfg(test)]
use mockall::automock;
use rand::seq::SliceRandom;

#[cfg_attr(test, automock)]
pub(crate) trait ConnectionMapReactor<K> {
    fn call(&self, identifiers: Vec<K>);
}

pub(crate) struct DummyConnectionMapReactor;

impl<K> ConnectionMapReactor<K> for DummyConnectionMapReactor {
    fn call(&self, _: Vec<K>) {}
}

pub(crate) struct ConnectionMap<K, H, R> {
    map: DashMap<K, Vec<(SocketAddr, H)>>,
    reactor: Option<R>,
}

impl<K, H, R> ConnectionMap<K, H, R>
where
    K: Eq + Hash + Clone,
    H: Clone,
    R: ConnectionMapReactor<K> + Send + 'static,
{
    pub(crate) fn new(reactor: Option<R>) -> Self {
        ConnectionMap {
            map: DashMap::new(),
            reactor,
        }
    }

    pub(crate) fn insert(&self, host: K, addr: SocketAddr, handler: H) {
        let len = self.map.len();
        self.map.entry(host).or_default().push((addr, handler));
        if self.map.len() > len {
            if let Some(reactor) = self.reactor.as_ref() {
                reactor.call(self.map.iter().map(|entry| entry.key().clone()).collect())
            }
        }
    }

    pub(crate) fn get<Q>(&self, host: &Q) -> Option<H>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let mut rng = rand::thread_rng();
        self.map.get(host).and_then(|handler| {
            handler
                .value()
                .as_slice()
                .choose(&mut rng)
                .map(|(_, handler)| Clone::clone(handler))
        })
    }

    pub(crate) fn remove<Q>(&self, host: &Q, addr: SocketAddr)
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let len = self.map.len();
        self.map.remove_if_mut(host, |_, value| {
            value.retain(|(address, _)| *address != addr);
            value.is_empty()
        });
        if self.map.len() < len {
            if let Some(reactor) = self.reactor.as_ref() {
                reactor.call(self.map.iter().map(|entry| entry.key().clone()).collect())
            }
        }
    }
}

#[cfg(test)]
mod connection_map_tests {
    use mockall::predicate::eq;

    use super::{ConnectionMap, MockConnectionMapReactor};

    #[test]
    fn inserts_and_removes_one_handler() {
        let mut mock = MockConnectionMapReactor::new();
        mock.expect_call().times(2).returning(|_| {});
        let map = ConnectionMap::<String, usize, _>::new(Some(mock));
        map.insert("host".into(), "127.0.0.1:1".parse().unwrap(), 1);
        assert_eq!(map.get("host"), Some(1));
        map.remove("host", "127.0.0.1:1".parse().unwrap());
        assert_eq!(map.get("host"), None);
    }

    #[test]
    fn returns_none_for_missing_host() {
        let mut mock = MockConnectionMapReactor::new();
        mock.expect_call().times(2).returning(|_| {});
        let map = ConnectionMap::<String, usize, _>::new(Some(mock));
        map.insert("host".into(), "127.0.0.1:1".parse().unwrap(), 1);
        map.insert("other".into(), "127.0.0.1:2".parse().unwrap(), 2);
        assert_eq!(map.get("unknown"), None);
    }

    #[test]
    fn returns_one_of_several_handlers() {
        let mut mock = MockConnectionMapReactor::new();
        mock.expect_call()
            .times(1)
            .with(eq(vec![String::from("host")]))
            .returning(|_| {});
        let map = ConnectionMap::<String, usize, _>::new(Some(mock));
        map.insert("host".into(), "127.0.0.1:1".parse().unwrap(), 1);
        map.insert("host".into(), "127.0.0.1:2".parse().unwrap(), 2);
        map.insert("host".into(), "127.0.0.1:3".parse().unwrap(), 3);
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
}
