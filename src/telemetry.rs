use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::{Duration, Instant},
};

use dashmap::DashMap;

use crate::tcp_alias::TcpAlias;

// A value that increases with time.
struct Counter {
    // The history of the value across several instants.
    history: VecDeque<(Instant, u64)>,
    // The sliding window of values to consider.
    window: Duration,
    // The period as a correction factor over the sliding window.
    // This will divide the count in order to return the rate over time.
    period: f64,
    // The current value.
    count: u64,
}

impl Counter {
    fn new(window: Duration, interval: Duration) -> Self {
        debug_assert!(window >= interval);
        Counter {
            history: [(Instant::now(), 0)].into_iter().collect(),
            period: window.as_secs_f64() / interval.as_secs_f64(),
            window,
            count: 0,
        }
    }

    // Add some amount to the given counter.
    fn add(&mut self, value: u64) {
        loop {
            let Some(element) = self.history.front() else {
                break;
            };
            // Remove elements at the front if they are too old.
            if element.0.elapsed() >= self.window {
                // Don't remove the first element if it is the last one.
                // Instead, update its instant.
                // This ensures that the first call to add is counted.
                if self.history.len() == 1 {
                    self.history.front_mut().unwrap().0 = Instant::now();
                    break;
                } else {
                    self.history.pop_front();
                }
            } else {
                break;
            }
        }
        self.count += value;
    }

    // Measure the counter, taking the period and window into account.
    fn measure(&mut self) -> f64 {
        let delta = loop {
            // If there are no elements in the history, return the current count.
            let Some(element) = self.history.front() else {
                break self.count;
            };
            // If the count hasn't changed, return the current count (rate will be 0).
            if element.1 == self.count {
                self.history.pop_front();
                break self.count;
            // The count has changed; if within window, return the front element.
            } else if element.0.elapsed() < self.window {
                break element.1;
            // Element is no longer within window; remove from history.
            } else {
                self.history.pop_front();
            }
        };
        // If the last element has a different count value, add the current count to the end.
        if let Some(element) = self.history.back() {
            if element.1 != self.count {
                self.history.push_back((Instant::now(), self.count));
            }
        // Also add the current count to the end if the history is empty.
        } else {
            self.history.push_back((Instant::now(), self.count));
        }
        (self.count - delta) as f64 / self.period
    }
}

#[cfg(test)]
mod counter_tests {
    use std::{thread::sleep, time::Duration};

    use super::Counter;

    #[test]
    fn takes_measurements() {
        let mut counter = Counter::new(Duration::from_secs(4), Duration::from_secs(1));
        assert_eq!(counter.measure(), 0.0);
        counter.add(8);
        let measure_1 = counter.measure();
        assert_eq!(measure_1, 2.0);
        counter.add(8);
        let measure_2 = counter.measure();
        assert_eq!(measure_2, 4.0);
    }

    #[test]
    fn resets_on_moving_window() {
        let mut counter = Counter::new(Duration::from_millis(1_000), Duration::from_millis(200));
        counter.add(10);
        let measure_1 = counter.measure();
        sleep(Duration::from_millis(1_000));
        counter.add(10);
        let measure_2 = counter.measure();
        assert_eq!(measure_2, measure_1);
    }
}

// Metadata to display on the admin interface.
pub(crate) struct Telemetry {
    // Connections per minute for each SSH alias.
    ssh_connections_per_minute: DashMap<String, Counter>,
    // Requests per minute for each HTTP host.
    http_requests_per_minute: DashMap<String, Counter>,
    // Connections per minute for each TCP port.
    tcp_connections_per_minute: DashMap<u16, Counter>,
    // Connections per minute for each local-forwarded alias.
    alias_connections_per_minute: DashMap<TcpAlias, Counter>,
}

impl Telemetry {
    pub(crate) fn new() -> Self {
        Telemetry {
            ssh_connections_per_minute: DashMap::new(),
            http_requests_per_minute: DashMap::new(),
            tcp_connections_per_minute: DashMap::new(),
            alias_connections_per_minute: DashMap::new(),
        }
    }

    // Take into account an SSH connection to the given hostname.
    pub(crate) fn add_ssh_connection(&self, alias: String) {
        self.ssh_connections_per_minute
            .entry(alias)
            .or_insert_with(|| Counter::new(Duration::from_secs(120), Duration::from_secs(60)))
            .value_mut()
            .add(1);
    }

    // Take into account an HTTP request to the given hostname.
    pub(crate) fn add_http_request(&self, hostname: String) {
        self.http_requests_per_minute
            .entry(hostname)
            .or_insert_with(|| Counter::new(Duration::from_secs(120), Duration::from_secs(60)))
            .value_mut()
            .add(1);
    }

    // Take into account a TCP connection to the given port.
    pub(crate) fn add_tcp_connection(&self, port: u16) {
        self.tcp_connections_per_minute
            .entry(port)
            .or_insert_with(|| Counter::new(Duration::from_secs(120), Duration::from_secs(60)))
            .value_mut()
            .add(1);
    }

    // Take into account a local-forwarded connection to the given alias.
    pub(crate) fn add_alias_connection(&self, alias: TcpAlias) {
        self.alias_connections_per_minute
            .entry(alias)
            .or_insert_with(|| Counter::new(Duration::from_secs(120), Duration::from_secs(60)))
            .value_mut()
            .add(1);
    }

    // Return data on all SSH connections per minute.
    pub(crate) fn get_ssh_connections_per_minute(&self) -> HashMap<String, f64> {
        self.ssh_connections_per_minute
            .iter_mut()
            .map(|mut entry| {
                let measure = entry.value_mut().measure();
                (entry.key().clone(), measure)
            })
            .collect()
    }

    // Return data on all HTTP requests per minute.
    pub(crate) fn get_http_requests_per_minute(&self) -> HashMap<String, f64> {
        self.http_requests_per_minute
            .iter_mut()
            .map(|mut entry| {
                let measure = entry.value_mut().measure();
                (entry.key().clone(), measure)
            })
            .collect()
    }

    // Return data on all TCP connections per minute.
    pub(crate) fn get_tcp_connections_per_minute(&self) -> HashMap<u16, f64> {
        self.tcp_connections_per_minute
            .iter_mut()
            .map(|mut entry| {
                let measure = entry.value_mut().measure();
                (*entry.key(), measure)
            })
            .collect()
    }

    // Return data on all alias connections per minute.
    pub(crate) fn get_alias_connections_per_minute(&self) -> HashMap<TcpAlias, f64> {
        self.alias_connections_per_minute
            .iter_mut()
            .map(|mut entry| {
                let measure = entry.value_mut().measure();
                (entry.key().clone(), measure)
            })
            .collect()
    }

    pub(crate) fn ssh_reactor(&self, aliases: Vec<String>) {
        let aliases: HashSet<String> = aliases.into_iter().collect();
        self.ssh_connections_per_minute
            .retain(|key, _| aliases.contains(key));
    }

    pub(crate) fn http_reactor(&self, hostnames: Vec<String>) {
        let hostnames: HashSet<String> = hostnames.into_iter().collect();
        self.http_requests_per_minute
            .retain(|key, _| hostnames.contains(key));
    }

    pub(crate) fn tcp_reactor(&self, ports: Vec<u16>) {
        let ports: HashSet<u16> = ports.into_iter().collect();
        self.tcp_connections_per_minute
            .retain(|key, _| ports.contains(key));
    }

    pub(crate) fn alias_reactor(&self, aliases: Vec<TcpAlias>) {
        let aliases: HashSet<TcpAlias> = aliases.into_iter().collect();
        self.alias_connections_per_minute
            .retain(|key, _| aliases.contains(key));
    }
}

#[cfg(test)]
mod telemetry_tests {
    use std::sync::Arc;

    use crate::{
        tcp_alias::{BorrowedTcpAlias, TcpAliasKey},
        telemetry::TcpAlias,
    };

    use super::Telemetry;

    #[test]
    fn includes_data_for_connections_on_ssh_aliases() {
        let telemetry = Telemetry::new();
        assert!(
            telemetry.get_ssh_connections_per_minute().is_empty(),
            "shouldn't have data for newly created telemetry"
        );
        telemetry.add_ssh_connection("foo".into());
        telemetry.add_ssh_connection("bar".into());
        telemetry.add_ssh_connection("qux".into());
        telemetry.add_ssh_connection("qux".into());
        let data = telemetry.get_ssh_connections_per_minute();
        assert_eq!(data.len(), 3);
        assert_eq!(data.get("foo").unwrap(), data.get("bar").unwrap());
        assert_eq!(*data.get("qux").unwrap(), 2.0 * data.get("foo").unwrap());
    }

    #[test]
    fn retains_ssh_aliases_that_are_still_active() {
        let telemetry = Arc::new(Telemetry::new());
        telemetry.ssh_reactor(vec!["host1".into(), "host2".into(), "host3".into()]);
        let data = telemetry.get_ssh_connections_per_minute();
        assert!(
            data.is_empty(),
            "shouldn't have data for newly created telemetry"
        );
        telemetry.add_ssh_connection("host1".into());
        telemetry.add_ssh_connection("host3".into());
        telemetry.add_ssh_connection("host4".into());
        telemetry.ssh_reactor(vec!["host1".into(), "host4".into(), "host5".into()]);
        let data = telemetry.get_ssh_connections_per_minute();
        assert_eq!(data.len(), 2);
        assert!(
            *data.get("host1").unwrap() > 0.0,
            "should have data for host1"
        );
        assert!(
            *data.get("host4").unwrap() > 0.0,
            "should have data for host4"
        );
    }

    #[test]
    fn ssh_data_isnt_affected_by_other_connections() {
        let telemetry = Telemetry::new();
        assert!(
            telemetry.get_ssh_connections_per_minute().is_empty(),
            "shouldn't have data for newly created telemetry"
        );
        telemetry.add_http_request("http".into());
        telemetry.add_tcp_connection(12345);
        telemetry.add_alias_connection(TcpAlias("alias".into(), 42));
        assert!(
            telemetry.get_ssh_connections_per_minute().is_empty(),
            "shouldn't have data for unaffected telemetry"
        );
    }

    #[test]
    fn includes_data_for_requests_on_http_domains() {
        let telemetry = Telemetry::new();
        assert!(
            telemetry.get_http_requests_per_minute().is_empty(),
            "shouldn't have data for newly created telemetry"
        );
        telemetry.add_http_request("foo".into());
        telemetry.add_http_request("bar".into());
        telemetry.add_http_request("qux".into());
        telemetry.add_http_request("qux".into());
        let data = telemetry.get_http_requests_per_minute();
        assert_eq!(data.len(), 3);
        assert_eq!(data.get("foo").unwrap(), data.get("bar").unwrap());
        assert_eq!(*data.get("qux").unwrap(), 2.0 * data.get("foo").unwrap());
    }

    #[test]
    fn retains_http_hostnames_that_are_still_active() {
        let telemetry = Arc::new(Telemetry::new());
        telemetry.http_reactor(vec!["host1".into(), "host2".into(), "host3".into()]);
        let data = telemetry.get_http_requests_per_minute();
        assert!(
            data.is_empty(),
            "shouldn't have data for newly created telemetry"
        );
        telemetry.add_http_request("host1".into());
        telemetry.add_http_request("host3".into());
        telemetry.add_http_request("host4".into());
        telemetry.http_reactor(vec!["host1".into(), "host4".into(), "host5".into()]);
        let data = telemetry.get_http_requests_per_minute();
        assert_eq!(data.len(), 2);
        assert!(
            *data.get("host1").unwrap() > 0.0,
            "should have data for host1"
        );
        assert!(
            *data.get("host4").unwrap() > 0.0,
            "should have data for host4"
        );
    }

    #[test]
    fn http_data_isnt_affected_by_other_connections() {
        let telemetry = Telemetry::new();
        assert!(
            telemetry.get_http_requests_per_minute().is_empty(),
            "shouldn't have data for newly created telemetry"
        );
        telemetry.add_ssh_connection("ssh".into());
        telemetry.add_tcp_connection(12345);
        telemetry.add_alias_connection(TcpAlias("alias".into(), 42));
        assert!(
            telemetry.get_http_requests_per_minute().is_empty(),
            "shouldn't have data for unaffected telemetry"
        );
    }

    #[test]
    fn includes_data_for_connections_on_tcp_ports() {
        let telemetry = Telemetry::new();
        assert!(
            telemetry.get_tcp_connections_per_minute().is_empty(),
            "shouldn't have data for newly created telemetry"
        );
        telemetry.add_tcp_connection(1);
        telemetry.add_tcp_connection(2);
        telemetry.add_tcp_connection(3);
        telemetry.add_tcp_connection(3);
        let data = telemetry.get_tcp_connections_per_minute();
        assert_eq!(data.len(), 3);
        assert_eq!(data.get(&1).unwrap(), data.get(&2).unwrap());
        assert_eq!(*data.get(&3).unwrap(), 2.0 * data.get(&1).unwrap());
    }

    #[test]
    fn retains_tcp_ports_that_are_still_active() {
        let telemetry = Arc::new(Telemetry::new());
        telemetry.tcp_reactor(vec![1, 2, 3]);
        let data = telemetry.get_tcp_connections_per_minute();
        assert!(
            data.is_empty(),
            "shouldn't have data for newly created telemetry"
        );
        telemetry.add_tcp_connection(1);
        telemetry.add_tcp_connection(3);
        telemetry.add_tcp_connection(4);
        telemetry.tcp_reactor(vec![1, 4, 5]);
        let data = telemetry.get_tcp_connections_per_minute();
        assert_eq!(data.len(), 2);
        assert!(*data.get(&1).unwrap() > 0.0, "should have data for port 1");
        assert!(*data.get(&4).unwrap() > 0.0, "should have data for port 4");
    }

    #[test]
    fn tcp_data_isnt_affected_by_other_connections() {
        let telemetry = Telemetry::new();
        assert!(
            telemetry.get_tcp_connections_per_minute().is_empty(),
            "shouldn't have data for newly created telemetry"
        );
        telemetry.add_http_request("http".into());
        telemetry.add_ssh_connection("ssh".into());
        telemetry.add_alias_connection(TcpAlias("alias".into(), 42));
        assert!(
            telemetry.get_tcp_connections_per_minute().is_empty(),
            "shouldn't have data for unaffected telemetry"
        );
    }

    #[test]
    fn includes_data_for_connections_on_aliases() {
        let telemetry = Telemetry::new();
        assert!(
            telemetry.get_alias_connections_per_minute().is_empty(),
            "shouldn't have data for newly created telemetry"
        );
        telemetry.add_alias_connection(TcpAlias("foo".into(), 1234));
        telemetry.add_alias_connection(TcpAlias("bar".into(), 2345));
        telemetry.add_alias_connection(TcpAlias("qux".into(), 3456));
        telemetry.add_alias_connection(TcpAlias("qux".into(), 3456));
        let data = telemetry.get_alias_connections_per_minute();
        assert_eq!(data.len(), 3);
        assert_eq!(
            data.get(&BorrowedTcpAlias("foo", &1234) as &dyn TcpAliasKey)
                .unwrap(),
            data.get(&BorrowedTcpAlias("bar", &2345) as &dyn TcpAliasKey)
                .unwrap()
        );
        assert_eq!(
            *data
                .get(&BorrowedTcpAlias("qux", &3456) as &dyn TcpAliasKey)
                .unwrap(),
            2.0 * data
                .get(&BorrowedTcpAlias("foo", &1234) as &dyn TcpAliasKey)
                .unwrap()
        );
    }

    #[test]
    fn retains_aliases_that_are_still_active() {
        let telemetry = Arc::new(Telemetry::new());
        telemetry.alias_reactor(vec![
            TcpAlias("host1".into(), 1234),
            TcpAlias("host2".into(), 2345),
            TcpAlias("host3".into(), 3456),
        ]);
        let data = telemetry.get_alias_connections_per_minute();
        assert!(
            data.is_empty(),
            "shouldn't have data for newly created telemetry"
        );
        telemetry.add_alias_connection(TcpAlias("host1".into(), 1234));
        telemetry.add_alias_connection(TcpAlias("host3".into(), 3456));
        telemetry.add_alias_connection(TcpAlias("host4".into(), 4567));
        telemetry.alias_reactor(vec![
            TcpAlias("host1".into(), 1234),
            TcpAlias("host4".into(), 4567),
            TcpAlias("host5".into(), 5678),
        ]);
        let data = telemetry.get_alias_connections_per_minute();
        assert_eq!(data.len(), 2);
        assert!(
            *data
                .get(&BorrowedTcpAlias("host1", &1234) as &dyn TcpAliasKey)
                .unwrap()
                > 0.0,
            "should have data for host1"
        );
        assert!(
            *data
                .get(&BorrowedTcpAlias("host4", &4567) as &dyn TcpAliasKey)
                .unwrap()
                > 0.0,
            "should have data for host4"
        );
    }

    #[test]
    fn alias_data_isnt_affected_by_other_connections() {
        let telemetry = Telemetry::new();
        assert!(
            telemetry.get_alias_connections_per_minute().is_empty(),
            "shouldn't have data for newly created telemetry"
        );
        telemetry.add_ssh_connection("ssh".into());
        telemetry.add_http_request("http".into());
        telemetry.add_tcp_connection(12345);
        assert!(
            telemetry.get_alias_connections_per_minute().is_empty(),
            "shouldn't have data for unaffected telemetry"
        );
    }
}
