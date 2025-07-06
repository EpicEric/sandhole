use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use ahash::RandomState;
use dashmap::DashMap;
use itertools::Itertools;
use metrics::{CounterFn, Recorder, Unit, describe_counter, describe_gauge, describe_histogram};
use tracing::warn;

use crate::tcp_alias::TcpAlias;

// A value that increases with time.
struct SlidingWindowCounter {
    // The history of the value across several instants.
    history: Mutex<VecDeque<(Instant, u64)>>,
    // The sliding window of values to consider.
    window: Duration,
    // The current value.
    count: AtomicU64,
}

impl CounterFn for SlidingWindowCounter {
    fn increment(&self, value: u64) {
        let mut history = self.history.lock().unwrap();
        loop {
            let Some(element) = history.front() else {
                break;
            };
            // Remove elements at the front if they are too old.
            if element.0.elapsed() >= self.window {
                // Don't remove the first element if it is the last one.
                // Instead, update its instant.
                // This ensures that the first call to add is counted.
                if history.len() == 1 {
                    history.front_mut().unwrap().0 = Instant::now();
                    break;
                } else {
                    history.pop_front();
                }
            } else {
                break;
            }
        }
        self.count.fetch_add(value, Ordering::Release);
    }

    fn absolute(&self, value: u64) {
        self.count.swap(value, Ordering::Release);
    }
}

impl SlidingWindowCounter {
    fn new(window: Duration) -> Self {
        SlidingWindowCounter {
            history: Mutex::new([(Instant::now(), 0)].into_iter().collect()),
            window,
            count: AtomicU64::new(0),
        }
    }

    // Measure the counter, taking the period and window into account.
    fn measure(&self) -> u64 {
        let count = self.count.load(Ordering::Acquire);
        let mut history = self.history.lock().unwrap();
        let measurement = loop {
            // If there are no elements in the history, return the current count.
            let Some(element) = history.front() else {
                break count;
            };
            // If the count hasn't changed, return the current count (rate will be 0).
            if element.1 == count {
                history.pop_front();
                break 0;
            // The count has changed; if within window, return the front element.
            } else if element.0.elapsed() < self.window {
                break count - element.1;
            // Element is no longer within window; remove from history.
            } else {
                history.pop_front();
            }
        };
        // If the last element has a different count value, add the current count to the end.
        if let Some(element) = history.back() {
            if element.1 != count {
                history.push_back((Instant::now(), count));
            }
        // Also add the current count to the end if the history is empty.
        } else {
            history.push_back((Instant::now(), count));
        }
        measurement
    }
}

pub(crate) const TELEMETRY_KEY_HOSTNAME: &str = "hostname";
pub(crate) const TELEMETRY_KEY_PORT: &str = "port";
pub(crate) const TELEMETRY_KEY_ALIAS: &str = "alias";

pub(crate) const TELEMETRY_COUNTER_SSH_CONNECTIONS_TOTAL: &str = "sandhole.ssh_connections.total";
pub(crate) const TELEMETRY_COUNTER_HTTP_REQUESTS_TOTAL: &str = "sandhole.http_requests.total";
pub(crate) const TELEMETRY_COUNTER_SNI_CONNECTIONS_TOTAL: &str = "sandhole.sni_connections.total";
pub(crate) const TELEMETRY_COUNTER_ALIAS_CONNECTIONS_TOTAL: &str =
    "sandhole.alias_connections.total";
pub(crate) const TELEMETRY_COUNTER_TCP_CONNECTIONS_TOTAL: &str = "sandhole.tcp_connections.total";
pub(crate) const TELEMETRY_COUNTER_USED_MEMORY_BYTES: &str = "system.used_memory.bytes";
pub(crate) const TELEMETRY_COUNTER_TOTAL_MEMORY_BYTES: &str = "system.total_memory.bytes";
pub(crate) const TELEMETRY_COUNTER_NETWORK_TX_BYTES: &str = "system.network_tx.bytes";
pub(crate) const TELEMETRY_COUNTER_NETWORK_RX_BYTES: &str = "system.network_rx.bytes";

pub(crate) const TELEMETRY_GAUGE_SSH_CONNECTIONS_CURRENT: &str = "sandhole.ssh_connections.current";
pub(crate) const TELEMETRY_GAUGE_SNI_CONNECTIONS_CURRENT: &str = "sandhole.sni_connections.current";
pub(crate) const TELEMETRY_GAUGE_ALIAS_CONNECTIONS_CURRENT: &str =
    "sandhole.alias_connections.current";
pub(crate) const TELEMETRY_GAUGE_TCP_CONNECTIONS_CURRENT: &str = "sandhole.tcp_connections.current";
pub(crate) const TELEMETRY_GAUGE_CPU_USAGE_PERCENT: &str = "system.cpu_usage.percent";

pub(crate) const TELEMETRY_HISTOGRAM_HTTP_ELAPSED_TIME_SECONDS: &str =
    "sandhole.http_elapsed_time.seconds";

// Metadata to display on the admin interface.
pub(crate) struct Telemetry {
    // Connections per minute for each SSH alias.
    ssh_connections_per_minute: DashMap<String, Arc<SlidingWindowCounter>, RandomState>,
    // Requests per minute for each HTTP host.
    http_requests_per_minute: DashMap<String, Arc<SlidingWindowCounter>, RandomState>,
    // Connections per minute for each SNI host.
    sni_connections_per_minute: DashMap<String, Arc<SlidingWindowCounter>, RandomState>,
    // Connections per minute for each local-forwarded alias.
    alias_connections_per_minute: DashMap<TcpAlias, Arc<SlidingWindowCounter>, RandomState>,
    // Connections per minute for each TCP port.
    tcp_connections_per_minute: DashMap<u16, Arc<SlidingWindowCounter>, RandomState>,
}

impl Telemetry {
    pub(crate) fn new() -> Self {
        describe_counter!(
            TELEMETRY_COUNTER_SSH_CONNECTIONS_TOTAL,
            "Total connections for SSH aliases"
        );
        describe_counter!(
            TELEMETRY_COUNTER_HTTP_REQUESTS_TOTAL,
            "Total requests for HTTP(S) hosts"
        );
        describe_counter!(
            TELEMETRY_COUNTER_SNI_CONNECTIONS_TOTAL,
            "Total connections for SNI hosts"
        );
        describe_counter!(
            TELEMETRY_COUNTER_ALIAS_CONNECTIONS_TOTAL,
            "Total connections for aliases"
        );
        describe_counter!(
            TELEMETRY_COUNTER_TCP_CONNECTIONS_TOTAL,
            "Total connections for TCP ports"
        );
        describe_counter!(TELEMETRY_COUNTER_USED_MEMORY_BYTES, "Used memory");
        describe_counter!(TELEMETRY_COUNTER_TOTAL_MEMORY_BYTES, "Total memory");
        describe_counter!(
            TELEMETRY_COUNTER_NETWORK_TX_BYTES,
            "Network transmitted data"
        );
        describe_counter!(TELEMETRY_COUNTER_NETWORK_RX_BYTES, "Network received data");

        describe_gauge!(
            TELEMETRY_GAUGE_SSH_CONNECTIONS_CURRENT,
            "Current requests for SSH aliases"
        );
        describe_gauge!(
            TELEMETRY_GAUGE_SNI_CONNECTIONS_CURRENT,
            "Current requests for SNI hosts"
        );
        describe_gauge!(
            TELEMETRY_GAUGE_ALIAS_CONNECTIONS_CURRENT,
            "Current requests for aliases"
        );
        describe_gauge!(
            TELEMETRY_GAUGE_TCP_CONNECTIONS_CURRENT,
            "Current requests for TCP ports"
        );
        describe_gauge!(TELEMETRY_GAUGE_CPU_USAGE_PERCENT, "Total CPU usage");

        describe_histogram!(
            TELEMETRY_HISTOGRAM_HTTP_ELAPSED_TIME_SECONDS,
            "Time to handle an HTTP request"
        );

        Telemetry {
            ssh_connections_per_minute: DashMap::default(),
            http_requests_per_minute: DashMap::default(),
            sni_connections_per_minute: DashMap::default(),
            tcp_connections_per_minute: DashMap::default(),
            alias_connections_per_minute: DashMap::default(),
        }
    }

    pub(crate) fn get_ssh_connections_per_minute(&self) -> HashMap<String, u64, RandomState> {
        self.ssh_connections_per_minute
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().measure()))
            .collect()
    }

    pub(crate) fn get_http_requests_per_minute(&self) -> HashMap<String, u64, RandomState> {
        self.http_requests_per_minute
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().measure()))
            .collect()
    }

    pub(crate) fn get_sni_connections_per_minute(&self) -> HashMap<String, u64, RandomState> {
        self.sni_connections_per_minute
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().measure()))
            .collect()
    }

    pub(crate) fn get_alias_connections_per_minute(&self) -> HashMap<TcpAlias, u64, RandomState> {
        self.alias_connections_per_minute
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().measure()))
            .collect()
    }

    pub(crate) fn get_tcp_connections_per_minute(&self) -> HashMap<u16, u64, RandomState> {
        self.tcp_connections_per_minute
            .iter()
            .map(|entry| (*entry.key(), entry.value().measure()))
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

    pub(crate) fn sni_reactor(&self, hostnames: Vec<String>) {
        let hostnames: HashSet<String> = hostnames.into_iter().collect();
        self.sni_connections_per_minute
            .retain(|key, _| hostnames.contains(key));
    }

    pub(crate) fn alias_reactor(&self, aliases: Vec<TcpAlias>) {
        let aliases: HashSet<TcpAlias> = aliases.into_iter().collect();
        self.alias_connections_per_minute
            .retain(|key, _| aliases.contains(key));
    }

    pub(crate) fn tcp_reactor(&self, ports: Vec<u16>) {
        let ports: HashSet<u16> = ports.into_iter().collect();
        self.tcp_connections_per_minute
            .retain(|key, _| ports.contains(key));
    }
}

impl Recorder for Telemetry {
    fn describe_counter(
        &self,
        _key: metrics::KeyName,
        _unit: Option<Unit>,
        _description: metrics::SharedString,
    ) {
    }

    fn describe_gauge(
        &self,
        _key: metrics::KeyName,
        _unit: Option<Unit>,
        _description: metrics::SharedString,
    ) {
    }

    fn describe_histogram(
        &self,
        _key: metrics::KeyName,
        _unit: Option<Unit>,
        _description: metrics::SharedString,
    ) {
    }

    fn register_counter(
        &self,
        key: &metrics::Key,
        _metadata: &metrics::Metadata<'_>,
    ) -> metrics::Counter {
        let name = key.name();
        let labels: Vec<(&str, &str)> = key
            .labels()
            .map(|label| (label.key(), label.value()))
            .sorted()
            .collect();
        match name {
            TELEMETRY_COUNTER_SSH_CONNECTIONS_TOTAL => {
                for (key, value) in labels {
                    if key == TELEMETRY_KEY_ALIAS {
                        return metrics::Counter::from_arc(Arc::clone(
                            self.ssh_connections_per_minute
                                .entry(value.to_string())
                                .or_insert(Arc::new(SlidingWindowCounter::new(
                                    Duration::from_secs(60),
                                )))
                                .value(),
                        ));
                    }
                }
            }
            TELEMETRY_COUNTER_HTTP_REQUESTS_TOTAL => {
                for (key, value) in labels {
                    if key == TELEMETRY_KEY_HOSTNAME {
                        return metrics::Counter::from_arc(Arc::clone(
                            self.http_requests_per_minute
                                .entry(value.to_string())
                                .or_insert(Arc::new(SlidingWindowCounter::new(
                                    Duration::from_secs(60),
                                )))
                                .value(),
                        ));
                    }
                }
            }
            TELEMETRY_COUNTER_SNI_CONNECTIONS_TOTAL => {
                for (key, value) in labels {
                    if key == TELEMETRY_KEY_HOSTNAME {
                        return metrics::Counter::from_arc(Arc::clone(
                            self.sni_connections_per_minute
                                .entry(value.to_string())
                                .or_insert(Arc::new(SlidingWindowCounter::new(
                                    Duration::from_secs(60),
                                )))
                                .value(),
                        ));
                    }
                }
            }
            TELEMETRY_COUNTER_ALIAS_CONNECTIONS_TOTAL => {
                for (key, value) in labels {
                    if key == TELEMETRY_KEY_PORT {
                        match value.parse::<TcpAlias>() {
                            Ok(port) => {
                                return metrics::Counter::from_arc(Arc::clone(
                                    self.alias_connections_per_minute
                                        .entry(port)
                                        .or_insert(Arc::new(SlidingWindowCounter::new(
                                            Duration::from_secs(60),
                                        )))
                                        .value(),
                                ));
                            }
                            Err(error) => {
                                warn!(alias = value, %error, "Invalid TCP alias in telemetry.")
                            }
                        }
                    }
                }
            }
            TELEMETRY_COUNTER_TCP_CONNECTIONS_TOTAL => {
                for (key, value) in labels {
                    if key == TELEMETRY_KEY_PORT {
                        match value.parse::<u16>() {
                            Ok(port) => {
                                return metrics::Counter::from_arc(Arc::clone(
                                    self.tcp_connections_per_minute
                                        .entry(port)
                                        .or_insert(Arc::new(SlidingWindowCounter::new(
                                            Duration::from_secs(60),
                                        )))
                                        .value(),
                                ));
                            }
                            Err(error) => warn!(port = value, %error, "Invalid port in telemetry."),
                        }
                    }
                }
            }
            _ => (),
        }
        metrics::Counter::noop()
    }

    fn register_gauge(
        &self,
        _key: &metrics::Key,
        _metadata: &metrics::Metadata<'_>,
    ) -> metrics::Gauge {
        metrics::Gauge::noop()
    }

    fn register_histogram(
        &self,
        _key: &metrics::Key,
        _metadata: &metrics::Metadata<'_>,
    ) -> metrics::Histogram {
        metrics::Histogram::noop()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod counter_tests {
    use std::{thread::sleep, time::Duration};

    use metrics::CounterFn;

    use super::SlidingWindowCounter;

    #[test_log::test]
    fn takes_measurements() {
        let counter = SlidingWindowCounter::new(Duration::from_secs(4));
        assert_eq!(counter.measure(), 0);
        counter.increment(2);
        let measure_1 = counter.measure();
        assert_eq!(measure_1, 2);
        counter.increment(2);
        let measure_2 = counter.measure();
        assert_eq!(measure_2, 4);
        counter.absolute(6);
        let measure_2 = counter.measure();
        assert_eq!(measure_2, 6);
    }

    #[test_log::test]
    fn resets_on_moving_window() {
        let counter = SlidingWindowCounter::new(Duration::from_millis(200));
        counter.increment(10);
        let measure_1 = counter.measure();
        assert_eq!(measure_1, 10);
        sleep(Duration::from_millis(500));
        counter.increment(10);
        let measure_2 = counter.measure();
        assert_eq!(measure_2, 10);
    }
}
