use std::{
    collections::{HashMap, HashSet, VecDeque},
    future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use ahash::RandomState;
use dashmap::DashMap;
use itertools::Itertools;
use metrics::{
    Counter, CounterFn, Recorder, Unit, describe_counter, describe_gauge, describe_histogram,
};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle, PrometheusRecorder};
use tokio::time::sleep;
use tracing::warn;

use crate::{droppable_handle::DroppableHandle, tcp_alias::TcpAlias};

// A value that increases with time.
struct SlidingWindowCounter {
    // Inner counter for metrics with a different exporter.
    inner: Counter,
    // The history of the value across several instants.
    history: Mutex<VecDeque<(Instant, u64)>>,
    // The sliding window of values to consider.
    window: Duration,
    // The current value.
    count: AtomicU64,
}

impl CounterFn for SlidingWindowCounter {
    fn increment(&self, value: u64) {
        self.inner.increment(value);
        self.clean();
        self.count.fetch_add(value, Ordering::Release);
    }

    fn absolute(&self, value: u64) {
        self.inner.absolute(value);
        self.clean();
        self.count.swap(value, Ordering::Release);
    }
}

impl SlidingWindowCounter {
    fn new(counter: Counter, window: Duration) -> Self {
        SlidingWindowCounter {
            inner: counter,
            history: Mutex::new([(Instant::now(), 0)].into_iter().collect()),
            window,
            count: AtomicU64::new(0),
        }
    }

    fn clean(&self) {
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

pub(crate) const TELEMETRY_COUNTER_SSH_CONNECTIONS_TOTAL: &str = "sandhole_ssh_connections_total";
pub(crate) const TELEMETRY_COUNTER_HTTP_REQUESTS_TOTAL: &str = "sandhole_http_requests_total";
pub(crate) const TELEMETRY_COUNTER_SNI_CONNECTIONS_TOTAL: &str = "sandhole_sni_connections_total";
pub(crate) const TELEMETRY_COUNTER_ALIAS_CONNECTIONS_TOTAL: &str =
    "sandhole_alias_connections_total";
pub(crate) const TELEMETRY_COUNTER_ADMIN_ALIAS_CONNECTIONS_TOTAL: &str =
    "sandhole_admin_alias_connections_total";
pub(crate) const TELEMETRY_COUNTER_TCP_CONNECTIONS_TOTAL: &str = "sandhole_tcp_connections_total";
pub(crate) const TELEMETRY_COUNTER_USED_MEMORY_BYTES: &str = "system_used_memory_bytes";
pub(crate) const TELEMETRY_COUNTER_TOTAL_MEMORY_BYTES: &str = "system_total_memory_bytes";
pub(crate) const TELEMETRY_COUNTER_NETWORK_TX_BYTES: &str = "system_network_tx_bytes";
pub(crate) const TELEMETRY_COUNTER_NETWORK_RX_BYTES: &str = "system_network_rx_bytes";

pub(crate) const TELEMETRY_GAUGE_SSH_CONNECTIONS_CURRENT: &str = "sandhole_ssh_connections_current";
pub(crate) const TELEMETRY_GAUGE_SNI_CONNECTIONS_CURRENT: &str = "sandhole_sni_connections_current";
pub(crate) const TELEMETRY_GAUGE_ALIAS_CONNECTIONS_CURRENT: &str =
    "sandhole_alias_connections_current";
pub(crate) const TELEMETRY_GAUGE_ADMIN_ALIAS_CONNECTIONS_CURRENT: &str =
    "sandhole_admin_alias_connections_current";
pub(crate) const TELEMETRY_GAUGE_TCP_CONNECTIONS_CURRENT: &str = "sandhole_tcp_connections_current";
pub(crate) const TELEMETRY_GAUGE_CPU_USAGE_PERCENT: &str = "system_cpu_usage_percent";

pub(crate) const TELEMETRY_HISTOGRAM_HTTP_ELAPSED_TIME_SECONDS: &str =
    "sandhole_http_elapsed_time_seconds";

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
    // Connections per minute for each admin alias.
    admin_alias_connections_per_minute: DashMap<TcpAlias, Arc<SlidingWindowCounter>, RandomState>,
    // Connections per minute for each TCP port.
    tcp_connections_per_minute: DashMap<u16, Arc<SlidingWindowCounter>, RandomState>,
    // Recorder for Prometheus metrics export.
    prometheus_recorder: Option<PrometheusRecorder>,
    // Join handle for the Prometheus upkeep task.
    _join_handle: DroppableHandle<()>,
}

impl Telemetry {
    pub(crate) fn new(enable_prometheus: bool) -> Self {
        if enable_prometheus {
            let prometheus_recorder = PrometheusBuilder::new()
                .set_buckets_for_metric(
                    metrics_exporter_prometheus::Matcher::Full(
                        TELEMETRY_HISTOGRAM_HTTP_ELAPSED_TIME_SECONDS.to_string(),
                    ),
                    &[
                        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 25.0,
                    ],
                )
                .expect("values should not be empty")
                .build_recorder();
            let handle = prometheus_recorder.handle();
            let join_handle = DroppableHandle(tokio::spawn(async move {
                loop {
                    sleep(Duration::from_secs(60)).await;
                    handle.run_upkeep();
                }
            }));

            Telemetry {
                ssh_connections_per_minute: DashMap::default(),
                http_requests_per_minute: DashMap::default(),
                sni_connections_per_minute: DashMap::default(),
                alias_connections_per_minute: DashMap::default(),
                admin_alias_connections_per_minute: DashMap::default(),
                tcp_connections_per_minute: DashMap::default(),
                prometheus_recorder: Some(prometheus_recorder),
                _join_handle: join_handle,
            }
        } else {
            Telemetry {
                ssh_connections_per_minute: DashMap::default(),
                http_requests_per_minute: DashMap::default(),
                sni_connections_per_minute: DashMap::default(),
                alias_connections_per_minute: DashMap::default(),
                admin_alias_connections_per_minute: DashMap::default(),
                tcp_connections_per_minute: DashMap::default(),
                prometheus_recorder: None,
                _join_handle: DroppableHandle(tokio::spawn(future::pending())),
            }
        }
    }

    pub(crate) fn register_metrics(&self) {
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
            TELEMETRY_COUNTER_ADMIN_ALIAS_CONNECTIONS_TOTAL,
            "Total connections for admin aliases"
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
    }

    pub(crate) fn prometheus_handle(&self) -> Option<PrometheusHandle> {
        self.prometheus_recorder
            .as_ref()
            .map(|recorder| recorder.handle())
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

    pub(crate) fn get_admin_alias_connections_per_minute(
        &self,
    ) -> HashMap<TcpAlias, u64, RandomState> {
        self.admin_alias_connections_per_minute
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
        key: metrics::KeyName,
        unit: Option<Unit>,
        description: metrics::SharedString,
    ) {
        self.prometheus_recorder
            .as_ref()
            .inspect(|recorder| recorder.describe_counter(key, unit, description));
    }

    fn describe_gauge(
        &self,
        key: metrics::KeyName,
        unit: Option<Unit>,
        description: metrics::SharedString,
    ) {
        self.prometheus_recorder
            .as_ref()
            .inspect(|recorder| recorder.describe_gauge(key, unit, description));
    }

    fn describe_histogram(
        &self,
        key: metrics::KeyName,
        unit: Option<Unit>,
        description: metrics::SharedString,
    ) {
        self.prometheus_recorder
            .as_ref()
            .inspect(|recorder| recorder.describe_histogram(key, unit, description));
    }

    fn register_counter(
        &self,
        key: &metrics::Key,
        metadata: &metrics::Metadata<'_>,
    ) -> metrics::Counter {
        let prometheus_counter = self
            .prometheus_recorder
            .as_ref()
            .map(|recorder| recorder.register_counter(key, metadata))
            .unwrap_or(metrics::Counter::noop());
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
                                    prometheus_counter,
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
                                    prometheus_counter,
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
                                    prometheus_counter,
                                    Duration::from_secs(60),
                                )))
                                .value(),
                        ));
                    }
                }
            }
            TELEMETRY_COUNTER_ALIAS_CONNECTIONS_TOTAL => {
                for (key, value) in labels {
                    if key == TELEMETRY_KEY_ALIAS {
                        match value.parse::<TcpAlias>() {
                            Ok(port) => {
                                return metrics::Counter::from_arc(Arc::clone(
                                    self.alias_connections_per_minute
                                        .entry(port)
                                        .or_insert(Arc::new(SlidingWindowCounter::new(
                                            prometheus_counter,
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
            TELEMETRY_COUNTER_ADMIN_ALIAS_CONNECTIONS_TOTAL => {
                for (key, value) in labels {
                    if key == TELEMETRY_KEY_ALIAS {
                        match value.parse::<TcpAlias>() {
                            Ok(port) => {
                                return metrics::Counter::from_arc(Arc::clone(
                                    self.admin_alias_connections_per_minute
                                        .entry(port)
                                        .or_insert(Arc::new(SlidingWindowCounter::new(
                                            prometheus_counter,
                                            Duration::from_secs(60),
                                        )))
                                        .value(),
                                ));
                            }
                            Err(error) => {
                                warn!(alias = value, %error, "Invalid admin alias in telemetry.")
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
                                            prometheus_counter,
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
        prometheus_counter
    }

    fn register_gauge(
        &self,
        key: &metrics::Key,
        metadata: &metrics::Metadata<'_>,
    ) -> metrics::Gauge {
        self.prometheus_recorder
            .as_ref()
            .map(|recorder| recorder.register_gauge(key, metadata))
            .unwrap_or(metrics::Gauge::noop())
    }

    fn register_histogram(
        &self,
        key: &metrics::Key,
        metadata: &metrics::Metadata<'_>,
    ) -> metrics::Histogram {
        self.prometheus_recorder
            .as_ref()
            .map(|recorder| recorder.register_histogram(key, metadata))
            .unwrap_or(metrics::Histogram::noop())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod counter_tests {
    use std::{thread::sleep, time::Duration};

    use metrics::{Counter, CounterFn};

    use super::SlidingWindowCounter;

    #[test_log::test]
    fn takes_measurements() {
        let counter = SlidingWindowCounter::new(Counter::noop(), Duration::from_secs(4));
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
        let counter = SlidingWindowCounter::new(Counter::noop(), Duration::from_millis(200));
        counter.increment(10);
        let measure_1 = counter.measure();
        assert_eq!(measure_1, 10);
        sleep(Duration::from_millis(500));
        counter.increment(10);
        let measure_2 = counter.measure();
        assert_eq!(measure_2, 10);
    }
}
