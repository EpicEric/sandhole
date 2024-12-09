use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::DashMap;

use crate::connections::ConnectionMapReactor;

struct Counter {
    history: VecDeque<(Instant, u64)>,
    window: Duration,
    period: f64,
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

    fn add(&mut self, value: u64) {
        loop {
            let Some(element) = self.history.front() else {
                break;
            };
            if element.0.elapsed() >= self.window {
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

    fn measure(&mut self) -> f64 {
        let delta = loop {
            let Some(element) = self.history.front() else {
                break self.count;
            };
            if element.1 == self.count {
                self.history.pop_front();
                break self.count;
            } else if element.0.elapsed() < self.window {
                break element.1;
            } else {
                self.history.pop_front();
            }
        };
        if let Some(element) = self.history.back() {
            if element.1 != self.count {
                self.history.push_back((Instant::now(), self.count));
            }
        } else {
            self.history.push_back((Instant::now(), self.count));
        }
        dbg!(&self.history);
        (self.count - delta) as f64 / self.period
    }
}

#[cfg(test)]
mod counter_tests {
    use std::{thread::sleep, time::Duration};

    use super::Counter;

    #[test]
    fn takes_measurements() {
        let mut counter = Counter::new(Duration::from_secs(5), Duration::from_secs(1));
        assert_eq!(counter.measure(), 0.0);
        counter.add(10);
        let measure_1 = counter.measure();
        assert!(measure_1 > 0.0);
        counter.add(10);
        let measure_2 = counter.measure();
        assert!(measure_2 > measure_1);
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

pub(crate) struct Telemetry {
    http_requests_per_minute: DashMap<String, Counter>,
}

impl Telemetry {
    pub(crate) fn new() -> Self {
        Telemetry {
            http_requests_per_minute: DashMap::new(),
        }
    }

    pub(crate) fn add_http_request(&self, hostname: String) {
        self.http_requests_per_minute
            .entry(hostname)
            .or_insert_with(|| Counter::new(Duration::from_secs(120), Duration::from_secs(60)))
            .value_mut()
            .add(1);
    }

    pub(crate) fn get_http_requests_per_minute(&self) -> HashMap<String, f64> {
        self.http_requests_per_minute
            .iter_mut()
            .map(|mut entry| {
                let measure = entry.value_mut().measure();
                (entry.key().clone(), measure)
            })
            .collect()
    }
}

impl ConnectionMapReactor<String> for Arc<Telemetry> {
    fn call(&self, hostnames: Vec<String>) {
        let hostnames: HashSet<String> = hostnames.into_iter().collect();
        self.http_requests_per_minute
            .retain(|key, _| hostnames.contains(key));
    }
}

#[cfg(test)]
mod telemetry_tests {
    use super::Telemetry;

    #[test]
    fn includes_data_for_requests_on_http_domains() {
        let telemetry = Telemetry::new();
        assert!(telemetry.get_http_requests_per_minute().is_empty());
        telemetry.add_http_request("foo".into());
        telemetry.add_http_request("bar".into());
        telemetry.add_http_request("qux".into());
        telemetry.add_http_request("qux".into());
        let data = telemetry.get_http_requests_per_minute();
        assert_eq!(data.len(), 3);
        assert_eq!(data.get("foo").unwrap(), data.get("bar").unwrap());
        assert_eq!(*data.get("qux").unwrap(), 2.0 * data.get("foo").unwrap());
    }
}
