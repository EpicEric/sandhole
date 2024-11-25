use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::DashMap;

use crate::connections::ConnectionMapReactor;

struct Counter {
    queue: VecDeque<(Instant, u64)>,
    interval: Duration,
    window: Duration,
    total_value: u64,
}

impl Counter {
    fn add(&mut self, value: u64) {
        self.shrink();
        self.queue.push_back((Instant::now(), value));
        self.total_value += value;
    }

    fn measure(&mut self) -> f64 {
        self.shrink();
        let period = self.window.as_secs_f64() / self.interval.as_secs_f64();
        (self.total_value as f64) / period
    }

    fn shrink(&mut self) {
        while let Some(element) = self.queue.pop_front() {
            if element.0.elapsed() < self.window {
                self.queue.push_front(element);
                break;
            } else {
                self.total_value -= element.1;
            }
        }
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
            .or_insert(Counter {
                queue: VecDeque::new(),
                interval: Duration::from_secs(60),
                window: Duration::from_secs(120),
                total_value: 0,
            })
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
