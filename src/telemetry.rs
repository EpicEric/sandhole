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
        Counter {
            history: VecDeque::new(),
            period: window.as_secs_f64() / interval.as_secs_f64(),
            window,
            count: 0,
        }
    }

    fn add(&mut self, value: u64) {
        self.count += value;
    }

    fn measure(&mut self) -> f64 {
        let delta = loop {
            let Some(element) = self.history.front() else {
                break self.count;
            };
            if element.0.elapsed() < self.window {
                break element.1;
            } else {
                self.history.pop_front();
            }
        };
        self.history.push_back((Instant::now(), self.count));
        (self.count - delta) as f64 / self.period
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
