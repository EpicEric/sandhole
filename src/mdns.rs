use std::collections::HashSet;

use ahash::RandomState;
use dashmap::DashMap;
use libmdns::{Responder, Service};
use tracing::error;

#[derive(Default)]
pub(crate) struct MdnsResponderReactor(DashMap<String, Service, RandomState>);

impl MdnsResponderReactor {
    pub(crate) fn http_reactor(&self, hostnames: &[String]) {
        let hostnames_set: HashSet<&str, RandomState> =
            hostnames.iter().map(|a| a.as_str()).collect();
        self.0.retain(|k, _| hostnames_set.contains(k.as_str()));
        for hostname in hostnames_set {
            if !self.0.contains_key(hostname) {
                match Responder::with_default_handle_and_ip_list_and_hostname(
                    vec![],
                    hostname.into(),
                ) {
                    Ok((responder, task)) => {
                        // TODO: This doesn't work
                        tokio::spawn(task);
                        self.0.insert(
                            hostname.into(),
                            responder.register(
                                "_http._tcp".into(),
                                format!("{hostname} HTTP server"),
                                80,
                                &[],
                            ),
                        );
                    }
                    Err(error) => {
                        error!(%error, "Failed to spawn mDNS responder.");
                    }
                }
            }
        }
    }
}
