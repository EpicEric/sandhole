use std::net::IpAddr;

use ipnet::IpNet;
use ipnet_trie::IpnetTrie;

use crate::error::ServerError;

// Connection policy applied to an IP range.
#[derive(PartialEq, Eq, Clone, Copy)]
enum IpPolicy {
    Allow,
    Deny,
}

// Service that identifies whether to allow or block a given IP address.
pub(crate) struct IpFilter {
    // Which policy to apply for IPs not found in the trie.
    default_policy: IpPolicy,
    // Trie for efficient lookup of IPs by the network prefix.
    data: IpnetTrie<IpPolicy>,
}

pub(crate) struct IpFilterConfig {
    pub(crate) allowlist: Option<Vec<IpNet>>,
    pub(crate) blocklist: Option<Vec<IpNet>>,
}

impl IpFilter {
    pub(crate) fn new(config: IpFilterConfig) -> anyhow::Result<Self> {
        let IpFilterConfig {
            allowlist,
            blocklist,
        } = config;
        let mut data = IpnetTrie::new();
        let mut default_policy = IpPolicy::Allow;
        if let Some(allowlist) = allowlist {
            if !allowlist.is_empty() {
                default_policy = IpPolicy::Deny;
            }
            for network in allowlist {
                if data.insert(network, IpPolicy::Allow).is_some() {
                    return Err(ServerError::DuplicateNetworkCidr(network).into());
                }
            }
        }
        if let Some(blocklist) = blocklist {
            for network in blocklist {
                if data.insert(network, IpPolicy::Deny).is_some() {
                    return Err(ServerError::DuplicateNetworkCidr(network).into());
                }
            }
        }
        Ok(IpFilter {
            default_policy,
            data,
        })
    }

    pub(crate) fn is_allowed(&self, address: IpAddr) -> bool {
        self.data
            .longest_match(&IpNet::from(address.to_canonical()))
            .map(|(_, policy)| *policy)
            .unwrap_or_else(|| self.default_policy)
            == IpPolicy::Allow
    }
}

#[cfg(test)]
mod ip_filter_tests {
    use std::{net::IpAddr, str::FromStr};

    use ipnet::IpNet;

    use super::{IpFilter, IpFilterConfig};

    #[test]
    fn should_allow_anyone_if_no_lists() {
        let filter = IpFilter::new(IpFilterConfig {
            allowlist: None,
            blocklist: None,
        })
        .unwrap();
        assert!(filter.is_allowed(IpAddr::from_str("127.0.0.1").unwrap()));
        assert!(filter.is_allowed(IpAddr::from_str("10.0.2.127").unwrap()));
        assert!(filter.is_allowed(IpAddr::from_str("1234:dead:beef::154").unwrap()));
        assert!(filter.is_allowed(IpAddr::from_str("1234:0db8:502e::3c").unwrap()));
    }

    #[test]
    fn should_allow_anyone_if_empty_lists() {
        let filter = IpFilter::new(IpFilterConfig {
            allowlist: Some(vec![]),
            blocklist: Some(vec![]),
        })
        .unwrap();
        assert!(filter.is_allowed(IpAddr::from_str("127.0.0.1").unwrap()));
        assert!(filter.is_allowed(IpAddr::from_str("10.0.2.127").unwrap()));
        assert!(filter.is_allowed(IpAddr::from_str("1234:dead:beef::154").unwrap()));
        assert!(filter.is_allowed(IpAddr::from_str("1234:0db8:502e::3c").unwrap()));
    }

    #[test]
    fn should_allow_addresses_not_in_blocklist() {
        let filter = IpFilter::new(IpFilterConfig {
            allowlist: None,
            blocklist: Some(vec![
                IpNet::from_str("10.0.0.0/20").unwrap(),
                IpNet::from_str("1234:dead::/32").unwrap(),
            ]),
        })
        .unwrap();
        assert!(filter.is_allowed(IpAddr::from_str("127.0.0.1").unwrap()));
        assert!(!filter.is_allowed(IpAddr::from_str("10.0.2.127").unwrap()));
        assert!(!filter.is_allowed(IpAddr::from_str("1234:dead:beef::154").unwrap()));
        assert!(filter.is_allowed(IpAddr::from_str("1234:0db8:502e::3c").unwrap()));
    }

    #[test]
    fn should_reject_addresses_not_in_allowlist() {
        let filter = IpFilter::new(IpFilterConfig {
            allowlist: Some(vec![
                IpNet::from_str("127.0.0.0/24").unwrap(),
                IpNet::from_str("10.0.0.0/18").unwrap(),
            ]),
            blocklist: None,
        })
        .unwrap();
        assert!(filter.is_allowed(IpAddr::from_str("127.0.0.1").unwrap()));
        assert!(filter.is_allowed(IpAddr::from_str("10.0.2.127").unwrap()));
        assert!(!filter.is_allowed(IpAddr::from_str("1234:dead:beef::154").unwrap()));
        assert!(!filter.is_allowed(IpAddr::from_str("1234:0db8:502e::3c").unwrap()));
    }

    #[test]
    fn should_only_accept_allowlist() {
        let filter = IpFilter::new(IpFilterConfig {
            allowlist: Some(vec![
                IpNet::from_str("127.0.0.0/24").unwrap(),
                IpNet::from_str("10.0.0.0/18").unwrap(),
            ]),
            blocklist: Some(vec![
                IpNet::from_str("10.0.0.0/20").unwrap(),
                IpNet::from_str("1234:dead::/32").unwrap(),
            ]),
        })
        .unwrap();
        assert!(filter.is_allowed(IpAddr::from_str("127.0.0.1").unwrap()));
        assert!(!filter.is_allowed(IpAddr::from_str("10.0.2.127").unwrap()));
        assert!(!filter.is_allowed(IpAddr::from_str("1234:dead:beef::154").unwrap()));
        assert!(!filter.is_allowed(IpAddr::from_str("1234:0db8:502e::3c").unwrap()));
    }

    #[test]
    fn should_fail_if_duplicated_network() {
        assert!(
            IpFilter::new(IpFilterConfig {
                allowlist: Some(vec![IpNet::from_str("127.0.0.0/24").unwrap()]),
                blocklist: Some(vec![IpNet::from_str("127.0.0.0/24").unwrap()]),
            })
            .is_err(),
            "shouldn't allow same network in both allowlist and blocklist"
        );
        assert!(
            IpFilter::new(IpFilterConfig {
                allowlist: Some(vec![
                    IpNet::from_str("127.0.0.0/24").unwrap(),
                    IpNet::from_str("127.0.0.0/24").unwrap()
                ]),
                blocklist: None,
            })
            .is_err(),
            "shouldn't allow same network in allowlist twice"
        );
        assert!(
            IpFilter::new(IpFilterConfig {
                allowlist: None,
                blocklist: Some(vec![
                    IpNet::from_str("127.0.0.0/24").unwrap(),
                    IpNet::from_str("127.0.0.0/24").unwrap()
                ]),
            })
            .is_err(),
            "shouldn't allow same network in blocklist twice"
        );
    }
}
