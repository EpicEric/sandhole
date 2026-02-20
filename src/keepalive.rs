// Shoutout to https://github.com/sunshowers-code/borrow-complex-key-example/blob/main/src/lib.rs

use std::{
    hash::{Hash, Hasher},
    net::IpAddr,
};

use russh::keys::ssh_key::Fingerprint;

// A TCP alias, with an address and a port.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct KeepaliveAlias(
    pub(crate) String,
    pub(crate) IpAddr,
    pub(crate) Option<Fingerprint>,
);

impl Hash for KeepaliveAlias {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
        self.1.hash(state);
        self.2
            .as_ref()
            .map(|fingerprint| fingerprint.as_bytes())
            .hash(state);
    }
}
