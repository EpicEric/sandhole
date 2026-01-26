// Shoutout to https://github.com/sunshowers-code/borrow-complex-key-example/blob/main/src/lib.rs

use std::{
    borrow::Borrow,
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

// A borrowed TCP alias, with references to an address and a port. Useful for accessing the TCP connection map.
#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct BorrowedKeepaliveAlias<'a>(
    pub(crate) &'a str,
    pub(crate) &'a IpAddr,
    pub(crate) &'a Option<Fingerprint>,
);

impl BorrowedKeepaliveAlias<'_> {
    pub(crate) fn as_owned(&self) -> KeepaliveAlias {
        KeepaliveAlias(self.0.to_string(), *self.1, *self.2)
    }
}

impl Hash for BorrowedKeepaliveAlias<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
        self.1.hash(state);
        self.2
            .as_ref()
            .map(|fingerprint| fingerprint.as_bytes())
            .hash(state);
    }
}

impl<'a> Borrow<dyn KeepaliveAliasKey + 'a> for KeepaliveAlias {
    fn borrow(&self) -> &(dyn KeepaliveAliasKey + 'a) {
        self
    }
}

pub(crate) trait KeepaliveAliasKey {
    fn key(&self) -> BorrowedKeepaliveAlias<'_>;
}

impl KeepaliveAliasKey for KeepaliveAlias {
    fn key(&self) -> BorrowedKeepaliveAlias<'_> {
        BorrowedKeepaliveAlias(self.0.as_str(), &self.1, &self.2)
    }
}

impl KeepaliveAliasKey for BorrowedKeepaliveAlias<'_> {
    fn key(&self) -> BorrowedKeepaliveAlias<'_> {
        *self
    }
}

impl PartialEq for dyn KeepaliveAliasKey + '_ {
    fn eq(&self, other: &Self) -> bool {
        self.key().eq(&other.key())
    }
}

impl Eq for dyn KeepaliveAliasKey + '_ {}

impl Hash for dyn KeepaliveAliasKey + '_ {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key().hash(state)
    }
}
