// Shoutout to https://github.com/sunshowers-code/borrow-complex-key-example/blob/main/src/lib.rs

use std::{
    borrow::Borrow,
    cmp::Ordering,
    hash::{Hash, Hasher},
};

// A TCP alias, with an address and a port.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct TcpAlias(pub(crate) String, pub(crate) u16);

// A borrowed TCP alias, with references to an address and a port. Useful for accessing the TCP connection map.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct BorrowedTcpAlias<'a>(pub(crate) &'a str, pub(crate) &'a u16);

impl<'a> Borrow<dyn TcpAliasKey + 'a> for TcpAlias {
    fn borrow(&self) -> &(dyn TcpAliasKey + 'a) {
        self
    }
}

pub(crate) trait TcpAliasKey {
    fn key(&self) -> BorrowedTcpAlias<'_>;
}

impl TcpAliasKey for TcpAlias {
    fn key(&self) -> BorrowedTcpAlias {
        BorrowedTcpAlias(self.0.as_str(), &self.1)
    }
}

impl TcpAliasKey for BorrowedTcpAlias<'_> {
    fn key(&self) -> BorrowedTcpAlias<'_> {
        *self
    }
}

impl PartialEq for (dyn TcpAliasKey + '_) {
    fn eq(&self, other: &Self) -> bool {
        self.key().eq(&other.key())
    }
}

impl Eq for (dyn TcpAliasKey + '_) {}

impl PartialOrd for (dyn TcpAliasKey + '_) {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for (dyn TcpAliasKey + '_) {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key().cmp(&other.key())
    }
}

impl Hash for (dyn TcpAliasKey + '_) {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key().hash(state)
    }
}
