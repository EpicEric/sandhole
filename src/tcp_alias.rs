// Shoutout to https://github.com/sunshowers-code/borrow-complex-key-example/blob/main/src/lib.rs

use std::{
    borrow::Borrow,
    cmp::Ordering,
    hash::{Hash, Hasher},
};

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct TcpAlias(pub(crate) String, pub(crate) u16);

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
    fn key<'k>(&'k self) -> BorrowedTcpAlias<'k> {
        BorrowedTcpAlias(self.0.as_str(), &self.1)
    }
}

impl<'a> TcpAliasKey for BorrowedTcpAlias<'a> {
    fn key(&self) -> BorrowedTcpAlias<'_> {
        *self
    }
}

impl<'a> PartialEq for (dyn TcpAliasKey + 'a) {
    fn eq(&self, other: &Self) -> bool {
        self.key().eq(&other.key())
    }
}

impl<'a> Eq for (dyn TcpAliasKey + 'a) {}

impl<'a> PartialOrd for (dyn TcpAliasKey + 'a) {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.key().partial_cmp(&other.key())
    }
}

impl<'a> Ord for (dyn TcpAliasKey + 'a) {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key().cmp(&other.key())
    }
}

impl<'a> Hash for (dyn TcpAliasKey + 'a) {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key().hash(state)
    }
}
