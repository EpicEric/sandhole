// Shoutout to https://github.com/sunshowers-code/borrow-complex-key-example/blob/main/src/lib.rs

use std::{
    borrow::Borrow,
    fmt::Display,
    hash::{Hash, Hasher},
    str::FromStr,
};

use color_eyre::eyre::OptionExt;

// A TCP alias, with an address and a port.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct SockAddrAlias(pub(crate) String, pub(crate) u16);

impl Display for SockAddrAlias {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.0, self.1)
    }
}

impl FromStr for SockAddrAlias {
    type Err = color_eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (left, right) = s.rsplit_once(':').ok_or_eyre("Missing : separator")?;
        Ok(SockAddrAlias(left.to_string(), right.parse()?))
    }
}

// A borrowed TCP alias, with references to an address and a port. Useful for accessing the TCP connection map.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct BorrowedSockAddrAlias<'a>(pub(crate) &'a str, pub(crate) &'a u16);

impl Display for BorrowedSockAddrAlias<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.0, self.1)
    }
}

impl<'a> Borrow<dyn SockAddrAliasKey + 'a> for SockAddrAlias {
    fn borrow(&self) -> &(dyn SockAddrAliasKey + 'a) {
        self
    }
}

pub(crate) trait SockAddrAliasKey {
    fn key(&self) -> BorrowedSockAddrAlias<'_>;
}

impl SockAddrAliasKey for SockAddrAlias {
    fn key(&self) -> BorrowedSockAddrAlias<'_> {
        BorrowedSockAddrAlias(self.0.as_str(), &self.1)
    }
}

impl SockAddrAliasKey for BorrowedSockAddrAlias<'_> {
    fn key(&self) -> BorrowedSockAddrAlias<'_> {
        *self
    }
}

impl PartialEq for dyn SockAddrAliasKey + '_ {
    fn eq(&self, other: &Self) -> bool {
        self.key().eq(&other.key())
    }
}

impl Eq for dyn SockAddrAliasKey + '_ {}

impl Hash for dyn SockAddrAliasKey + '_ {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key().hash(state)
    }
}
