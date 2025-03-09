use std::sync::Arc;

#[cfg(test)]
use mockall::automock;

use crate::{
    certificates::CertificateResolver,
    tcp::{PortHandler, TcpHandler},
    tcp_alias::TcpAlias,
    telemetry::Telemetry,
};

#[cfg_attr(test, automock)]
pub(crate) trait ConnectionMapReactor<K> {
    fn call(&self, identifiers: Vec<K>);
}

pub(crate) struct DummyConnectionMapReactor;

impl<K> ConnectionMapReactor<K> for DummyConnectionMapReactor {
    fn call(&self, _: Vec<K>) {}
}

pub(crate) struct SshReactor(pub(crate) Arc<Telemetry>);

impl ConnectionMapReactor<String> for SshReactor {
    fn call(&self, identifiers: Vec<String>) {
        self.0.ssh_reactor(identifiers);
    }
}

pub(crate) struct HttpReactor {
    pub(crate) certificates: Arc<CertificateResolver>,
    pub(crate) telemetry: Arc<Telemetry>,
}

// When the list of hostnames served by Sandhole changes, we must notify the
// certificates resolver (in order to update the ACME challenges) and the telemetry
// (in order to tell which hostnames are still being tracked or not).
impl ConnectionMapReactor<String> for HttpReactor {
    fn call(&self, identifiers: Vec<String>) {
        self.certificates
            .update_acme_domains(identifiers.as_slice());
        self.telemetry.http_reactor(identifiers);
    }
}

pub(crate) struct TcpReactor {
    pub(crate) handler: Arc<TcpHandler>,
    pub(crate) telemetry: Arc<Telemetry>,
}

impl ConnectionMapReactor<u16> for TcpReactor {
    fn call(&self, identifiers: Vec<u16>) {
        self.handler.update_ports(identifiers.clone());
        self.telemetry.tcp_reactor(identifiers);
    }
}

pub(crate) struct AliasReactor(pub(crate) Arc<Telemetry>);

impl ConnectionMapReactor<TcpAlias> for AliasReactor {
    fn call(&self, identifiers: Vec<TcpAlias>) {
        self.0.alias_reactor(identifiers);
    }
}
