// sandhole: Expose HTTP/SSH/TCP services through SSH port forwarding
// Copyright (C) 2024-2026 Eric Rodrigues Pires
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for
// more details.
//
// You should have received a copy of the GNU Affero General Public License along
// with this program. If not, see <https://www.gnu.org/licenses/>.

use std::sync::Arc;

use crate::{
    certificates::CertificateResolver,
    sock_addr_alias::SockAddrAlias,
    tcp::{TcpHandler, TcpPortHandler},
    telemetry::Telemetry,
    udp::{UdpHandler, UdpPortHandler},
};

#[cfg_attr(test, mockall::automock)]
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

pub(crate) struct SniReactor(pub(crate) Arc<Telemetry>);

impl ConnectionMapReactor<String> for SniReactor {
    fn call(&self, identifiers: Vec<String>) {
        self.0.sni_reactor(identifiers);
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

pub(crate) struct UdpReactor {
    pub(crate) handler: Arc<UdpHandler>,
    pub(crate) telemetry: Arc<Telemetry>,
}

impl ConnectionMapReactor<u16> for UdpReactor {
    fn call(&self, identifiers: Vec<u16>) {
        self.handler.update_ports(identifiers.clone());
        self.telemetry.udp_reactor(identifiers);
    }
}

pub(crate) struct AliasReactor(pub(crate) Arc<Telemetry>);

impl ConnectionMapReactor<SockAddrAlias> for AliasReactor {
    fn call(&self, identifiers: Vec<SockAddrAlias>) {
        self.0.alias_reactor(identifiers);
    }
}
