use std::sync::Arc;

use crate::connections::ConnectionMapReactor;
use dashmap::DashMap;

pub(crate) struct TcpHandler {
    sockets: DashMap<u16, ()>,
}

impl ConnectionMapReactor<u16> for Arc<TcpHandler> {
    fn call(&self, ports: Vec<u16>) {}
}
