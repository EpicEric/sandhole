#[cfg_attr(not(feature = "prometheus"), expect(unused_imports))]
use std::time::Duration;
use std::{net::IpAddr, sync::Arc};

#[cfg_attr(not(feature = "prometheus"), expect(unused_imports))]
use bytes::Bytes;
#[cfg_attr(not(feature = "prometheus"), expect(unused_imports))]
use http::{HeaderValue, Request, Response, StatusCode, header::CONTENT_TYPE};
#[cfg_attr(not(feature = "prometheus"), expect(unused_imports))]
use http_body_util::Full;
#[cfg_attr(not(feature = "prometheus"), expect(unused_imports))]
use hyper::body::Incoming;
#[cfg_attr(not(feature = "prometheus"), expect(unused_imports))]
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
#[cfg(feature = "prometheus")]
use metrics_exporter_prometheus::PrometheusHandle;
use russh::keys::ssh_key::Fingerprint;
use tokio::io::DuplexStream;
#[cfg_attr(not(feature = "prometheus"), expect(unused_imports))]
use tokio::time::timeout;

use crate::{
    connection_handler::{ConnectionHandler, ConnectionHttpData},
    error::ServerError,
    ssh::ServerHandlerSender,
};

#[derive(Clone)]
pub(crate) struct AdminAliasHandler {
    pub(crate) handler: Arc<dyn Fn() -> DuplexStream + Send + Sync + 'static>,
}

impl ConnectionHandler<DuplexStream> for AdminAliasHandler {
    fn log_channel(&self) -> ServerHandlerSender {
        ServerHandlerSender(None)
    }

    async fn tunneling_channel(
        &self,
        _ip: IpAddr,
        _port: u16,
    ) -> Result<DuplexStream, ServerError> {
        Err(ServerError::TunnelingUnavailable)
    }

    fn can_alias(&self, _ip: IpAddr, _port: u16, _fingerprint: Option<&'_ Fingerprint>) -> bool {
        // We can return true due to a previous check that an admin key is being used
        true
    }

    async fn aliasing_channel(
        &self,
        _ip: IpAddr,
        _port: u16,
        _fingerprint: Option<&'_ Fingerprint>,
    ) -> Result<DuplexStream, ServerError> {
        Ok((self.handler)())
    }

    fn http_data(&self) -> Option<ConnectionHttpData> {
        None
    }
}

#[cfg(feature = "prometheus")]
pub(crate) fn get_prometheus_service(
    handle: PrometheusHandle,
    tcp_connection_timeout: Option<Duration>,
    buffer_size: usize,
) -> DuplexStream {
    let service = hyper::service::service_fn(move |req: Request<Incoming>| {
        let handle_clone = handle.clone();
        async move {
            if req.uri().path() == "/" {
                let mut response = Response::new(Full::new(Bytes::from(
                    tokio::task::spawn_blocking(move || handle_clone.render())
                        .await
                        .expect("task runs to completion"),
                )));
                response
                    .headers_mut()
                    .append(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
                Ok(response)
            } else {
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::default())
            }
        }
    });
    let (server, client) = tokio::io::duplex(buffer_size);
    let io = TokioIo::new(server);
    tokio::spawn(async move {
        let server = auto::Builder::new(TokioExecutor::new());
        let conn = server.serve_connection_with_upgrades(io, service);
        match tcp_connection_timeout {
            Some(duration) => {
                let _ = timeout(duration, conn).await;
            }
            None => {
                let _ = conn.await;
            }
        }
    });
    client
}
