use std::sync::Arc;

use anyhow::Context;
use http::{
    header::{CONTENT_TYPE, HOST},
    uri::Scheme,
    Request,
};
use hyper::Uri;
use hyper_util::rt::TokioIo;
use log::{error, warn};
use rustls::ClientConfig;
use rustls_platform_verifier::ConfigVerifierExt;
use serde::Serialize;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use webpki::types::ServerName;

pub(crate) struct ApiLogin {
    url: Uri,
    address: String,
    scheme: ApiScheme,
    host: String,
    server_name: ServerName<'static>,
    config: Arc<ClientConfig>,
}

enum ApiScheme {
    Http,
    Https,
}

#[derive(Serialize)]
struct AuthenticationRequest<'a> {
    user: &'a str,
    password: &'a str,
}

impl ApiLogin {
    pub(crate) fn new(endpoint: &str) -> anyhow::Result<Self> {
        let url: Uri = endpoint
            .parse()
            .with_context(|| "Invalid endpoint for API login")?;
        let scheme = url
            .scheme()
            .with_context(|| "API login URL has no scheme")?
            .clone();
        let scheme = if scheme == Scheme::HTTP {
            ApiScheme::Http
        } else if scheme == Scheme::HTTPS {
            ApiScheme::Https
        } else {
            panic!("API login URL has unknown scheme (must be set to either http:// or https://)");
        };
        let host = url
            .host()
            .with_context(|| "API login URL has no host")?
            .to_string();
        let server_name = ServerName::try_from(host.clone())
            .with_context(|| "Invalid server name for API login URL")?;
        let address = format!(
            "{}:{}",
            host,
            url.port_u16().unwrap_or(match scheme {
                ApiScheme::Http => 80,
                ApiScheme::Https => 443,
            })
        );
        Ok(ApiLogin {
            url,
            address,
            scheme,
            host,
            server_name,
            config: Arc::new(ClientConfig::with_platform_verifier()),
        })
    }

    pub(crate) async fn authenticate(&self, user: &str, password: &str) -> bool {
        let data = AuthenticationRequest { user, password };
        let tcp_stream = match TcpStream::connect(&self.address).await {
            Ok(tcp_stream) => tcp_stream,
            Err(err) => {
                error!("API login TCP connection failed: {}", err);
                return false;
            }
        };
        let request = Request::builder()
            .method("POST")
            .uri(&self.url)
            .header(HOST, &self.host)
            .header(CONTENT_TYPE, "application/json; charset=UTF-8")
            .body(serde_json::to_string(&data).unwrap())
            .unwrap();
        match self.scheme {
            ApiScheme::Http => {
                let (mut sender, conn) =
                    match hyper::client::conn::http1::handshake(TokioIo::new(tcp_stream)).await {
                        Ok(result) => result,
                        Err(err) => {
                            error!("API login handshake failed: {}", err);
                            return false;
                        }
                    };
                tokio::spawn(async move {
                    if let Err(err) = conn.await {
                        warn!("API login TCP connection errored: {:?}", err);
                    }
                });
                let response = match sender.send_request(request).await {
                    Ok(response) => response,
                    Err(err) => {
                        error!("API login HTTP request failed: {}", err);
                        return false;
                    }
                };
                response.status().is_success()
            }
            ApiScheme::Https => {
                let connector = TlsConnector::from(Arc::clone(&self.config));
                let tls_stream = match connector
                    .connect(self.server_name.clone(), tcp_stream)
                    .await
                {
                    Ok(tls_stream) => tls_stream,
                    Err(err) => {
                        error!("API login TLS connection failed: {}", err);
                        return false;
                    }
                };
                let (mut sender, conn) =
                    match hyper::client::conn::http1::handshake(TokioIo::new(tls_stream)).await {
                        Ok(result) => result,
                        Err(err) => {
                            error!("API login handshake failed: {}", err);
                            return false;
                        }
                    };
                tokio::spawn(async move {
                    if let Err(err) = conn.await {
                        warn!("API login TCP connection errored: {:?}", err);
                    }
                });
                let response = match sender.send_request(request).await {
                    Ok(response) => response,
                    Err(err) => {
                        error!("API login HTTP request failed: {}", err);
                        return false;
                    }
                };
                response.status().is_success()
            }
        }
    }
}

#[cfg(test)]
mod api_login_tests {
    use axum::{response::IntoResponse, routing::post, Json, Router};
    use http::StatusCode;
    use tokio::net::TcpListener;

    use super::ApiLogin;

    #[tokio::test]
    async fn authenticates_on_successful_response() {
        async fn endpoint(Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
            if payload.get("user").unwrap() == "eric"
                && payload.get("password").unwrap() == "sandhole"
            {
                (StatusCode::OK, "Success")
            } else {
                (StatusCode::FORBIDDEN, "Not authenticated")
            }
        }
        let app = Router::new().route("/authentication", post(endpoint));
        let listener = TcpListener::bind("127.0.0.1:28011").await.unwrap();
        let jh = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let api_login = ApiLogin::new("http://localhost:28011/authentication".into()).unwrap();
        assert!(api_login.authenticate("eric", "sandhole").await);
        jh.abort();
    }

    #[tokio::test]
    async fn doesnt_authenticate_on_unsuccessful_response() {
        async fn endpoint(Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
            if payload.get("user").unwrap() == "eric"
                && payload.get("password").unwrap() == "sandhole"
            {
                (StatusCode::FORBIDDEN, "Success but rejected")
            } else {
                (StatusCode::OK, "Failure but allowed")
            }
        }
        let app = Router::new().route("/authentication", post(endpoint));
        let listener = TcpListener::bind("127.0.0.1:28012").await.unwrap();
        let jh = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let api_login = ApiLogin::new("http://localhost:28012/authentication".into()).unwrap();
        assert!(!api_login.authenticate("eric", "sandhole").await);
        jh.abort();
    }
}
