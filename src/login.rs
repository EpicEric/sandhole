use std::{marker::PhantomData, net::SocketAddr, sync::Arc};

use anyhow::{anyhow, Context, Result};
use http::{
    header::{CONTENT_TYPE, HOST, USER_AGENT},
    uri::Scheme,
    Request,
};
use hyper::Uri;
use hyper_util::rt::TokioIo;
use log::warn;
#[cfg(test)]
use mockall::automock;
use rustls::ClientConfig;
use rustls_platform_verifier::ConfigVerifierExt;
use serde::Serialize;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use webpki::types::ServerName;

use crate::{droppable_handle::DroppableHandle, error::ServerError};

// Parsed data for login HTTP requests.
pub(crate) struct ApiLogin<C> {
    //
    configurer: PhantomData<C>,
    // URL for the POST requests
    url: Uri,
    // Address and port of the login API
    address: String,
    // Which scheme to connect with (HTTP or HTTPS)
    scheme: ApiScheme,
    // The hostname for the server
    host: String,
    // Which server name to specify for TLS requests
    server_name: ServerName<'static>,
}

enum ApiScheme {
    Http,
    Https(Arc<ClientConfig>),
}

#[derive(Serialize)]
pub(crate) struct AuthenticationRequest<'a> {
    pub(crate) user: &'a str,
    pub(crate) password: &'a str,
    pub(crate) remote_address: &'a SocketAddr,
}

// Trait for TLS configuration setup.
#[cfg_attr(test, automock)]
pub(crate) trait Configurer {
    // Returns the TLS client configuration.
    fn get_client_config(&self) -> ClientConfig;
}

pub(crate) struct PlatformVerifierConfigurer;

impl Configurer for PlatformVerifierConfigurer {
    // Returns the CA certificate chain from the operating system.
    fn get_client_config(&self) -> ClientConfig {
        ClientConfig::with_platform_verifier()
    }
}

impl<C: Configurer> ApiLogin<C> {
    // Create the login client with the shared configuration for HTTP requests.
    pub(crate) fn new(endpoint: &str, configurer: C) -> anyhow::Result<Self> {
        // Parse data from the URL
        let url: Uri = endpoint
            .parse()
            .with_context(|| "Invalid endpoint for API login")?;
        let scheme = url
            .scheme()
            .with_context(|| "API login URL has no scheme")?
            .clone();
        // Check the scheme from the URL
        let scheme = if scheme == Scheme::HTTP {
            ApiScheme::Http
        } else if scheme == Scheme::HTTPS {
            ApiScheme::Https(Arc::new(configurer.get_client_config()))
        } else {
            return Err(ServerError::UnknownHttpScheme).with_context(|| "Invalid API login URL")?;
        };
        let host = url
            .host()
            .with_context(|| "API login URL has no host")?
            .to_string();
        //
        let server_name = ServerName::try_from(host.clone())
            .with_context(|| "Invalid server name for API login URL")?;
        // Create address from host and port
        let address = format!(
            "{}:{}",
            host,
            url.port_u16().unwrap_or(match scheme {
                ApiScheme::Http => 80,
                ApiScheme::Https(_) => 443,
            })
        );
        Ok(ApiLogin {
            configurer: PhantomData,
            url,
            address,
            scheme,
            host,
            server_name,
        })
    }

    // Sends a POST request with the authentication body to the configured service, returning true if authenticated.
    pub(crate) async fn authenticate(&self, data: &AuthenticationRequest<'_>) -> Result<bool> {
        // Connect to the remote host
        let tcp_stream = match TcpStream::connect(&self.address).await {
            Ok(tcp_stream) => tcp_stream,
            Err(err) => {
                return Err(anyhow!("API login TCP connection failed: {}", err));
            }
        };
        // Create the request
        let request = Request::builder()
            .method("POST")
            .uri(&self.url)
            .header(HOST, &self.host)
            .header(
                USER_AGENT,
                concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION")),
            )
            .header(CONTENT_TYPE, "application/json; charset=UTF-8")
            .body(serde_json::to_string(data).unwrap())
            .expect("Invalid request");
        let (response, _join_handle) = match self.scheme {
            // Send an HTTP request (usually to an internal server)
            ApiScheme::Http => {
                // Create an HTTP handshake
                let (mut sender, conn) =
                    match hyper::client::conn::http1::handshake(TokioIo::new(tcp_stream)).await {
                        Ok(result) => result,
                        Err(err) => {
                            return Err(anyhow!("API login handshake failed: {}", err));
                        }
                    };
                let _join_handle = DroppableHandle(tokio::spawn(async move {
                    if let Err(err) = conn.await {
                        warn!("API login TCP connection errored: {:?}", err);
                    }
                }));
                // Get the response via HTTP
                match sender.send_request(request).await {
                    Ok(response) => (response, _join_handle),
                    Err(err) => {
                        return Err(anyhow!("API login HTTP request failed: {}", err));
                    }
                }
            }
            // Send an HTTPS request (usually to an external server)
            ApiScheme::Https(ref config) => {
                // Establish the TLS stream
                let connector = TlsConnector::from(Arc::clone(config));
                let tls_stream = match connector
                    .connect(self.server_name.clone(), tcp_stream)
                    .await
                {
                    Ok(tls_stream) => tls_stream,
                    Err(err) => {
                        return Err(anyhow!("API login TLS connection failed: {}", err));
                    }
                };
                // Create an HTTP handshake
                let (mut sender, conn) =
                    match hyper::client::conn::http1::handshake(TokioIo::new(tls_stream)).await {
                        Ok(result) => result,
                        Err(err) => {
                            return Err(anyhow!("API login handshake failed: {}", err));
                        }
                    };
                let _join_handle = DroppableHandle(tokio::spawn(async move {
                    if let Err(err) = conn.await {
                        warn!("API login TCP connection errored: {:?}", err);
                    }
                }));
                // Get the response via HTTP
                match sender.send_request(request).await {
                    Ok(response) => (response, _join_handle),
                    Err(err) => {
                        return Err(anyhow!("API login HTTP request failed: {}", err));
                    }
                }
            }
        };
        // Authenticate if status code is within 200-299
        Ok(response.status().is_success())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod api_login_tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
    };

    use axum::{extract::Request, response::IntoResponse, routing::post, Json, Router};
    use http::StatusCode;
    use hyper::{body::Incoming, service::service_fn};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use tower::Service;
    use webpki::types::{pem::PemObject, CertificateDer, PrivateKeyDer};

    use super::{ApiLogin, AuthenticationRequest, MockConfigurer};

    #[tokio::test]
    async fn authenticates_on_successful_http_response() {
        let mut mock = MockConfigurer::new();
        mock.expect_get_client_config().never();

        async fn endpoint(Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
            if payload.get("user").unwrap() == "eric"
                && payload.get("password").unwrap() == "sandhole"
                && payload.get("remote_address").unwrap() == "127.0.0.1:12345"
            {
                (StatusCode::OK, "Success")
            } else {
                (StatusCode::FORBIDDEN, "Not authenticated")
            }
        }
        let app = Router::new().route("/authentication", post(endpoint));
        let listener = TcpListener::bind("127.0.0.1:28011").await.unwrap();
        let jh = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let api_login = ApiLogin::new("http://localhost:28011/authentication", mock).unwrap();
        assert!(
            api_login
                .authenticate(&AuthenticationRequest {
                    user: "eric",
                    password: "sandhole",
                    remote_address: &SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                        12345
                    )
                })
                .await
                .unwrap(),
            "should authenticated valid user"
        );
        jh.abort();
    }

    #[tokio::test]
    async fn doesnt_authenticate_on_unsuccessful_http_response() {
        let mut mock = MockConfigurer::new();
        mock.expect_get_client_config().never();

        async fn endpoint(Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
            if payload.get("user").unwrap() == "eric"
                && payload.get("password").unwrap() == "sandhole"
                && payload.get("remote_address").unwrap() == "127.0.0.1:12345"
            {
                (StatusCode::FORBIDDEN, "Success but rejected")
            } else {
                (StatusCode::OK, "Failure but allowed")
            }
        }
        let app = Router::new().route("/authentication", post(endpoint));
        let listener = TcpListener::bind("127.0.0.1:28012").await.unwrap();
        let jh = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let api_login = ApiLogin::new("http://localhost:28012/authentication", mock).unwrap();
        assert!(
            !api_login
                .authenticate(&AuthenticationRequest {
                    user: "eric",
                    password: "sandhole",
                    remote_address: &SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                        12345
                    )
                })
                .await
                .unwrap(),
            "shouldn't authenticate expected user"
        );
        jh.abort();
    }

    #[tokio::test]
    async fn authenticates_on_successful_https_response() {
        let mut mock = MockConfigurer::new();
        let mut root_store = RootCertStore::empty();
        root_store.add_parsable_certificates(
            CertificateDer::pem_file_iter(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/data/ca/rootCA.pem"
            ))
            .and_then(|iter| iter.collect::<Result<Vec<_>, _>>())
            .expect("Failed to parse client certificates"),
        );
        let tls_client_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        mock.expect_get_client_config()
            .once()
            .return_once(move || tls_client_config);

        async fn endpoint(Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
            if payload.get("user").unwrap() == "eric"
                && payload.get("password").unwrap() == "sandhole"
                && payload.get("remote_address").unwrap() == "127.0.0.1:12345"
            {
                (StatusCode::OK, "Success")
            } else {
                (StatusCode::FORBIDDEN, "Not authenticated")
            }
        }
        let app = Router::new().route("/secure_authentication", post(endpoint));
        let listener = TcpListener::bind("127.0.0.1:28013").await.unwrap();
        let tls_server_config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    CertificateDer::pem_file_iter(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/tests/data/certificates/localhost/fullchain.pem"
                    ))
                    .and_then(|iter| iter.collect::<Result<Vec<_>, _>>())
                    .expect("Failed to parse server certificates"),
                    PrivateKeyDer::from_pem_file(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/tests/data/certificates/localhost/privkey.pem"
                    ))
                    .expect("Failed to parse server key"),
                )
                .expect("Failed to build server config"),
        );
        let tls_acceptor = TlsAcceptor::from(tls_server_config);
        let jh = tokio::spawn(async move {
            loop {
                let acceptor = tls_acceptor.clone();
                let service = app.clone();
                let (conn, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let stream = TokioIo::new(acceptor.accept(conn).await.unwrap());
                    let hyper_service =
                        service_fn(move |request: Request<Incoming>| service.clone().call(request));
                    hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                        .serve_connection_with_upgrades(stream, hyper_service)
                        .await
                        .unwrap();
                });
            }
        });

        let api_login =
            ApiLogin::new("https://localhost:28013/secure_authentication", mock).unwrap();
        assert!(
            api_login
                .authenticate(&AuthenticationRequest {
                    user: "eric",
                    password: "sandhole",
                    remote_address: &SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                        12345
                    )
                })
                .await
                .unwrap(),
            "should authenticated valid user"
        );
        jh.abort();
    }
}
