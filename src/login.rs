use std::{marker::PhantomData, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use http::uri::Scheme;
use hyper::Uri;
#[cfg(test)]
use mockall::automock;
use reqwest::Client;
use rustls::{ClientConfig, RootCertStore, client::WebPkiServerVerifier, crypto::CryptoProvider};
use serde::Serialize;
use webpki_roots::TLS_SERVER_ROOTS;

use crate::error::ServerError;

// Parsed data for login HTTP requests.
pub(crate) struct ApiLogin<C> {
    //
    configurer: PhantomData<C>,
    // Endpoint of the login API
    endpoint: String,
    // Client to connect with
    client: Client,
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
    fn get_client_config(&self, provider: CryptoProvider) -> Result<ClientConfig>;
}

pub(crate) struct WebpkiVerifierConfigurer;

impl Configurer for WebpkiVerifierConfigurer {
    // Returns the CA certificate chain from the operating system.
    fn get_client_config(&self, provider: CryptoProvider) -> Result<ClientConfig> {
        let mut store = RootCertStore::empty();
        store.extend(TLS_SERVER_ROOTS.iter().map(|ta| ta.to_owned()));
        Ok(ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()?
            .with_webpki_verifier(WebPkiServerVerifier::builder(Arc::new(store)).build()?)
            .with_no_client_auth())
    }
}

impl<C: Configurer> ApiLogin<C> {
    // Create the login client with the shared configuration for HTTP requests.
    pub(crate) fn from(
        configurer: C,
        endpoint: String,
        timeout: Option<Duration>,
    ) -> anyhow::Result<Self> {
        // Parse data from the URL
        let mut client_builder = Client::builder().hickory_dns(true).user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ));
        if let Some(timeout) = timeout {
            client_builder = client_builder.timeout(timeout);
        }
        let scheme = endpoint
            .parse::<Uri>()
            .with_context(|| "Invalid endpoint for API login")?
            .scheme()
            .with_context(|| "API login URL has no scheme")?
            .clone();
        // Create client and address from scheme
        let client = if scheme == Scheme::HTTP {
            client_builder
                .build()
                .with_context(|| "Unable to build HTTP client")?
        } else if scheme == Scheme::HTTPS {
            client_builder
                .use_preconfigured_tls(
                    configurer
                        .get_client_config(rustls::crypto::aws_lc_rs::default_provider())
                        .with_context(|| "Unable to get TLS client configuration")?,
                )
                .https_only(true)
                .build()
                .with_context(|| "Unable to build HTTPS client")?
        } else {
            return Err(ServerError::UnknownHttpScheme).with_context(|| "Invalid API login URL");
        };
        Ok(ApiLogin {
            configurer: PhantomData,
            endpoint,
            client,
        })
    }

    // Sends a POST request with the authentication body to the configured service, returning true if authenticated.
    pub(crate) async fn authenticate(&self, data: &AuthenticationRequest<'_>) -> Result<bool> {
        // Send an HTTP/HTTPS request
        let response = self.client.post(&self.endpoint).json(data).send().await?;
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

    use axum::{
        Json, Router,
        extract::Request,
        response::{IntoResponse, Redirect},
        routing::post,
    };
    use http::StatusCode;
    use hyper::{body::Incoming, service::service_fn};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    use tokio::{io::AsyncReadExt, net::TcpListener};
    use tokio_rustls::TlsAcceptor;
    use tower::Service;

    use super::{ApiLogin, AuthenticationRequest, MockConfigurer};

    #[test_log::test(tokio::test)]
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

        let api_login =
            ApiLogin::from(mock, "http://localhost:28011/authentication".into(), None).unwrap();
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
            "should authenticate valid user"
        );
        jh.abort();
    }

    #[test_log::test(tokio::test)]
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

        let api_login =
            ApiLogin::from(mock, "http://localhost:28012/authentication".into(), None).unwrap();
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

    #[test_log::test(tokio::test)]
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
        mock.expect_get_client_config()
            .once()
            .return_once(move |provider| {
                Ok(ClientConfig::builder_with_provider(Arc::new(provider))
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_root_certificates(root_store)
                    .with_no_client_auth())
            });

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
            ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
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

        let api_login = ApiLogin::from(
            mock,
            "https://localhost:28013/secure_authentication".into(),
            None,
        )
        .unwrap();
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
            "should authenticate valid user"
        );
        jh.abort();
    }

    #[test_log::test(tokio::test)]
    async fn authenticates_on_successful_http_redirect() {
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
        let app = Router::new()
            .route(
                "/authentication",
                post(async || Redirect::permanent("/real_authentication")),
            )
            .route("/real_authentication", post(endpoint));
        let listener = TcpListener::bind("127.0.0.1:28014").await.unwrap();
        let jh = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let api_login =
            ApiLogin::from(mock, "http://localhost:28014/authentication".into(), None).unwrap();
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
            "should authenticate valid user"
        );
        jh.abort();
    }

    #[test_log::test]
    fn fails_on_empty_url() {
        let mut mock = MockConfigurer::new();
        mock.expect_get_client_config().never();
        assert!(
            ApiLogin::from(mock, "".into(), None).is_err(),
            "should error on empty URL"
        );
    }

    #[test_log::test]
    fn fails_on_invalid_url() {
        let mut mock = MockConfigurer::new();
        mock.expect_get_client_config().never();
        assert!(
            ApiLogin::from(mock, "https://should.fail/\x00".into(), None).is_err(),
            "should error on missing URL"
        );
    }

    #[test_log::test]
    fn fails_on_missing_host() {
        let mut mock = MockConfigurer::new();
        mock.expect_get_client_config().never();
        assert!(
            ApiLogin::from(mock, "https:///invalid".into(), None).is_err(),
            "should error on missing host"
        );
    }

    #[test_log::test]
    fn fails_on_invalid_host() {
        let mut mock = MockConfigurer::new();
        mock.expect_get_client_config().never();
        assert!(
            ApiLogin::from(mock, "https://should\x00fail".into(), None).is_err(),
            "should error on invalid host"
        );
    }

    #[test_log::test]
    fn fails_on_missing_scheme() {
        let mut mock = MockConfigurer::new();
        mock.expect_get_client_config().never();
        assert!(
            ApiLogin::from(mock, "should.fail".into(), None).is_err(),
            "should error on missing scheme"
        );
    }

    #[test_log::test]
    fn fails_on_unknown_scheme() {
        let mut mock = MockConfigurer::new();
        mock.expect_get_client_config().never();
        assert!(
            ApiLogin::from(mock, "unknown://should.fail".into(), None).is_err(),
            "should error on unknown scheme"
        );
    }

    #[test_log::test(tokio::test)]
    async fn errors_when_unable_to_connect_to_socket() {
        let mut mock = MockConfigurer::new();
        mock.expect_get_client_config().never();

        let api_login =
            ApiLogin::from(mock, "http://localhost:28015/authentication".into(), None).unwrap();
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
                .is_err(),
            "should fail to connect to socket"
        );
    }

    #[test_log::test(tokio::test)]
    async fn errors_when_unable_to_complete_http_handshake() {
        let mut mock = MockConfigurer::new();
        mock.expect_get_client_config().never();

        let listener = TcpListener::bind("127.0.0.1:28016").await.unwrap();
        let jh = tokio::spawn(async move {
            loop {
                drop(listener.accept().await.unwrap());
            }
        });

        let api_login =
            ApiLogin::from(mock, "http://localhost:28016/authentication".into(), None).unwrap();
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
                .is_err(),
            "should fail to complete HTTP handshake"
        );
        jh.abort();
    }

    #[test_log::test(tokio::test)]
    async fn errors_when_http_request_fails() {
        let mut mock = MockConfigurer::new();
        mock.expect_get_client_config().never();

        let listener = TcpListener::bind("127.0.0.1:28017").await.unwrap();
        let jh = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 1024];
                loop {
                    let len = stream.read(&mut buf).await.unwrap();
                    if buf[..len].windows(4).any(|subslice| subslice == b"POST") {
                        drop(stream);
                        break;
                    }
                }
            }
        });

        let api_login =
            ApiLogin::from(mock, "http://localhost:28017/authentication".into(), None).unwrap();
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
                .is_err(),
            "should fail to complete HTTP request"
        );
        jh.abort();
    }

    #[test_log::test(tokio::test)]
    async fn errors_when_unable_to_complete_https_handshake() {
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
        mock.expect_get_client_config()
            .once()
            .return_once(move |provider| {
                Ok(ClientConfig::builder_with_provider(Arc::new(provider))
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_root_certificates(root_store)
                    .with_no_client_auth())
            });

        let listener = TcpListener::bind("127.0.0.1:28018").await.unwrap();
        let jh = tokio::spawn(async move {
            loop {
                drop(listener.accept().await.unwrap());
            }
        });

        let api_login = ApiLogin::from(
            mock,
            "https://localhost:28018/secure_authentication".into(),
            None,
        )
        .unwrap();
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
                .is_err(),
            "should fail to complete HTTPS handshake"
        );
        jh.abort();
    }

    #[test_log::test(tokio::test)]
    async fn errors_when_https_request_fails() {
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
        mock.expect_get_client_config()
            .once()
            .return_once(move |provider| {
                Ok(ClientConfig::builder_with_provider(Arc::new(provider))
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_root_certificates(root_store)
                    .with_no_client_auth())
            });

        let listener = TcpListener::bind("127.0.0.1:28019").await.unwrap();
        let tls_server_config = Arc::new(
            ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
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
                let (conn, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut stream = acceptor.accept(conn).await.unwrap();
                    let mut buf = [0u8; 1024];
                    loop {
                        let len = stream.read(&mut buf).await.unwrap();
                        if buf[..len].windows(4).any(|subslice| subslice == b"POST") {
                            drop(stream);
                            break;
                        }
                    }
                });
            }
        });

        let api_login = ApiLogin::from(
            mock,
            "https://localhost:28019/secure_authentication".into(),
            None,
        )
        .unwrap();
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
                .is_err(),
            "should fail to complete HTTPS request"
        );
        jh.abort();
    }
}
