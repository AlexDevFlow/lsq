//! Regression guard for the client certificate.
//!
//! LocalSend 1.18 makes the client certificate mandatory on its HTTPS server
//! whenever it is not serving its web pages — which is the normal receive
//! state. A request from a client that presents no certificate is dropped
//! during the handshake with a `CertificateRequired` alert, so a discovery
//! reply sent that way never reaches the peer and the peer never learns that
//! this device exists.
//!
//! Every outgoing HTTPS request lsq makes must therefore carry its identity.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};

/// Mirrors the shape of LocalSend's own verifier: client auth is mandatory,
/// and any certificate that verifies is trusted (peers are identified by
/// fingerprint, not by an authority).
#[derive(Debug)]
struct MandatoryClientCert;

impl ClientCertVerifier for MandatoryClientCert {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Starts an HTTPS server that refuses clients without a certificate,
/// the way a LocalSend 1.18 device in receive mode does.
async fn start_mtls_server() -> u16 {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "LocalSend User");
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();

    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(MandatoryClientCert))
        .with_single_cert(
            vec![CertificateDer::from(cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der())),
        )
        .unwrap();

    // Hand the already-bound listener to the server: the port cannot be taken
    // in between, and a client that connects before the accept loop is running
    // waits in the backlog instead of being refused.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let app = axum::Router::new()
        .route(
            "/api/localsend/v2/register",
            axum::routing::post(|| async { "{}" }),
        )
        .route(
            "/api/localsend/v2/prepare-download",
            axum::routing::post(|| async {
                axum::Json(serde_json::json!({
                    "info": { "alias": "mtls-peer" },
                    "sessionId": "test-session",
                    "files": {
                        "f": { "id": "f", "fileName": "hello.txt", "size": 5,
                               "fileType": "text/plain" }
                    }
                }))
            }),
        )
        .route(
            "/api/localsend/v2/download",
            axum::routing::get(|| async { "hello" }),
        );
    let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(config));
    tokio::spawn(async move {
        let _ = axum_server::from_tcp_rustls(listener, tls)
            .serve(app.into_make_service())
            .await;
    });
    port
}

#[tokio::test]
async fn client_without_identity_is_refused_by_an_mtls_peer() {
    let port = start_mtls_server().await;
    let url = format!("https://127.0.0.1:{port}/api/localsend/v2/register");

    let certless = lsq::sender::insecure_client().unwrap();
    assert!(
        certless.post(&url).send().await.is_err(),
        "a certless client must not be able to reach an mTLS peer — if this \
         starts passing, the premise of the test below no longer holds"
    );
}

#[tokio::test]
async fn client_with_identity_reaches_an_mtls_peer() {
    let port = start_mtls_server().await;
    let url = format!("https://127.0.0.1:{port}/api/localsend/v2/register");

    let id = lsq::certs::generate_identity("").unwrap();
    let client = lsq::sender::client_with_identity(Some(&id)).unwrap();
    let res = client.post(&url).send().await;
    assert!(
        res.is_ok(),
        "lsq's identity client must reach a peer that requires a client \
         certificate: {:?}",
        res.err()
    );
}

#[tokio::test]
async fn pull_presents_identity_to_an_mtls_peer() {
    let port = start_mtls_server().await;
    let base = format!("https://127.0.0.1:{port}");
    let dest = tempfile::tempdir().unwrap();
    let id = lsq::certs::generate_identity("").unwrap();

    let error = lsq::pull::pull_files(&base, dest.path(), None, None, true, None)
        .await
        .unwrap_err();
    assert!(error.unreachable);
    let outcome = lsq::pull::pull_files(&base, dest.path(), None, None, true, Some(&id))
        .await
        .unwrap();
    assert_eq!(outcome.fetched, 1);
    assert_eq!(outcome.total_bytes, 5);
    assert_eq!(
        std::fs::read(dest.path().join("hello.txt")).unwrap(),
        b"hello"
    );
}
