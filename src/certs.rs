//! Self-signed certificate generation and fingerprinting.
//!
//! Spec §2: in HTTPS mode the fingerprint is the SHA-256 hash of the
//! certificate. Certificate parameters follow the official LocalSend app
//! so we look identical on the wire.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

pub struct Identity {
    pub cert_der: Vec<u8>,
    pub cert_pem: String,
    pub key_pem: String,
    /// SHA-256 of the DER certificate, UPPERCASE hex, no separators
    /// (matches the official app's `certificateHash`).
    pub fingerprint: String,
}

/// Subject CN of the official app; matching it keeps lsq
/// certs are indistinguishable from the app's on the wire.
pub const CERT_COMMON_NAME: &str = "LocalSend User";

pub fn generate_identity(_alias: &str) -> Result<Identity> {
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, CERT_COMMON_NAME);
    // Official app: 10-year validity.
    let now = std::time::SystemTime::now();
    params.not_before = now.into();
    params.not_after = (now + std::time::Duration::from_secs(10 * 365 * 24 * 3600)).into();
    let key_pair = rcgen::KeyPair::generate()?; // ECDSA P-256
    let cert = params.self_signed(&key_pair)?;
    let cert_der = cert.der().to_vec();
    let fingerprint = sha256_hex(&cert_der);
    Ok(Identity {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
        cert_der,
        fingerprint,
    })
}

/// Load the identity from `dir` (cert.pem + key.pem), or generate one and
/// save it there. Persisting the cert keeps the fingerprint stable across
/// restarts, so peers remember this device.
pub fn load_or_create_identity(dir: &Path) -> Result<Identity> {
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    if cert_path.exists() && key_path.exists() {
        let cert_pem = fs::read_to_string(&cert_path)?;
        let key_pem = fs::read_to_string(&key_path)?;
        let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
            .context("reading stored cert.pem")?;
        let cert_der = pem.contents;
        let fingerprint = sha256_hex(&cert_der);
        return Ok(Identity { cert_der, cert_pem, key_pem, fingerprint });
    }
    let id = generate_identity("")?;
    fs::create_dir_all(dir)?;
    fs::write(&cert_path, &id.cert_pem)?;
    fs::write(&key_path, &id.key_pem)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(id)
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    // The app writes its certificateHash as uppercase hex; match it.
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// Random fingerprint for HTTP (unencrypted) mode, spec §2.
pub fn random_fingerprint() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| {
            let idx = rng.gen_range(0..36);
            char::from_digit(idx, 36).unwrap()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_has_consistent_fingerprint() {
        let id = generate_identity("LocalSend User").unwrap();
        assert_eq!(id.fingerprint.len(), 64);
        assert_eq!(id.fingerprint, sha256_hex(&id.cert_der));
        assert!(id.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(id.key_pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn identities_are_unique() {
        let a = generate_identity("x").unwrap();
        let b = generate_identity("x").unwrap();
        assert_ne!(a.fingerprint, b.fingerprint);
    }

    #[test]
    fn random_fingerprint_shape() {
        let f = random_fingerprint();
        assert_eq!(f.len(), 32);
        assert_ne!(f, random_fingerprint());
    }

    #[test]
    fn persisted_identity_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let a = load_or_create_identity(dir.path()).unwrap();
        let b = load_or_create_identity(dir.path()).unwrap();
        assert_eq!(a.fingerprint, b.fingerprint);
        assert_eq!(a.cert_der, b.cert_der);
        assert_eq!(a.fingerprint.len(), 64);
    }
}
