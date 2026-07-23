use crate::types::Cr3st4n1Credential;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("schema validation failed: {0:?}")]
    Schema(Vec<String>),
    #[error("serialization: {0}")]
    Serialize(#[from] serde_yaml::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("serialization: {0}")]
    Serialize(#[from] serde_yaml::Error),
    #[error("base64 decode: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invalid signature length")]
    SignatureLength,
    #[error("signature verification failed")]
    BadSignature(#[from] ed25519_dalek::SignatureError),
}

/// Sign a credential in place. Validates against embedded schema first.
/// Clone before calling if you need the unsigned original.
pub fn sign(cred: &mut Cr3st4n1Credential, key: &SigningKey) -> Result<(), SignError> {
    let value = serde_json::to_value(&*cred)?;
    crate::schema::validate(&value).map_err(SignError::Schema)?;

    let hash = canonical_hash(cred)?;
    let sig = key.sign(&hash);

    cred.signature.algorithm = "Ed25519".into();
    cred.signature.signature = BASE64.encode(sig.to_bytes());
    Ok(())
}

/// Verify a credential's Ed25519 signature.
pub fn verify(cred: &Cr3st4n1Credential, key: &VerifyingKey) -> Result<(), VerifyError> {
    let yaml = canonical_yaml(cred)?;
    let hash: [u8; 32] = Sha256::digest(yaml.as_bytes()).into();
    let sig_bytes = BASE64.decode(&cred.signature.signature)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| VerifyError::SignatureLength)?;
    key.verify(&hash, &sig)?;
    Ok(())
}

/// SHA-256 hex digest of canonical form. Use as actor_ref in .m3m3tic files.
pub fn content_hash(cred: &Cr3st4n1Credential) -> Result<String, SignError> {
    let hash = canonical_hash(cred)?;
    Ok(hash.iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
        s
    }))
}

/// Raw 32-byte signing payload for external/HSM signers.
pub fn signing_payload(cred: &Cr3st4n1Credential) -> Result<[u8; 32], SignError> {
    canonical_hash(cred)
}

/// Canonical YAML bytes (signature zeroed). Public for pinned-output testing.
pub fn canonical_bytes(cred: &Cr3st4n1Credential) -> Result<Vec<u8>, serde_yaml::Error> {
    canonical_yaml(cred).map(|s| s.into_bytes())
}

// ---- internal ----

fn canonical_yaml(cred: &Cr3st4n1Credential) -> Result<String, serde_yaml::Error> {
    let mut copy = cred.clone();
    copy.signature.signature = String::new();
    serde_yaml::to_string(&copy)
}

fn canonical_hash(cred: &Cr3st4n1Credential) -> Result<[u8; 32], SignError> {
    let yaml = canonical_yaml(cred)?;
    Ok(Sha256::digest(yaml.as_bytes()).into())
}
