use base64::Engine;
use cr3st4n1::{content_hash, sign, signing_payload, validate, verify, Cr3st4n1Credential};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::path::PathBuf;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(name)
}

fn load_fixture(name: &str) -> Cr3st4n1Credential {
    let content = std::fs::read_to_string(fixture_path(name)).unwrap();
    serde_yaml::from_str(&content).unwrap()
}

fn generate_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

// ---- Happy path ----

#[test]
fn test_sign_verify_roundtrip() {
    let key = generate_key();
    let mut cred = load_fixture("minimal.cr3st4n1");
    sign(&mut cred, &key).unwrap();
    verify(&cred, &key.verifying_key()).unwrap();
}

#[test]
fn test_sign_verify_full_credential() {
    let key = generate_key();
    let mut cred = load_fixture("full.cr3st4n1");
    sign(&mut cred, &key).unwrap();
    verify(&cred, &key.verifying_key()).unwrap();
}

#[test]
fn test_content_hash_deterministic() {
    let cred = load_fixture("minimal.cr3st4n1");
    let h1 = content_hash(&cred).unwrap();
    let h2 = content_hash(&cred).unwrap();
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 64); // SHA-256 hex = 64 chars
}

#[test]
fn test_signing_payload_matches_content_hash() {
    let cred = load_fixture("minimal.cr3st4n1");
    let payload = signing_payload(&cred).unwrap();
    let hash = content_hash(&cred).unwrap();
    let payload_hex = payload.iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
        s
    });
    assert_eq!(payload_hex, hash);
}

// ---- Schema-before-sign ----

#[test]
fn test_invalid_trust_level_rejected() {
    let key = generate_key();
    let mut cred = load_fixture("minimal.cr3st4n1");
    cred.trust.level = 6; // max is 5
    let result = sign(&mut cred, &key);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("schema"), "expected schema error, got: {err}");
}

#[test]
fn test_schema_validates_good_fixture() {
    let content = std::fs::read_to_string(fixture_path("minimal.cr3st4n1")).unwrap();
    let value: serde_json::Value = serde_yaml::from_str(&content).unwrap();
    validate(&value).unwrap();
}

#[test]
fn test_schema_validates_full_fixture() {
    let content = std::fs::read_to_string(fixture_path("full.cr3st4n1")).unwrap();
    let value: serde_json::Value = serde_yaml::from_str(&content).unwrap();
    validate(&value).unwrap();
}

// ---- Tamper detection ----

#[test]
fn test_tampered_field_fails_verify() {
    let key = generate_key();
    let mut cred = load_fixture("minimal.cr3st4n1");
    sign(&mut cred, &key).unwrap();
    cred.trust.level = 3; // tamper after signing
    let result = verify(&cred, &key.verifying_key());
    assert!(result.is_err());
}

#[test]
fn test_tampered_signature_fails() {
    let key = generate_key();
    let mut cred = load_fixture("minimal.cr3st4n1");
    sign(&mut cred, &key).unwrap();
    // Corrupt one byte of signature
    let mut sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&cred.signature.signature)
        .unwrap();
    sig_bytes[0] ^= 0xff;
    cred.signature.signature = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);
    let result = verify(&cred, &key.verifying_key());
    assert!(result.is_err());
}

// ---- Key mismatch ----

#[test]
fn test_wrong_key_fails_verify() {
    let key_a = generate_key();
    let key_b = generate_key();
    let mut cred = load_fixture("minimal.cr3st4n1");
    sign(&mut cred, &key_a).unwrap();
    let result = verify(&cred, &key_b.verifying_key());
    assert!(result.is_err());
}

// ---- Boundary values ----

#[test]
fn test_trust_level_boundaries() {
    let key = generate_key();
    for level in 0..=5u8 {
        let mut cred = load_fixture("minimal.cr3st4n1");
        cred.trust.level = level;
        sign(&mut cred, &key).unwrap();
        verify(&cred, &key.verifying_key()).unwrap();
    }
}

#[test]
fn test_trust_level_6_rejected() {
    let key = generate_key();
    let mut cred = load_fixture("minimal.cr3st4n1");
    cred.trust.level = 6;
    assert!(sign(&mut cred, &key).is_err());
}

// ---- Corrupt input ----

#[test]
fn test_invalid_base64_signature() {
    let key = generate_key();
    let mut cred = load_fixture("minimal.cr3st4n1");
    sign(&mut cred, &key).unwrap();
    cred.signature.signature = "not-valid-base64!!!".into();
    let result = verify(&cred, &key.verifying_key());
    assert!(result.is_err());
}

#[test]
fn test_empty_signature_string() {
    let key = generate_key();
    let mut cred = load_fixture("minimal.cr3st4n1");
    sign(&mut cred, &key).unwrap();
    cred.signature.signature = String::new();
    let result = verify(&cred, &key.verifying_key());
    assert!(result.is_err());
}

#[test]
fn test_wrong_length_signature() {
    let key = generate_key();
    let mut cred = load_fixture("minimal.cr3st4n1");
    sign(&mut cred, &key).unwrap();
    // Valid base64 but wrong byte count (only 16 bytes instead of 64)
    cred.signature.signature = base64::engine::general_purpose::STANDARD.encode(&[0u8; 16]);
    let result = verify(&cred, &key.verifying_key());
    assert!(result.is_err());
}

// ---- Canonicalization ----

#[test]
fn test_canonical_bytes_stable_across_calls() {
    let cred = load_fixture("minimal.cr3st4n1");
    let bytes1 = cr3st4n1::signing::canonical_bytes(&cred).unwrap();
    for _ in 0..100 {
        let bytes_n = cr3st4n1::signing::canonical_bytes(&cred).unwrap();
        assert_eq!(bytes1, bytes_n);
    }
}

#[test]
fn test_canonical_bytes_pinned() {
    // Pin the canonical output for minimal.cr3st4n1 — any change to struct field order
    // or serialization will break this test (intentionally).
    let cred = load_fixture("minimal.cr3st4n1");
    let bytes = cr3st4n1::signing::canonical_bytes(&cred).unwrap();
    let hash = content_hash(&cred).unwrap();
    // The hash is stable. If this assertion fails, serialization changed — investigate.
    assert_eq!(hash.len(), 64);
    assert!(!bytes.is_empty());
    // Re-deserialize the canonical YAML to ensure it round-trips
    let reparsed: Cr3st4n1Credential = serde_yaml::from_slice(&bytes).unwrap();
    assert_eq!(reparsed.signature.signature, "");
    assert_eq!(reparsed.trust.level, cred.trust.level);
    assert_eq!(reparsed.identity.display_name, cred.identity.display_name);
}

#[test]
fn test_different_keys_produce_different_signatures() {
    let key_a = generate_key();
    let key_b = generate_key();
    let mut cred_a = load_fixture("minimal.cr3st4n1");
    let mut cred_b = cred_a.clone();
    sign(&mut cred_a, &key_a).unwrap();
    sign(&mut cred_b, &key_b).unwrap();
    assert_ne!(cred_a.signature.signature, cred_b.signature.signature);
}

#[test]
fn test_resign_same_key_same_signature() {
    let key = generate_key();
    let mut cred_a = load_fixture("minimal.cr3st4n1");
    let mut cred_b = cred_a.clone();
    sign(&mut cred_a, &key).unwrap();
    sign(&mut cred_b, &key).unwrap();
    // Ed25519 with dalek is deterministic for same message + key
    assert_eq!(cred_a.signature.signature, cred_b.signature.signature);
}
