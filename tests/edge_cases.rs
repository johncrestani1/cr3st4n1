use cr3st4n1::{content_hash, sign, validate, Cr3st4n1Credential};
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

// ---- Schema conditional: AI agent ----

#[test]
fn test_ai_agent_without_metadata_fails_schema() {
    let mut cred = load_fixture("full.cr3st4n1");
    // full.cr3st4n1 has type=ai_agent with ai_agent_metadata.
    // Remove the metadata — schema should reject.
    cred.identity.ai_agent_metadata = None;
    let value = serde_json::to_value(&cred).unwrap();
    let result = validate(&value);
    assert!(
        result.is_err(),
        "ai_agent without ai_agent_metadata should fail schema validation"
    );
}

#[test]
fn test_human_with_ai_metadata_passes_schema() {
    // Schema only *requires* ai_agent_metadata when type=ai_agent.
    // A human with ai_agent_metadata is allowed (not required, but not forbidden).
    let mut cred = load_fixture("full.cr3st4n1");
    cred.identity.identity_type = cr3st4n1::types::IdentityType::Human;
    // Keep ai_agent_metadata — should still pass
    let value = serde_json::to_value(&cred).unwrap();
    let result = validate(&value);
    assert!(
        result.is_ok(),
        "human with ai_agent_metadata should pass: {result:?}"
    );
}

// ---- Schema conditional: device binding ----

#[test]
fn test_fingerprinted_without_hw_fingerprint_fails() {
    let mut cred = load_fixture("minimal.cr3st4n1");
    cred.device.binding_level = cr3st4n1::types::BindingLevel::Fingerprinted;
    cred.device.hardware_fingerprint = None;
    let value = serde_json::to_value(&cred).unwrap();
    let result = validate(&value);
    assert!(
        result.is_err(),
        "fingerprinted without hardware_fingerprint should fail schema validation"
    );
}

#[test]
fn test_none_binding_with_hw_fingerprint_passes() {
    let mut cred = load_fixture("minimal.cr3st4n1");
    cred.device.binding_level = cr3st4n1::types::BindingLevel::None;
    cred.device.hardware_fingerprint = Some("sha256:abc123".into());
    let value = serde_json::to_value(&cred).unwrap();
    let result = validate(&value);
    assert!(
        result.is_ok(),
        "none binding with hardware_fingerprint should pass: {result:?}"
    );
}

// ---- Malformed input ----

#[test]
fn test_yaml_with_utf8_bom() {
    let content = std::fs::read_to_string(fixture_path("minimal.cr3st4n1")).unwrap();
    let with_bom = format!("\u{FEFF}{content}");
    let result: Result<Cr3st4n1Credential, _> = serde_yaml::from_str(&with_bom);
    // serde_yaml should handle BOM gracefully (either parse or give clear error)
    // We just verify no panic
    let _ = result;
}

#[test]
fn test_empty_file_parse_error() {
    let result: Result<Cr3st4n1Credential, _> = serde_yaml::from_str("");
    assert!(result.is_err(), "empty file should produce parse error");
}

#[test]
fn test_truncated_yaml_parse_error() {
    let result: Result<Cr3st4n1Credential, _> =
        serde_yaml::from_str("cr3st4n1:\n  version: \"1.0.0\"\n  created_at:");
    assert!(result.is_err(), "truncated YAML should produce parse error");
}

#[test]
fn test_json_as_yaml_parses() {
    // JSON is valid YAML. Verify a JSON-formatted credential parses.
    let cred = load_fixture("minimal.cr3st4n1");
    let json_str = serde_json::to_string_pretty(&cred).unwrap();
    let reparsed: Result<Cr3st4n1Credential, _> = serde_yaml::from_str(&json_str);
    assert!(reparsed.is_ok(), "JSON should parse as valid YAML");
    assert_eq!(reparsed.unwrap(), cred);
}

// ---- Content hash stability ----

#[test]
fn test_hash_stable_after_roundtrip() {
    // Load from disk, deserialize, re-serialize, hash — should match original hash
    let cred = load_fixture("minimal.cr3st4n1");
    let hash1 = content_hash(&cred).unwrap();

    // Re-serialize and re-parse
    let yaml = serde_yaml::to_string(&cred).unwrap();
    let reparsed: Cr3st4n1Credential = serde_yaml::from_str(&yaml).unwrap();
    let hash2 = content_hash(&reparsed).unwrap();

    assert_eq!(hash1, hash2, "hash should be stable after roundtrip");
}

#[test]
fn test_hash_changes_when_field_changes() {
    let cred = load_fixture("minimal.cr3st4n1");
    let hash1 = content_hash(&cred).unwrap();

    let mut modified = cred;
    modified.identity.display_name = "Different Name".into();
    let hash2 = content_hash(&modified).unwrap();

    assert_ne!(hash1, hash2, "hash should change when field changes");
}

// ---- Credential lifecycle ----

#[test]
fn test_resign_changes_content_hash() {
    let key = generate_key();
    let mut cred = load_fixture("minimal.cr3st4n1");
    let hash_before = content_hash(&cred).unwrap();

    // Change signer identity before signing
    cred.signature.signer = "new-signer".into();
    sign(&mut cred, &key).unwrap();

    // Content hash includes signer field (with signature zeroed)
    let hash_after = content_hash(&cred).unwrap();
    assert_ne!(
        hash_before, hash_after,
        "changing signer should change content hash"
    );
}

#[test]
fn test_content_hash_differs_between_fixtures() {
    let minimal = load_fixture("minimal.cr3st4n1");
    let full = load_fixture("full.cr3st4n1");
    let h1 = content_hash(&minimal).unwrap();
    let h2 = content_hash(&full).unwrap();
    assert_ne!(h1, h2, "different credentials should have different hashes");
}
