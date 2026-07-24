use std::path::PathBuf;
use std::process::Command;

fn bin_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    // Use the same profile as the test binary
    if cfg!(debug_assertions) {
        path.push("debug");
    } else {
        path.push("release");
    }
    path.push(if cfg!(windows) {
        "cr3st4n1.exe"
    } else {
        "cr3st4n1"
    });
    path
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(name)
}

fn cr3st4n1_cmd() -> Command {
    Command::new(bin_path())
}

#[test]
fn test_cli_keygen() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("test-key.json");
    let output = cr3st4n1_cmd()
        .args(["key", "generate", "--output"])
        .arg(&key_path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "keygen failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(key_path.exists());
    let data: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&key_path).unwrap()).unwrap();
    assert!(data["secret"].is_string());
    assert!(data["public"].is_string());
}

#[test]
fn test_cli_sign_verify_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("key.json");
    let signed_path = dir.path().join("signed.cr3st4n1");

    // Generate key
    let output = cr3st4n1_cmd()
        .args(["key", "generate", "--output"])
        .arg(&key_path)
        .output()
        .unwrap();
    assert!(output.status.success());

    // Copy fixture to temp
    std::fs::copy(fixture_path("minimal.cr3st4n1"), &signed_path).unwrap();

    // Sign
    let output = cr3st4n1_cmd()
        .args(["credential", "sign", "--input"])
        .arg(&signed_path)
        .arg("--key")
        .arg(&key_path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "sign failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Extract public key path
    let pub_path = dir.path().join("pub.json");
    let key_data: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&key_path).unwrap()).unwrap();
    let pub_data = serde_json::json!({ "public": key_data["public"] });
    std::fs::write(&pub_path, serde_json::to_string(&pub_data).unwrap()).unwrap();

    // Verify
    let output = cr3st4n1_cmd()
        .args(["credential", "verify", "--input"])
        .arg(&signed_path)
        .arg("--key")
        .arg(&pub_path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_cli_verify_tampered() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("key.json");
    let signed_path = dir.path().join("signed.cr3st4n1");

    // Generate key
    cr3st4n1_cmd()
        .args(["key", "generate", "--output"])
        .arg(&key_path)
        .output()
        .unwrap();

    // Copy and sign
    std::fs::copy(fixture_path("minimal.cr3st4n1"), &signed_path).unwrap();
    cr3st4n1_cmd()
        .args(["credential", "sign", "--input"])
        .arg(&signed_path)
        .arg("--key")
        .arg(&key_path)
        .output()
        .unwrap();

    // Tamper with the signed file
    let content = std::fs::read_to_string(&signed_path).unwrap();
    let tampered = content.replace("Test User", "Tampered User");
    std::fs::write(&signed_path, tampered).unwrap();

    // Extract public key
    let pub_path = dir.path().join("pub.json");
    let key_data: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&key_path).unwrap()).unwrap();
    std::fs::write(
        &pub_path,
        serde_json::json!({ "public": key_data["public"] }).to_string(),
    )
    .unwrap();

    // Verify should fail with exit code 2
    let output = cr3st4n1_cmd()
        .args(["credential", "verify", "--input"])
        .arg(&signed_path)
        .arg("--key")
        .arg(&pub_path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn test_cli_validate_good() {
    let output = cr3st4n1_cmd()
        .args(["credential", "validate", "--input"])
        .arg(fixture_path("minimal.cr3st4n1"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Valid"));
}

#[test]
fn test_cli_validate_bad() {
    let dir = tempfile::tempdir().unwrap();
    let bad_path = dir.path().join("bad.cr3st4n1");
    std::fs::write(&bad_path, "cr3st4n1:\n  version: '1.0.0'\n").unwrap();
    let output = cr3st4n1_cmd()
        .args(["credential", "validate", "--input"])
        .arg(&bad_path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn test_cli_hash() {
    let output = cr3st4n1_cmd()
        .args(["hash", "--input"])
        .arg(fixture_path("minimal.cr3st4n1"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert_eq!(hash.len(), 64, "expected 64-char hex hash, got: {hash}");
}

#[test]
fn test_cli_inspect_minimal() {
    let output = cr3st4n1_cmd()
        .args(["credential", "inspect", "--input"])
        .arg(fixture_path("minimal.cr3st4n1"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Identity: Test User (human)"));
    assert!(stdout.contains("Trust: Level 1 (email_verified)"));
    assert!(stdout.contains("status:    present (use --key to verify)"));
    assert!(stdout.contains("chain:"));
    assert!(stdout.contains("-> bonfire-platform"));
}

#[test]
fn test_cli_inspect_full_ai_agent() {
    let output = cr3st4n1_cmd()
        .args(["credential", "inspect", "--input"])
        .arg(fixture_path("full.cr3st4n1"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Identity: Bonfire Content Bot (ai_agent)"));
    assert!(stdout.contains("operator:"));
    assert!(stdout.contains("model:     claude-opus-4-6"));
    assert!(stdout.contains("Trust: Level 4 (gov_id)"));
    assert!(stdout.contains("providers: 3"));
    assert!(stdout.contains("device:    attested"));
    assert!(stdout.contains("hw:"));
    // 3 chain entries
    assert!(stdout.contains("-> bonfire-platform"));
    assert!(stdout.contains("-> hellosign"));
    assert!(stdout.contains("-> clear-id"));
}

#[test]
fn test_cli_inspect_with_key_valid() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("key.json");
    let signed_path = dir.path().join("signed.cr3st4n1");

    // Generate key and sign
    cr3st4n1_cmd()
        .args(["key", "generate", "--output"])
        .arg(&key_path)
        .output()
        .unwrap();
    std::fs::copy(fixture_path("minimal.cr3st4n1"), &signed_path).unwrap();
    cr3st4n1_cmd()
        .args(["credential", "sign", "--input"])
        .arg(&signed_path)
        .arg("--key")
        .arg(&key_path)
        .output()
        .unwrap();

    // Inspect with --key should show "valid"
    let output = cr3st4n1_cmd()
        .args(["credential", "inspect", "--input"])
        .arg(&signed_path)
        .arg("--key")
        .arg(&key_path)
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("status:    valid"));
}

#[test]
fn test_cli_inspect_with_key_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("key.json");
    let other_key_path = dir.path().join("other-key.json");
    let signed_path = dir.path().join("signed.cr3st4n1");

    // Generate two different keys
    cr3st4n1_cmd()
        .args(["key", "generate", "--output"])
        .arg(&key_path)
        .output()
        .unwrap();
    cr3st4n1_cmd()
        .args(["key", "generate", "--output"])
        .arg(&other_key_path)
        .output()
        .unwrap();

    // Sign with first key
    std::fs::copy(fixture_path("minimal.cr3st4n1"), &signed_path).unwrap();
    cr3st4n1_cmd()
        .args(["credential", "sign", "--input"])
        .arg(&signed_path)
        .arg("--key")
        .arg(&key_path)
        .output()
        .unwrap();

    // Inspect with wrong key should exit 2 and show INVALID
    let output = cr3st4n1_cmd()
        .args(["credential", "inspect", "--input"])
        .arg(&signed_path)
        .arg("--key")
        .arg(&other_key_path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("INVALID"));
}

#[test]
fn test_cli_inspect_json() {
    let output = cr3st4n1_cmd()
        .args(["credential", "inspect", "--input"])
        .arg(fixture_path("minimal.cr3st4n1"))
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("inspect --json must produce valid JSON");
    assert!(json["_inspect"]["content_hash"].is_string());
    assert_eq!(json["_inspect"]["signature_status"], "present");
    assert_eq!(json["_inspect"]["schema_valid"], true);
    assert_eq!(json["identity"]["display_name"], "Test User");
}

#[test]
fn test_cli_missing_input() {
    let output = cr3st4n1_cmd()
        .args([
            "credential",
            "validate",
            "--input",
            "/nonexistent/path.cr3st4n1",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
}
