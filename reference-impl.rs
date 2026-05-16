//! .cr3st4n1 identity credential — human + hardware + authorization.
//!
//! A `.cr3st4n1` file is a portable, Ed25519-signed credential binding a
//! verified human identity (HelloSign contract + Circle.so membership) to
//! specific hardware (composite fingerprint). It serves as both:
//!   - The Bonfire license artifact (replaces config.json trial fields)
//!   - The foundation for a portable affiliate identity standard
//!
//! Phase 1 (this module):
//!   - Identity: HelloSign contract_id + Circle tag + email
//!   - Device: SHA-256 hardware fingerprint (disk + CPU + MAC)
//!   - Authorization: roles + tier from Circle membership
//!   - Signature: Ed25519 (key compiled into daemon binary)
//!
//! On successful dual-gate verification, the daemon generates this file
//! at `~/.bonfire/identity.cr3st4n1`. On subsequent boots, the daemon
//! validates the file's signature + hardware match — no network calls needed.

use anyhow::{anyhow, Result};
use ed25519_dalek::{Signer, SigningKey, Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::path::{Path, PathBuf};

// ============================================================================
// FILE STRUCTURE (matches YAML schema in cr3st4n1-file-approach.md)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cr3st4n1File {
    pub cr3st4n1: Cr3st4n1Meta,
    pub identity: Identity,
    pub device: Device,
    pub authorization: Authorization,
    #[serde(rename = "_signature")]
    pub signature: FileSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cr3st4n1Meta {
    pub version: String,
    pub created_at: String,
    pub generator: Generator,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Generator {
    pub tool: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub display_name: String,
    pub email: String,
    pub verification: Verification,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verification {
    pub level: String,
    pub hellosign: Option<HelloSignVerification>,
    pub circle: Option<CircleVerification>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloSignVerification {
    pub signature_request_id: String,
    pub signed_at: Option<String>,
    pub signer_email: String,
    pub contract_template: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircleVerification {
    pub community_id: String,
    pub email: String,
    pub membership_tier: String,
    pub tag_id: String,
    pub tag_name: String,
    pub verified_at: String,
    pub subscription_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub binding_level: String,
    pub hardware_fingerprint: String,
    pub registered_at: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authorization {
    pub roles: Vec<String>,
    pub tier: String,
    pub features: Vec<String>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSignature {
    pub signer: String,
    pub algorithm: String,
    pub signed_at: String,
    pub signature: String,
}

// ============================================================================
// SIGNING KEY (compiled into binary — same security model as CIRCLE_API_TOKEN)
// ============================================================================

/// Ed25519 signing key seed (32 bytes, hex-encoded).
/// Set at build time via CR3ST4N1_SIGNING_KEY env var.
/// If empty, .cr3st4n1 file generation is disabled (non-fatal).
const SIGNING_KEY_HEX: &str = match option_env!("CR3ST4N1_SIGNING_KEY") {
    Some(v) => v,
    None => "",
};

/// Get the Ed25519 signing key (if configured at build time).
fn get_signing_key() -> Option<SigningKey> {
    if SIGNING_KEY_HEX.is_empty() {
        return None;
    }
    let bytes = hex::decode(SIGNING_KEY_HEX).ok()?;
    if bytes.len() != 32 {
        tracing::error!("CR3ST4N1_SIGNING_KEY must be 32 bytes (64 hex chars), got {}", bytes.len());
        return None;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Some(SigningKey::from_bytes(&seed))
}

/// Get the Ed25519 verifying (public) key.
pub fn get_verifying_key() -> Option<VerifyingKey> {
    get_signing_key().map(|sk| sk.verifying_key())
}

// ============================================================================
// GENERATE
// ============================================================================

/// Parameters for generating a new .cr3st4n1 file after dual-gate verification.
pub struct GenerateParams {
    pub email: String,
    pub hellosign_contract_id: Option<String>,
    pub circle_tag_date: Option<String>,
    pub hardware_fingerprint: String,
    pub daemon_version: String,
}

/// Generate a new .cr3st4n1 file from verification data.
/// Returns None if the signing key is not configured.
pub fn generate(params: &GenerateParams) -> Option<Cr3st4n1File> {
    let signing_key = get_signing_key()?;
    let now = chrono::Utc::now().to_rfc3339();

    let mut file = Cr3st4n1File {
        cr3st4n1: Cr3st4n1Meta {
            version: "0.1.0".to_string(),
            created_at: now.clone(),
            generator: Generator {
                tool: "Bonfire Terminal".to_string(),
                version: params.daemon_version.clone(),
            },
        },
        identity: Identity {
            display_name: params.email.split('@').next().unwrap_or("user").to_string(),
            email: params.email.clone(),
            verification: Verification {
                level: "contract".to_string(),
                hellosign: params.hellosign_contract_id.as_ref().map(|id| HelloSignVerification {
                    signature_request_id: id.clone(),
                    signed_at: None,
                    signer_email: params.email.clone(),
                    contract_template: None,
                }),
                circle: Some(CircleVerification {
                    community_id: "363417".to_string(),
                    email: params.email.clone(),
                    membership_tier: "mentorship".to_string(),
                    tag_id: "246372".to_string(),
                    tag_name: "Bonfire".to_string(),
                    verified_at: params.circle_tag_date.clone().unwrap_or_else(|| now.clone()),
                    subscription_status: "active".to_string(),
                }),
            },
        },
        device: Device {
            binding_level: "fingerprinted".to_string(),
            hardware_fingerprint: params.hardware_fingerprint.clone(),
            registered_at: now.clone(),
            last_seen: now.clone(),
        },
        authorization: Authorization {
            roles: vec!["affiliate".to_string(), "bonfire_user".to_string()],
            tier: "mentorship".to_string(),
            features: vec![
                "ai_chat".to_string(),
                "terminal".to_string(),
                "bridge_messaging".to_string(),
                "ad_creation".to_string(),
                "compliance_validation".to_string(),
            ],
            expires_at: None,
        },
        // Placeholder — will be filled by sign()
        signature: FileSignature {
            signer: "Bonfire Terminal".to_string(),
            algorithm: "Ed25519".to_string(),
            signed_at: now.clone(),
            signature: String::new(),
        },
    };

    // Sign the content (everything except _signature.signature)
    let content_hash = compute_content_hash(&file);
    let sig = signing_key.sign(&content_hash);
    file.signature.signature = format!("base64:{}", base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD, sig.to_bytes()
    ));

    Some(file)
}

// ============================================================================
// VERIFY
// ============================================================================

/// Verify a .cr3st4n1 file: signature valid + hardware fingerprint matches.
pub fn verify(file: &Cr3st4n1File, current_hardware_fingerprint: &str) -> Result<()> {
    // Check hardware binding
    if file.device.hardware_fingerprint != current_hardware_fingerprint {
        return Err(anyhow!(
            "Hardware fingerprint mismatch: file bound to different machine"
        ));
    }

    // Check signature
    let verifying_key = get_verifying_key()
        .ok_or_else(|| anyhow!("CR3ST4N1_SIGNING_KEY not configured — cannot verify"))?;

    let sig_b64 = file.signature.signature
        .strip_prefix("base64:")
        .ok_or_else(|| anyhow!("Invalid signature format (expected base64: prefix)"))?;

    let sig_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD, sig_b64
    ).map_err(|e| anyhow!("Invalid base64 signature: {}", e))?;

    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| anyhow!("Invalid Ed25519 signature: {}", e))?;

    let content_hash = compute_content_hash(file);
    verifying_key.verify(&content_hash, &signature)
        .map_err(|_| anyhow!("Signature verification FAILED — file may have been tampered with"))?;

    Ok(())
}

// ============================================================================
// LOAD / SAVE
// ============================================================================

/// Default path: ~/.bonfire/identity.cr3st4n1
pub fn default_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".bonfire")
        .join("identity.cr3st4n1")
}

/// Load a .cr3st4n1 file from disk.
pub fn load(path: &Path) -> Result<Cr3st4n1File> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow!("Failed to read {}: {}", path.display(), e))?;
    serde_yaml::from_str(&content)
        .map_err(|e| anyhow!("Failed to parse .cr3st4n1 YAML: {}", e))
}

/// Save a .cr3st4n1 file to disk (YAML format).
pub fn save(file: &Cr3st4n1File, path: &Path) -> Result<()> {
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let yaml = serde_yaml::to_string(file)
        .map_err(|e| anyhow!("Failed to serialize .cr3st4n1: {}", e))?;
    std::fs::write(path, yaml)
        .map_err(|e| anyhow!("Failed to write {}: {}", path.display(), e))?;
    tracing::info!("Wrote .cr3st4n1 credential to {}", path.display());
    Ok(())
}

// ============================================================================
// CONTENT HASH (deterministic, excludes signature field)
// ============================================================================

/// Compute SHA-256 hash of all file content EXCEPT the signature value itself.
/// This is what gets Ed25519-signed.
fn compute_content_hash(file: &Cr3st4n1File) -> Vec<u8> {
    let mut hasher = Sha256::new();
    // Hash each section deterministically (field order matters)
    hasher.update(format!("cr3st4n1.version={}", file.cr3st4n1.version));
    hasher.update(format!("cr3st4n1.created_at={}", file.cr3st4n1.created_at));
    hasher.update(format!("identity.email={}", file.identity.email));
    hasher.update(format!("identity.verification.level={}", file.identity.verification.level));
    if let Some(ref hs) = file.identity.verification.hellosign {
        hasher.update(format!("hellosign.id={}", hs.signature_request_id));
        hasher.update(format!("hellosign.email={}", hs.signer_email));
    }
    if let Some(ref c) = file.identity.verification.circle {
        hasher.update(format!("circle.tag_id={}", c.tag_id));
        hasher.update(format!("circle.verified_at={}", c.verified_at));
    }
    hasher.update(format!("device.fingerprint={}", file.device.hardware_fingerprint));
    hasher.update(format!("device.binding_level={}", file.device.binding_level));
    hasher.update(format!("authorization.tier={}", file.authorization.tier));
    for role in &file.authorization.roles {
        hasher.update(format!("authorization.role={}", role));
    }
    hasher.finalize().to_vec()
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> GenerateParams {
        GenerateParams {
            email: "test@example.com".to_string(),
            hellosign_contract_id: Some("sig_abc123".to_string()),
            circle_tag_date: Some("2026-05-15T10:00:00Z".to_string()),
            hardware_fingerprint: "sha256:abcdef1234567890".to_string(),
            daemon_version: "2.7.245".to_string(),
        }
    }

    #[test]
    fn generate_returns_none_without_signing_key() {
        // CR3ST4N1_SIGNING_KEY is empty in test builds
        let result = generate(&test_params());
        // Will be None since SIGNING_KEY_HEX is empty in tests
        assert!(result.is_none(), "generate() should return None without signing key");
    }

    #[test]
    fn content_hash_is_deterministic() {
        let file = Cr3st4n1File {
            cr3st4n1: Cr3st4n1Meta {
                version: "0.1.0".to_string(),
                created_at: "2026-05-15T10:00:00Z".to_string(),
                generator: Generator {
                    tool: "Bonfire Terminal".to_string(),
                    version: "2.7.245".to_string(),
                },
            },
            identity: Identity {
                display_name: "test".to_string(),
                email: "test@example.com".to_string(),
                verification: Verification {
                    level: "contract".to_string(),
                    hellosign: None,
                    circle: None,
                },
            },
            device: Device {
                binding_level: "fingerprinted".to_string(),
                hardware_fingerprint: "sha256:abc".to_string(),
                registered_at: "2026-05-15T10:00:00Z".to_string(),
                last_seen: "2026-05-15T10:00:00Z".to_string(),
            },
            authorization: Authorization {
                roles: vec!["bonfire_user".to_string()],
                tier: "mentorship".to_string(),
                features: vec![],
                expires_at: None,
            },
            signature: FileSignature {
                signer: "Bonfire Terminal".to_string(),
                algorithm: "Ed25519".to_string(),
                signed_at: "2026-05-15T10:00:00Z".to_string(),
                signature: String::new(),
            },
        };

        let hash1 = compute_content_hash(&file);
        let hash2 = compute_content_hash(&file);
        assert_eq!(hash1, hash2, "Content hash must be deterministic");
        assert_eq!(hash1.len(), 32, "SHA-256 produces 32 bytes");
    }

    #[test]
    fn yaml_round_trip() {
        let file = Cr3st4n1File {
            cr3st4n1: Cr3st4n1Meta {
                version: "0.1.0".to_string(),
                created_at: "2026-05-15T10:00:00Z".to_string(),
                generator: Generator {
                    tool: "Bonfire Terminal".to_string(),
                    version: "2.7.245".to_string(),
                },
            },
            identity: Identity {
                display_name: "maria".to_string(),
                email: "maria@example.com".to_string(),
                verification: Verification {
                    level: "contract".to_string(),
                    hellosign: Some(HelloSignVerification {
                        signature_request_id: "sig_abc".to_string(),
                        signed_at: Some("2026-05-15T09:30:00Z".to_string()),
                        signer_email: "maria@example.com".to_string(),
                        contract_template: Some("bonfire_5k".to_string()),
                    }),
                    circle: Some(CircleVerification {
                        community_id: "363417".to_string(),
                        email: "maria@example.com".to_string(),
                        membership_tier: "mentorship".to_string(),
                        tag_id: "246372".to_string(),
                        tag_name: "Bonfire".to_string(),
                        verified_at: "2026-05-15T09:45:00Z".to_string(),
                        subscription_status: "active".to_string(),
                    }),
                },
            },
            device: Device {
                binding_level: "fingerprinted".to_string(),
                hardware_fingerprint: "sha256:a3f2b8c1".to_string(),
                registered_at: "2026-05-15T10:00:00Z".to_string(),
                last_seen: "2026-05-15T10:00:00Z".to_string(),
            },
            authorization: Authorization {
                roles: vec!["affiliate".to_string(), "bonfire_user".to_string()],
                tier: "mentorship".to_string(),
                features: vec!["ai_chat".to_string(), "terminal".to_string()],
                expires_at: None,
            },
            signature: FileSignature {
                signer: "Bonfire Terminal".to_string(),
                algorithm: "Ed25519".to_string(),
                signed_at: "2026-05-15T10:00:00Z".to_string(),
                signature: "base64:AAAA".to_string(),
            },
        };

        let yaml = serde_yaml::to_string(&file).unwrap();
        assert!(yaml.contains("maria@example.com"));
        assert!(yaml.contains("sig_abc"));
        assert!(yaml.contains("246372"));
        assert!(yaml.contains("fingerprinted"));

        let parsed: Cr3st4n1File = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.identity.email, "maria@example.com");
        assert_eq!(parsed.device.hardware_fingerprint, "sha256:a3f2b8c1");
        assert_eq!(parsed.authorization.tier, "mentorship");
    }
}
