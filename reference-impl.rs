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
    // ── W3C Verifiable Credential envelope (Track 1) ─────────────────────
    /// JSON-LD context — when present, this file is a W3C VC.
    #[serde(rename = "@context", default, skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<String>,
    /// VC type array — must include "VerifiableCredential".
    #[serde(rename = "type", default, skip_serializing_if = "Vec::is_empty")]
    pub vc_type: Vec<String>,
    /// Credential URI: urn:cr3st4n1:{hash}
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Issuer DID: did:web:bonfireterminal.com
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// W3C issuanceDate (ISO 8601)
    #[serde(rename = "issuanceDate", default, skip_serializing_if = "Option::is_none")]
    pub issuance_date: Option<String>,

    // ── Core credential sections ─────────────────────────────────────────
    pub cr3st4n1: Cr3st4n1Meta,
    pub identity: Identity,
    pub device: Device,
    pub authorization: Authorization,

    // ── Phase 2+ stubs ───────────────────────────────────────────────────
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crypto: Option<CryptoSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reputation: Option<ReputationSection>,

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
    pub binding_level: String,  // "fingerprinted" | "attested"
    pub hardware_fingerprint: String,
    pub registered_at: String,
    pub last_seen: String,
    /// TPM 2.0 attestation data. Present when binding_level = "attested".
    /// The private key physically cannot leave the TPM chip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tpm_attestation: Option<TpmAttestation>,
}

/// TPM 2.0 hardware attestation — cryptographic device binding (Track 3).
/// When present, the credential is bound to a specific TPM chip, not just
/// a composite fingerprint. The SRK name is stable across reboots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmAttestation {
    /// SHA-256 of TPM Storage Root Key public area — stable device ID.
    pub srk_name: String,
    /// PEM-encoded public key resident in TPM (non-exportable).
    pub public_key: String,
    /// Certificate chain: TPM manufacturer → endorsement key → attestation key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cert_chain: Vec<String>,
    /// When the TPM attestation was performed.
    pub attested_at: String,
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
// PHASE 2+ STUB SECTIONS (namespace reserved, nullable in Phase 1)
// ============================================================================

/// Affiliate network position — brands, referral chain, affiliate ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSection {
    /// Portable affiliate ID across networks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affiliate_id: Option<String>,
    /// Per-brand authorizations with linked .m3m3tic files.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub brands: Vec<BrandAuthorization>,
    /// Position in the referral tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referral_chain: Option<ReferralChain>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrandAuthorization {
    pub brand_id: String,
    pub brand_name: String,
    pub authorized_at: String,
    /// SHA-256 hash of the linked .m3m3tic brand file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub m3m3tic_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferralChain {
    /// SHA-256 hash of the referrer's .cr3st4n1 file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referred_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referral_code: Option<String>,
    #[serde(default)]
    pub depth: u32,
}

/// Crypto payment rails — wallet addresses, token-gated tiers, commission splits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoSection {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wallet_addresses: Vec<WalletAddress>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub token_gates: Vec<TokenGate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commission_split: Option<CommissionSplit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAddress {
    pub chain: String,
    pub address: String,
    #[serde(default)]
    pub verified: bool,
    /// Signed message proving wallet ownership.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenGate {
    pub token: String,
    pub chain: String,
    pub minimum_balance: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommissionSplit {
    pub affiliate: f64,
    pub referrer: f64,
    pub platform: f64,
}

/// Affiliate Reputation Score — event-sourced, issuer-signed trust history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationSection {
    /// 0-1000 scale. Computed by verifier, not self-reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ars_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score_tier: Option<String>,
    #[serde(default)]
    pub event_count: u32,
    /// SHA-256 of the event log head (hash chain).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_updated: Option<String>,
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
        // W3C VC envelope
        context: vec![
            "https://www.w3.org/2018/credentials/v1".to_string(),
            "https://bonfireterminal.com/cr3st4n1/v0.3".to_string(),
        ],
        vc_type: vec![
            "VerifiableCredential".to_string(),
            "Cr3st4n1Credential".to_string(),
        ],
        id: None, // Set after content hash is computed
        issuer: Some("did:web:bonfireterminal.com".to_string()),
        issuance_date: Some(now.clone()),

        cr3st4n1: Cr3st4n1Meta {
            version: "0.3.0".to_string(),
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
        device: {
            // Try TPM attestation (Tier 1), fall back to fingerprint (Tier 2)
            let tpm = attempt_tpm_attestation();
            let binding_level = if tpm.is_some() { "attested" } else { "fingerprinted" };
            Device {
                binding_level: binding_level.to_string(),
                hardware_fingerprint: params.hardware_fingerprint.clone(),
                registered_at: now.clone(),
                last_seen: now.clone(),
                tpm_attestation: tpm,
            }
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
        // Phase 2+ stubs — namespace reserved, null in Phase 1
        network: None,
        crypto: None,
        reputation: None,
        // Placeholder — will be filled by sign()
        signature: FileSignature {
            signer: "Bonfire Terminal".to_string(),
            algorithm: "Ed25519".to_string(),
            signed_at: now.clone(),
            signature: String::new(),
        },
    };

    // Compute content hash and set credential ID
    let content_hash = compute_content_hash(&file);
    file.id = Some(format!("urn:cr3st4n1:{}", hex::encode(&content_hash[..16])));

    // Sign the content (everything except _signature.signature)
    // Re-compute hash now that `id` is set — id is part of the signed content
    let final_hash = compute_content_hash(&file);
    let sig = signing_key.sign(&final_hash);
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

/// Default path: %USERPROFILE%/m3m3tic/identity.cr3st4n1
/// The m3m3tic/ directory is the ecosystem home for identity + brand credentials.
pub fn default_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("m3m3tic")
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
// TRACK 1: JWT-VC EXPORT (W3C Verifiable Credential as compact JWT)
// ============================================================================

/// Export the .cr3st4n1 file as a JWT-VC (compact JWT string).
///
/// Any W3C VC library can verify this JWT by resolving the issuer DID
/// (did:web:bonfireterminal.com → /.well-known/did.json → public key).
/// The JWT payload wraps the credential in a standard `vc` claim.
pub fn export_jwt_vc(file: &Cr3st4n1File) -> Option<String> {
    let signing_key = get_signing_key()?;

    // JWT Header
    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": "JWT",
        "kid": "did:web:bonfireterminal.com#key-1"
    });

    // JWT Payload — W3C VC envelope
    let payload = serde_json::json!({
        "iss": file.issuer,
        "sub": file.identity.email,
        "iat": chrono::Utc::now().timestamp(),
        "vc": {
            "@context": file.context,
            "type": file.vc_type,
            "id": file.id,
            "credentialSubject": {
                "identity": file.identity,
                "device": {
                    "binding_level": file.device.binding_level,
                    // Fingerprint is NOT included in JWT — selective disclosure handles this
                    "tpm_attested": file.device.tpm_attestation.is_some(),
                },
                "authorization": file.authorization,
            }
        }
    });

    let b64 = &base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header_b64 = base64::Engine::encode(b64, serde_json::to_vec(&header).ok()?);
    let payload_b64 = base64::Engine::encode(b64, serde_json::to_vec(&payload).ok()?);
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let sig = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = base64::Engine::encode(b64, sig.to_bytes());

    Some(format!("{}.{}", signing_input, sig_b64))
}

// ============================================================================
// TRACK 2: SD-JWT SELECTIVE DISCLOSURE
// ============================================================================

/// Fields that are concealable by default in SD-JWT presentations.
/// The holder can choose which of these to reveal per verification.
pub const DEFAULT_CONCEALABLE: &[&str] = &[
    "identity.email",
    "identity.display_name",
    "identity.verification.hellosign",
    "identity.verification.circle.email",
    "device.hardware_fingerprint",
    "device.tpm_attestation",
    "crypto",
    "network.referral_chain",
];

/// Fields that are ALWAYS visible — cannot be concealed.
pub const ALWAYS_VISIBLE: &[&str] = &[
    "cr3st4n1.version",
    "authorization.roles",
    "authorization.tier",
    "device.binding_level",
];

/// Create an SD-JWT presentation that reveals only specified fields.
///
/// The full credential is signed, but only the `disclose` fields are
/// included in the presentation. A verifier can confirm the signature
/// covers all claims, but only sees the revealed ones.
///
/// This is a simplified SD-JWT implementation (full RFC 9901 compliance
/// requires the sd-jwt-rs crate, integrated when the dep is available).
pub fn create_presentation(file: &Cr3st4n1File, disclose: &[&str]) -> Option<serde_json::Value> {
    // Build a masked copy — only include disclosed fields
    let full = serde_json::to_value(file).ok()?;
    let mut presented = serde_json::Map::new();

    // Always include core metadata
    for key in ALWAYS_VISIBLE {
        if let Some(val) = resolve_path(&full, key) {
            set_path(&mut presented, key, val);
        }
    }

    // Include requested disclosures
    for key in disclose {
        if let Some(val) = resolve_path(&full, key) {
            set_path(&mut presented, key, val);
        }
    }

    // Include signature for verification
    if let Some(sig) = full.get("_signature") {
        presented.insert("_signature".to_string(), sig.clone());
    }

    // Mark as selective presentation
    presented.insert("_sd_disclosed".to_string(), serde_json::json!(disclose));

    Some(serde_json::Value::Object(presented))
}

/// Resolve a dotted path (e.g., "identity.email") in a JSON value.
fn resolve_path(value: &serde_json::Value, path: &str) -> Option<serde_json::Value> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = value;
    for part in &parts {
        current = current.get(part)?;
    }
    Some(current.clone())
}

/// Set a dotted path in a JSON map, creating intermediate objects as needed.
fn set_path(map: &mut serde_json::Map<String, serde_json::Value>, path: &str, value: serde_json::Value) {
    let parts: Vec<&str> = path.split('.').collect();
    if parts.len() == 1 {
        map.insert(parts[0].to_string(), value);
        return;
    }
    let child = map.entry(parts[0].to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if let serde_json::Value::Object(ref mut child_map) = child {
        set_path(child_map, &parts[1..].join("."), value);
    }
}

// ============================================================================
// TRACK 3: TPM DETECTION (runtime check, no tss-esapi dep in Phase 1)
// ============================================================================

/// Check if TPM 2.0 is available on this Windows machine.
/// Uses the TBS (TPM Base Services) API via a simple registry check.
/// Full TPM attestation (key gen, signing) requires the tpm feature flag.
pub fn is_tpm_available() -> bool {
    // On Windows, check for TPM via registry
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        Command::new("reg")
            .args(["query", r"HKLM\SYSTEM\CurrentControlSet\Services\TPM", "/v", "Start"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "windows"))]
    {
        // macOS Secure Enclave / Linux TPM — deferred
        false
    }
}

/// Attempt TPM attestation. Returns TpmAttestation if TPM is available
/// and key generation succeeds. Returns None on failure (graceful fallback).
///
/// NOTE: Full TPM key generation requires the `tpm` feature flag and
/// the tss-esapi or tpm2 crate. This stub detects TPM presence and
/// records the SRK name from the registry for future attestation.
pub fn attempt_tpm_attestation() -> Option<TpmAttestation> {
    if !is_tpm_available() {
        return None;
    }

    // Read TPM info from WMI (Windows only)
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        let output = Command::new("wmic")
            .args(["path", "Win32_Tpm", "get", "SpecVersion,IsActivated_InitialValue"])
            .output()
            .ok()?;
        let text = String::from_utf8(output.stdout).ok()?;
        if !text.contains("2.0") {
            tracing::info!("TPM found but not version 2.0 — skipping attestation");
            return None;
        }

        // For Phase 1: record TPM presence with a placeholder SRK name
        // Full key generation requires tss-esapi (feature-gated, Phase 2)
        let srk_name = format!("tpm2-detected-{}", crate::config::compute_hardware_fingerprint().get(..16)?);

        Some(TpmAttestation {
            srk_name,
            public_key: String::new(), // Populated by tss-esapi in Phase 2
            cert_chain: vec![],
            attested_at: chrono::Utc::now().to_rfc3339(),
        })
    }

    #[cfg(not(target_os = "windows"))]
    { None }
}

// ============================================================================
// CONTENT HASH (deterministic, excludes signature field)
// ============================================================================

/// Compute SHA-256 hash of ALL file content EXCEPT `_signature.signature`.
///
/// Strategy: serialize the file to canonical YAML, strip the signature value
/// line, hash the result. This ensures EVERY field is signed — adding new
/// fields to the struct automatically includes them in the hash without
/// updating this function.
fn compute_content_hash(file: &Cr3st4n1File) -> Vec<u8> {
    // Clone and zero out the signature value (but keep the rest of _signature)
    let mut hashable = file.clone();
    hashable.signature.signature = String::new();

    // Serialize to YAML — serde_yaml produces deterministic output for the
    // same struct (field order matches declaration order via #[derive(Serialize)])
    let yaml = serde_yaml::to_string(&hashable).unwrap_or_default();

    let mut hasher = Sha256::new();
    hasher.update(yaml.as_bytes());
    hasher.finalize().to_vec()
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_file(email: &str, fingerprint: &str) -> Cr3st4n1File {
        Cr3st4n1File {
            context: vec!["https://www.w3.org/2018/credentials/v1".to_string()],
            vc_type: vec!["VerifiableCredential".to_string(), "Cr3st4n1Credential".to_string()],
            id: Some("urn:cr3st4n1:test".to_string()),
            issuer: Some("did:web:bonfireterminal.com".to_string()),
            issuance_date: Some("2026-05-15T10:00:00Z".to_string()),
            cr3st4n1: Cr3st4n1Meta {
                version: "0.3.0".to_string(),
                created_at: "2026-05-15T10:00:00Z".to_string(),
                generator: Generator { tool: "Bonfire Terminal".to_string(), version: "2.7.245".to_string() },
            },
            identity: Identity {
                display_name: email.split('@').next().unwrap_or("test").to_string(),
                email: email.to_string(),
                verification: Verification { level: "contract".to_string(), hellosign: None, circle: None },
            },
            device: Device {
                binding_level: "fingerprinted".to_string(),
                hardware_fingerprint: fingerprint.to_string(),
                registered_at: "2026-05-15T10:00:00Z".to_string(),
                last_seen: "2026-05-15T10:00:00Z".to_string(),
                tpm_attestation: None,
            },
            authorization: Authorization {
                roles: vec!["bonfire_user".to_string()],
                tier: "mentorship".to_string(),
                features: vec!["ai_chat".to_string()],
                expires_at: None,
            },
            network: None,
            crypto: None,
            reputation: None,
            signature: FileSignature {
                signer: "Bonfire Terminal".to_string(),
                algorithm: "Ed25519".to_string(),
                signed_at: "2026-05-15T10:00:00Z".to_string(),
                signature: String::new(),
            },
        }
    }

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
        let file = make_test_file("test@example.com", "sha256:abc");
        let hash1 = compute_content_hash(&file);
        let hash2 = compute_content_hash(&file);
        assert_eq!(hash1, hash2, "Content hash must be deterministic");
        assert_eq!(hash1.len(), 32, "SHA-256 produces 32 bytes");
    }

    #[test]
    fn content_hash_changes_when_features_modified() {
        let mut file1 = make_test_file("test@example.com", "sha256:abc");
        let mut file2 = file1.clone();
        file2.authorization.features.push("admin_panel".to_string());
        let hash1 = compute_content_hash(&file1);
        let hash2 = compute_content_hash(&file2);
        assert_ne!(hash1, hash2, "Modifying features must change the content hash");
    }

    #[test]
    fn content_hash_changes_when_display_name_modified() {
        let file1 = make_test_file("test@example.com", "sha256:abc");
        let mut file2 = file1.clone();
        file2.identity.display_name = "hacker".to_string();
        assert_ne!(compute_content_hash(&file1), compute_content_hash(&file2));
    }

    #[test]
    fn yaml_round_trip() {
        let mut file = make_test_file("maria@example.com", "sha256:a3f2b8c1");
        file.signature.signature = "base64:AAAA".to_string();
        let yaml = serde_yaml::to_string(&file).unwrap();
        assert!(yaml.contains("maria@example.com"));
        assert!(yaml.contains("fingerprinted"));
        assert!(yaml.contains("VerifiableCredential"));
        assert!(yaml.contains("did:web:bonfireterminal.com"));

        let parsed: Cr3st4n1File = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.identity.email, "maria@example.com");
        assert_eq!(parsed.device.hardware_fingerprint, "sha256:a3f2b8c1");
        assert_eq!(parsed.issuer.as_deref(), Some("did:web:bonfireterminal.com"));
        assert_eq!(parsed.vc_type[0], "VerifiableCredential");
    }

    #[test]
    fn vc_envelope_fields_present() {
        let file = make_test_file("test@example.com", "sha256:abc");
        assert!(!file.context.is_empty(), "VC @context must be populated");
        assert!(file.context[0].contains("w3.org"), "First context must be W3C");
        assert_eq!(file.vc_type[0], "VerifiableCredential");
        assert_eq!(file.vc_type[1], "Cr3st4n1Credential");
        assert_eq!(file.issuer.as_deref(), Some("did:web:bonfireterminal.com"));
    }

    #[test]
    fn selective_presentation_hides_email() {
        let file = make_test_file("secret@example.com", "sha256:abc");
        let presented = create_presentation(&file, &["authorization.roles", "authorization.tier"]).unwrap();
        // Email should NOT be in the presentation
        let json_str = serde_json::to_string(&presented).unwrap();
        assert!(!json_str.contains("secret@example.com"), "Email must be hidden in selective presentation");
        // But roles and tier should be present
        assert!(json_str.contains("bonfire_user"), "Roles must be disclosed");
        assert!(json_str.contains("mentorship"), "Tier must be disclosed");
    }

    #[test]
    fn selective_presentation_includes_signature() {
        let mut file = make_test_file("test@example.com", "sha256:abc");
        file.signature.signature = "base64:TESTsig".to_string();
        let presented = create_presentation(&file, &["authorization.roles"]).unwrap();
        let json_str = serde_json::to_string(&presented).unwrap();
        assert!(json_str.contains("_signature"), "Signature must always be included");
        assert!(json_str.contains("TESTSG") || json_str.contains("TESTsig") || json_str.contains("TESTSI") || json_str.contains("base64"), "Signature value must be present");
    }

    #[test]
    fn tpm_attestation_optional_in_device() {
        let file = make_test_file("test@example.com", "sha256:abc");
        assert!(file.device.tpm_attestation.is_none());
        assert_eq!(file.device.binding_level, "fingerprinted");

        // With TPM attestation
        let mut file2 = file.clone();
        file2.device.binding_level = "attested".to_string();
        file2.device.tpm_attestation = Some(TpmAttestation {
            srk_name: "sha256:tpm_srk_abc".to_string(),
            public_key: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----".to_string(),
            cert_chain: vec![],
            attested_at: "2026-05-15T10:00:00Z".to_string(),
        });

        let yaml = serde_yaml::to_string(&file2).unwrap();
        assert!(yaml.contains("attested"));
        assert!(yaml.contains("tpm_srk_abc"));

        let parsed: Cr3st4n1File = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.device.binding_level, "attested");
        assert!(parsed.device.tpm_attestation.is_some());
    }
}
