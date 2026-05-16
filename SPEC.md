# .cr3st4n1 File Specification v0.3.0

**Status**: Phase 1 shipped, Phase 2 namespace reserved (Bonfire Terminal v2.7.245+)

## What is a .cr3st4n1 file?

A portable, Ed25519-signed credential binding a verified human identity to specific hardware. It answers four questions:

| Layer | Question | Source |
|---|---|---|
| Identity | Who is this person? | HelloSign contract + Circle.so membership |
| Device | What machine are they on? | SHA-256 hardware fingerprint |
| Authorization | What can they do? | Roles, tier, feature flags |
| Signature | Is this credential authentic? | Ed25519 over content hash |

## Format

YAML. The `_signature` section is excluded from the content hash before signing.

```yaml
cr3st4n1:
  version: "0.2.0"
  created_at: "2026-05-15T10:00:00Z"
  generator:
    tool: "Bonfire Terminal"
    version: "2.7.245"

identity:
  display_name: "Maria Gonzalez"
  email: "maria@example.com"
  verification:
    level: "contract"  # contract | stripe_identity | notarized
    hellosign:
      signature_request_id: "abc123def456"
      signed_at: "2026-05-15T09:30:00Z"
      signer_email: "maria@example.com"
      contract_template: "bonfire_5k"
    circle:
      community_id: "363417"
      email: "maria@example.com"
      membership_tier: "mentorship"
      tag_id: "246372"
      tag_name: "Bonfire"
      verified_at: "2026-05-15T09:45:00Z"
      subscription_status: "active"

device:
  binding_level: "fingerprinted"  # fingerprinted | attested (Phase 2: TPM)
  hardware_fingerprint: "sha256:a3f2b8c1..."
  registered_at: "2026-05-15T10:00:00Z"
  last_seen: "2026-05-15T10:00:00Z"

authorization:
  roles:
    - "affiliate"
    - "bonfire_user"
  tier: "mentorship"
  features:
    - "ai_chat"
    - "terminal"
    - "bridge_messaging"
    - "ad_creation"
    - "compliance_validation"
  expires_at: null  # null = no expiration

# Phase 2+ stubs (nullable, namespace reserved)
network: null    # affiliate_id, brands[], referral_chain
crypto: null     # wallet_addresses[], token_gates[], commission_split
reputation: null # ars_score, score_tier, event_count, events_hash

_signature:
  signer: "Bonfire Terminal"
  algorithm: "Ed25519"
  signed_at: "2026-05-15T10:00:00Z"
  signature: "base64:..."
```

## Verification

1. Load YAML file
2. Compute SHA-256 of all fields EXCEPT `_signature.signature` (deterministic field order)
3. Verify Ed25519 signature over the hash using the published verifying key
4. Compare `device.hardware_fingerprint` against current machine's fingerprint
5. If both pass: credential is authentic and bound to this machine

## Content Hash Algorithm (v0.3.0)

The entire YAML document is hashed, not individual fields. This ensures
every field (including future additions) is automatically signed.

1. Clone the file structure
2. Set `_signature.signature` to empty string
3. Serialize to YAML (serde_yaml produces deterministic field order)
4. SHA-256 hash the YAML bytes

This replaces the v0.1.0 approach of hashing 12 cherry-picked fields,
which left `authorization.features`, `identity.display_name`, and
`generator` unsigned.

## Issuance Flow

```
User clicks "Verify" in Bonfire Terminal
  -> Daemon checks HelloSign API (signed contract?)
  -> Daemon checks Circle.so API (Bonfire tag #246372?)
  -> BOTH must pass (dual-gate)
  -> Daemon generates .cr3st4n1 file
  -> Ed25519 signs content hash
  -> Saves to ~/.bonfire/identity.cr3st4n1 (Phase 1)
  -> Future: saves to %USERPROFILE%/m3m3tic/ (Phase 2)
```

## Offline Verification

On every daemon boot, the .cr3st4n1 file is validated locally:
- No HelloSign API call
- No Circle.so API call
- Just signature check + hardware match
- Verified in <1ms

## Phases

| Phase | What | Status |
|---|---|---|
| 1 | HelloSign + Circle + hardware fingerprint + Ed25519 | **Shipped** |
| 2 | Stripe Identity ($1.50/user) for gov ID + selfie | Planned |
| 3 | Reputation ledger (Affiliate Reputation Score) | Planned |
| 4 | Network manifest (IAM-style permissions per brand) | Planned |

## Relationship to .m3m3tic

```
.m3m3tic (Brand File)          .cr3st4n1 (Person File)
"What is this brand            "Who is this person,
 allowed to say?"               on what machine,
                                authorized to do what?"
```

Together they form a complete, machine-enforceable authorization chain.

## Reference Implementation

- **Rust (daemon)**: `bonfire-terminal/daemon/src/cr3st4n1.rs`
- **Spec**: This document
- **Research**: `cr3st4n1-file-approach.md`
