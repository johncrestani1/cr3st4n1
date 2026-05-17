# .cr3st4n1 File Specification v0.4.0

**Status**: Draft
**Date**: 2026-05-17
**Authors**: Bonfire Terminal

---

## 1. Purpose

A `.cr3st4n1` file is a portable, Ed25519-signed credential that answers one question:

> **"Who is this person and can we trust them?"**

That's all. No permissions. No brand info. No jurisdiction logic. No relationship details. Those live in the `.m3m3tic` file that references this credential.

---

## 2. Two-File Ecosystem

| File | Answers | Contains |
|---|---|---|
| `.cr3st4n1` | "Who is this actor?" | Identity, device binding, trust level |
| `.m3m3tic` | "What is this brand + who can act on it?" | Brand, relationships, jurisdictions |

The `.m3m3tic` file references `.cr3st4n1` credentials via hash (`actor_ref: "sha256:..."`). The credential itself knows nothing about any brand.

---

## 3. Schema

```yaml
cr3st4n1:
  version: "0.4.0"
  created_at: "2026-05-17T00:00:00Z"
  generator:
    tool: "Bonfire Terminal"
    version: "2.7.246"

identity:
  display_name: "Art Villalobos"
  email: "art@salvomedia.com"
  organization: "Salvo Media LLC"
  verification:
    level: "contract"                  # self_declared | email_verified | contract | identity_document | notarized
    providers:
      - type: "e_signature"
        provider: "hellosign"
        signature_request_id: "abc123"
        signed_at: "2026-05-17T09:00:00Z"
        signer_email: "art@salvomedia.com"
        contract_template: "bonfire_agency"
      - type: "membership"
        provider: "circle"
        community_id: "363417"
        tier: "mentorship"
        tag_id: "246372"
        verified_at: "2026-05-17T09:30:00Z"
        subscription_status: "active"

device:
  binding_level: "fingerprinted"       # fingerprinted | attested | none
  hardware_fingerprint: "sha256:a3f2b8c1d4e5..."
  registered_at: "2026-05-17T10:00:00Z"
  last_seen: "2026-05-17T10:00:00Z"

trust:
  level: 3                             # 0-5 scale (see below)
  credential_chain:
    - issuer: "Bonfire Terminal"
      issued_at: "2026-05-17T10:00:00Z"
      method: "hellosign+circle dual-gate"

_signature:
  signer: "Bonfire Terminal"
  algorithm: "Ed25519"
  signed_at: "2026-05-17T10:00:00Z"
  signature: "base64:..."
```

---

## 4. Fields

### 4.1 `cr3st4n1` (REQUIRED)

| Field | Type | Required | Description |
|---|---|---|---|
| `version` | string (semver) | YES | Spec version |
| `created_at` | datetime (ISO 8601) | YES | When credential was issued |
| `generator.tool` | string | no | Issuing tool name |
| `generator.version` | string | no | Issuing tool version |

### 4.2 `identity` (REQUIRED)

| Field | Type | Required | Description |
|---|---|---|---|
| `display_name` | string | YES | Human-readable name |
| `email` | string | YES | Verified email address |
| `organization` | string | no | Company/org name |
| `verification.level` | enum | YES | Verification strength |
| `verification.providers[]` | array | YES | Verification sources (min 1) |

#### Verification Levels

| Level | Name | Requirements |
|---|---|---|
| `self_declared` | Self-declared | Email only, no external verification |
| `email_verified` | Email verified | Email confirmation link clicked |
| `contract` | Contract signed | E-signature provider confirms signed document |
| `identity_document` | Gov ID verified | Stripe Identity or equivalent ($1.50/verification) |
| `notarized` | Notarized | Legal notarization of identity |

#### Verification Provider Types

| Type | Provider Examples | What It Proves |
|---|---|---|
| `e_signature` | HelloSign, DocuSign | Person signed a legal contract |
| `membership` | Circle.so, Stripe | Person holds active paid membership |
| `gov_id` | Stripe Identity, Jumio | Government-issued ID matches person |
| `notary` | Notarize.com | Legally notarized identity declaration |

### 4.3 `device` (REQUIRED)

| Field | Type | Required | Description |
|---|---|---|---|
| `binding_level` | enum | YES | `fingerprinted` / `attested` / `none` |
| `hardware_fingerprint` | string | YES (if fingerprinted) | SHA-256 composite (disk serial + CPU ID + MAC) |
| `registered_at` | datetime | YES | When device was first bound |
| `last_seen` | datetime | no | Last successful verification |

### 4.4 `trust` (REQUIRED)

| Field | Type | Required | Description |
|---|---|---|---|
| `level` | integer (0-5) | YES | Composite trust score |
| `credential_chain[]` | array | YES | Issuance history |

#### Trust Levels

| Level | Name | How Achieved |
|---|---|---|
| 0 | Anonymous | No verification |
| 1 | Email-verified | Email confirmation |
| 2 | Single-gate | One provider verified (HelloSign OR Circle) |
| 3 | Dual-gate | Two providers verified (HelloSign AND Circle) |
| 4 | Identity-verified | Gov ID + dual-gate |
| 5 | Fully-attested | Gov ID + dual-gate + TPM attestation |

### 4.5 `_signature` (REQUIRED)

| Field | Type | Required | Description |
|---|---|---|---|
| `signer` | string | YES | Who signed (tool name) |
| `algorithm` | string | YES | `Ed25519` |
| `signed_at` | datetime | YES | Signature timestamp |
| `signature` | string | YES | Base64-encoded Ed25519 signature |

---

## 5. What This File Does NOT Contain

| Concern | Where It Lives | Why Not Here |
|---|---|---|
| Roles (agency, affiliate, etc.) | `.m3m3tic` relationships[].type | Roles are brand-specific, not identity-specific |
| Permissions (what actor can do) | `.m3m3tic` relationships[].authority | Permissions are granted by brand owner |
| Compensation (how actor is paid) | `.m3m3tic` relationships[].compensation | Payment is per-engagement, not per-person |
| Brand references | `.m3m3tic` relationships[].actor_ref | Brand references the person, not vice versa |
| Platform credentials | `.m3m3tic` brand.platform_config | Platform access is brand-scoped |
| Jurisdiction rules | Policy packs (.rego files) | Regulation is external to identity |
| Disclosure requirements | Policy packs evaluate context | Disclosures depend on relationship + jurisdiction |

---

## 6. Issuance Flow

```
1. Actor installs Bonfire Terminal
2. Actor initiates verification
3. Daemon checks HelloSign API → signed contract?
4. Daemon checks Circle.so API → Bonfire tag #246372 present?
5. BOTH must pass (dual-gate → trust level 3)
6. Daemon captures hardware fingerprint (SHA-256 composite)
7. Daemon generates .cr3st4n1 YAML
8. Daemon signs with Ed25519
9. Saved to ~/.bonfire/identity.cr3st4n1
```

---

## 7. Verification Flow (Every Boot, Offline)

```
1. Daemon starts
2. Load ~/.bonfire/identity.cr3st4n1
3. Ed25519 signature check (pure math, no network)
4. SHA-256 hardware fingerprint matches current machine?
5. Both pass → credential valid
6. Under 1ms, zero network dependency
```

---

## 8. Content Hash (Signing Method)

The entire YAML document is signed, not individual fields:

1. Clone the file structure
2. Set `_signature.signature` to empty string
3. Serialize to YAML (deterministic field order via serde_yaml)
4. SHA-256 hash the YAML bytes
5. Ed25519 sign the hash

This ensures every field (including future additions) is automatically covered by the signature.

---

## 9. How .m3m3tic References .cr3st4n1

The brand owner's `.m3m3tic` file grants authority by referencing the credential hash:

```yaml
# In .m3m3tic
relationships:
  - actor_ref: "sha256:a3f2b8c1d4e5..."   # SHA-256 of the .cr3st4n1 file
    actor_name: "Salvo Media LLC"
    type: "agency"
    authority:
      brand_voice: true
      spend: true
      ...
```

At evaluation time:
1. Compute SHA-256 of actor's `.cr3st4n1` file
2. Find matching `relationships[].actor_ref` in the brand's `.m3m3tic`
3. If match found → actor is authorized with that relationship's authority
4. If no match → actor is unknown to this brand → DENY

---

## 10. Multi-Brand Actors

An actor has ONE `.cr3st4n1` file (their identity). Multiple brands can reference it:

```
Brand A (.m3m3tic) → relationships[]: actor_ref: "sha256:XYZ..."  (type: agency)
Brand B (.m3m3tic) → relationships[]: actor_ref: "sha256:XYZ..."  (type: affiliate)
Brand C (.m3m3tic) → (no reference) → actor unknown to this brand
```

The actor doesn't need multiple credentials. Each brand independently decides what authority to grant them.

---

## 11. On-Chain Protocol

The `.cr3st4n1` credential is the identity layer for the M3M3TIC affiliate settlement protocol:

```
.cr3st4n1 (who is this person?)
    |
    v
.m3m3tic (what can they do for this brand?)
    |
    +-- relationships[].type → commission rate lookup
    |       Bronze: 15% | Silver: 22% | Gold: 30% | Diamond: 40%
    |
    v
M3M3TICProtocol.sol (Base L2)
    |
    +-- EIP-712 signed referral events
    +-- 3-way split: protocol (10%) + affiliate (X%) + vendor (remainder)
    +-- USDC settlement
```

---

## 12. Migration from v0.3.0

v0.3.0 had `authorization.roles`, `network`, `crypto`, `reputation` sections. In v0.4.0:

| v0.3.0 | v0.4.0 | Reason |
|---|---|---|
| `authorization.roles` | Removed | Roles live in .m3m3tic relationships[].type |
| `authorization.features` | Removed | Features are Bonfire Terminal config, not credential |
| `network` | Removed | Brand relationships live in .m3m3tic |
| `crypto` | Removed | On-chain config is protocol-level, not credential-level |
| `reputation` | Removed | Future: separate reputation artifact |

The credential is now PURE IDENTITY. Everything else moved to `.m3m3tic`.

---

## 13. Security Considerations

- Contains PII (email, organization) — encrypt at rest
- Hardware fingerprint is a device identifier — do not expose publicly
- Ed25519 signature prevents tampering — any field change invalidates
- Credential file should have restrictive filesystem permissions (600)
- Compromise of one credential does NOT expose brand permissions (those are in .m3m3tic)
