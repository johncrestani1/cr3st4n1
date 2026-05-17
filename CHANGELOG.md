# Changelog

All notable changes to the .cr3st4n1 specification will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Spec status labels: **Draft** | **Candidate** | **Standard**

---

## [0.4.0] - 2026-05-17 [Draft]

### Architecture (BREAKING)
- **Pure identity only**: Credential contains NOTHING except who the actor is and how they were verified. All roles, permissions, brand relationships, and compensation moved to `.m3m3tic` files.
- **Two-file ecosystem**: `.cr3st4n1` (identity) + `.m3m3tic` (brand + authority). No third file type.
- **Liability chain**: AI agents MUST chain to a human operator via `operator_ref`.

### Added
- `identity.type` field: `human | ai_agent | organization`
- `identity.ai_agent_metadata`: operator_ref, model, autonomy_level, deployer (required when type == ai_agent)
- `identity.licenses[]`: regulatory clearance IDs (UAE Advertiser Permit, Saudi Mawthooq, Nigeria ARCON)
- `trust.level` integer scale (0-5): anonymous → email → single-gate → dual-gate → gov-id → fully-attested
- `trust.credential_chain[]`: full issuance history with method

### Changed
- `identity.verification.providers[]` replaces flat provider fields (now an array supporting multiple verification sources)
- `device.binding_level` enum: `fingerprinted | attested | none` (was just fingerprinted)

### Removed (BREAKING)
- `authorization.roles` — moved to `.m3m3tic` relationships[].type
- `authorization.features` — moved to Bonfire Terminal config
- `network` section — moved to `.m3m3tic` relationships[]
- `crypto` section — moved to `.m3m3tic` protocol section
- `reputation` section — deferred to separate artifact (future)

### Migration from v0.3.0
1. Remove `authorization`, `network`, `crypto`, `reputation` sections entirely
2. Add `identity.type: "human"` (or ai_agent/organization)
3. Add `trust.level` integer (compute from verification providers)
4. Restructure `identity.verification` to use `providers[]` array
5. Roles/permissions now live in the BRAND's `.m3m3tic` file, not the credential

---

## [0.3.0] - 2026-05-15 [Superseded]

### Added
- Content hash v0.3.0: entire YAML document hashed (replaces 12-field cherry-pick from v0.1.0)
- W3C Verifiable Credential alignment (optional @context and type fields)
- Phase 2-5 stubs (network, crypto, reputation) as nullable placeholders

### Changed
- Signing method: hash entire document instead of individual fields

---

## [0.2.0] - 2026-05-01 [Superseded]

### Added
- Hardware fingerprint composite (disk serial + CPU ID + MAC address)
- Circle.so membership verification as second gate
- Ed25519 signature over content hash

---

## [0.1.0] - 2026-04-15 [Superseded]

### Added
- Initial specification: identity + device + authorization
- HelloSign contract verification
- 12-field content hash for signing
- Basic role array (affiliate, bonfire_user)
