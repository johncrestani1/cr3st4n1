# Changelog

All notable changes to the .cr3st4n1 specification will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Spec status labels: **Draft** | **Candidate** | **Standard**

---

## [1.0.0-rc.1] - 2026-07-23 [Candidate]

Renamed from v0.4.0. This is the release candidate for the first stable version.

### Breaking (from v0.3.0)

- **Pure identity only**: credential contains nothing except who the actor is and how they were verified. All roles, permissions, brand relationships, and compensation moved to `.m3m3tic` files.
- **Two-file ecosystem**: `.cr3st4n1` (identity) + `.m3m3tic` (brand + authority). No third file type.
- **Liability chain**: AI agents MUST chain to a human operator via `operator_ref`.
- Removed `authorization`, `network`, `crypto`, `reputation` sections entirely.
- `identity.verification.providers[]` replaces flat provider fields.

### Added

- `identity.type` field: `human | ai_agent | organization`
- `identity.ai_agent_metadata`: operator_ref, model, autonomy_level, deployer (required when type == ai_agent)
- `identity.licenses[]`: regulatory clearance IDs
- `trust.level` integer scale (0-5): anonymous, email, single-gate, dual-gate, gov-id, fully-attested
- `trust.credential_chain[]`: full issuance history with method
- `device.binding_level` enum: `fingerprinted | attested | cloud | none`

### Changed (from v0.4.0 Draft)

- Deleted v0.3 reference implementation (replaced by cr3st4n1-core crate)
- Rewrote all examples to validate against schema.json
- Added CI schema validation (Python jsonschema) on every commit
- Version bump to 1.0.0-rc.1

### Migration from v0.3.0

1. Remove `authorization`, `network`, `crypto`, `reputation` sections entirely
2. Add `identity.type: "human"` (or ai_agent/organization)
3. Add `trust.level` integer (compute from verification providers)
4. Restructure `identity.verification` to use `providers[]` array
5. Roles/permissions now live in the brand's `.m3m3tic` file, not the credential
