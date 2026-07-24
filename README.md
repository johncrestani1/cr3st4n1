# `cr3st4n1`

Lightweight identity credentials for content compliance. Designed for
cases where W3C VCs are too heavy and API keys are too simple.

The identity half of the `.m3m3tic` ecosystem. A `.cr3st4n1` file
answers one question: is this actor who they claim to be, and how
much should you trust that claim?

## Install

```bash
cargo install cr3st4n1
```

## Quick Start

```bash
# Generate a signing key
cr3st4n1 key generate --output key.json

# Sign a credential
cr3st4n1 credential sign --input identity.cr3st4n1 --key key.json

# Inspect a credential (identity, trust, signature status, content hash)
cr3st4n1 credential inspect --input identity.cr3st4n1

# Inspect with inline signature verification
cr3st4n1 credential inspect --input identity.cr3st4n1 --key key.json

# Verify signature only
cr3st4n1 credential verify --input identity.cr3st4n1 --key key.json

# Content hash (actor_ref for .m3m3tic files)
cr3st4n1 hash --input identity.cr3st4n1
```

## Inspect

`credential inspect` answers "what is this file?" in one command:

```
$ cr3st4n1 credential inspect --input case-studies/operator-alpha.cr3st4n1 --key bonfire-platform-key.json

Identity: Operator Alpha (human)
  email:     operator@example.com
  org:       Bonfire Terminal Inc.

Trust: Level 1 (email_verified)
  providers: 1
  device:    none
  chain:
    -> bonfire-platform (email_verification, 2026-07-23)

Signature:
  signer:    bonfire-platform (Ed25519)
  signed at: 2026-07-23T18:00:00Z
  hash:      ade88d3b3eb7ea249abbab883c3f763a6c354fbf22c11fb36adba4b0e5f9be4b
  status:    valid
```

Use `--json` for machine-readable output (credential verbatim + `_inspect` metadata block).
Use `--key` to verify the signature inline. Without `--key`, signature status shows `present` or `absent`.

Exit codes: 0 = success, 1 = parse/schema error, 2 = signature verification failed.

## Format

YAML files with Ed25519 signatures. Trust levels 0-5. Offline-verifiable.
JSON Schema (Draft 2020-12) for validation.

```yaml
cr3st4n1:
  version: "1.0.0"
  created_at: "2026-07-23T00:00:00Z"

identity:
  type: "human"
  display_name: "Alice"
  email: "alice@example.com"
  verification:
    level: "email_verified"
    providers:
      - type: "platform_registration"
        provider: "bonfire"

device:
  binding_level: "none"
  registered_at: "2026-07-23T00:00:00Z"

trust:
  level: 1
  credential_chain:
    - issuer: "bonfire-platform"
      issued_at: "2026-07-23T00:00:00Z"
      method: "email_verification"

_signature:
  signer: "bonfire-platform"
  algorithm: "Ed25519"
  signed_at: "2026-07-23T00:00:00Z"
  signature: ""
```

## Examples

- `examples/minimal.cr3st4n1` — Trust level 1, email verified human
- `examples/full.cr3st4n1` — Trust level 4, AI agent with TPM attestation
- `case-studies/operator-alpha.cr3st4n1` — Real signed credential (see [case study](case-studies/bonfire-terminal-issuance.md))

## Trust Levels

| Level | Name | Verification |
|-------|------|-------------|
| 0 | Anonymous | None |
| 1 | Email | Email verified |
| 2 | Single-gate | One provider (e.g., contract signed) |
| 3 | Dual-gate | Two providers (e.g., HelloSign + Circle.so) |
| 4 | Gov ID | Government-issued identity document |
| 5 | Fully attested | Gov ID + TPM hardware attestation |

## Why not X?

| Alternative | Why cr3st4n1 exists |
|-------------|---------------------|
| W3C VCs (DIDKit, Aries) | Full VC stack is ~30 crates. cr3st4n1 is 1 crate, 4 source files. |
| API keys | No identity information, no trust levels, no offline verification. |
| JWTs | No schema validation, no selective disclosure path, no content-addressed DID. |
| OAuth tokens | Require online verification. cr3st4n1 verifies offline. |

## CLI Reference

| Command | Description |
|---------|-------------|
| `key generate --output KEY` | Generate Ed25519 signing keypair |
| `key public --key KEY` | Extract public key from keypair |
| `credential validate --input FILE` | Validate against embedded JSON Schema |
| `credential sign --input FILE --key KEY` | Sign credential (validates schema first) |
| `credential verify --input FILE --key KEY` | Verify Ed25519 signature |
| `credential inspect --input FILE [--key KEY] [--json]` | Inspect credential: identity, trust, signature, hash |
| `hash --input FILE` | Print SHA-256 content hash (for `actor_ref`) |

## Performance

All operations complete in under 100 microseconds on commodity hardware.
Run `cargo bench` for numbers on your machine.

## Verify in Python

Credentials can be verified in Python with one dependency (`pynacl`):

```bash
pip install pynacl
python examples/verify.py signed.cr3st4n1 <pubkey_base64>
```

Cross-language verification is tested in CI. The Python verifier uses
line-level string replacement to reproduce Rust's canonical form, avoiding
serialization differences between serde_yaml and PyYAML.

## Case Study

See [case-studies/bonfire-terminal-issuance.md](case-studies/bonfire-terminal-issuance.md) for a
real credential issued by Bonfire Terminal v2.7.309, signed and verified in both Rust and Python.

## Specification

See [SPEC.md](SPEC.md) for the full v1.0.0-rc.1 format specification.

## How .m3m3tic References .cr3st4n1

```yaml
# In a brand's .m3m3tic file
relationships:
  - actor_ref: "sha256:ade88d3b..."   # SHA-256 content hash of the .cr3st4n1 file
    actor_name: "Operator Alpha"
    type: "agency"
    authority:
      brand_voice: true
      spend: true
```

One actor, one credential. Multiple brands can reference it independently.

## Related

- [m3m3tic](https://github.com/johncrestani1/m3m3tic) — Brand identity + compliance policies
- [did:m3m3tic](did-method-m3m3tic.md) — DID method specification
- [bonfire-terminal](https://github.com/johncrestani1/bonfire-terminal) — Desktop app + Rust daemon (issues credentials)

## License

Apache 2.0
