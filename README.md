# `cr3st4n1`

Lightweight identity credentials for content compliance. Designed for
cases where W3C VCs are too heavy and API keys are too simple.

The identity half of the `.m3m3tic` ecosystem. A `.cr3st4n1` file
answers one question: is this actor who they claim to be, and how
much should you trust that claim?

## Format

YAML files with Ed25519 signatures. Trust levels 0-5. Offline-verifiable.
JSON Schema (Draft 2020-12) for validation.

```yaml
cr3st4n1:
  version: "1.0.0"

identity:
  display_name: "Alice"
  type: "human"
  verification:
    level: "email_verified"
    providers:
      - type: "platform_registration"
        provider: "bonfire"
        verified_at: "2026-07-23T00:00:00Z"

device:
  binding_level: "none"

trust:
  level: 1
  credential_chain:
    - type: "email_verified"
      provider: "bonfire"
      verified_at: "2026-07-23T00:00:00Z"

_signature:
  signer: "did:m3m3tic:bonfire-issuer"
  algorithm: "Ed25519"
  signed_at: "2026-07-23T00:00:00Z"
  signature: ""
```

## Examples

See `examples/minimal.cr3st4n1` (trust level 1) and `examples/full.cr3st4n1` (trust level 4, AI agent, TPM attestation).

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

## Specification

See [SPEC.md](SPEC.md) for the full v1.0.0-rc.1 format specification.

## How .m3m3tic References .cr3st4n1

```yaml
# In a brand's .m3m3tic file
relationships:
  - actor_ref: "sha256:a3f2b8c1..."   # SHA-256 of the .cr3st4n1 file
    actor_name: "Salvo Media LLC"
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
