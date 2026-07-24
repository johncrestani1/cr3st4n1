# Case Study: Bonfire Terminal Credential Issuance

## Context

Bonfire Terminal is a desktop AI orchestration tool (v2.7.309). When users
complete onboarding, the platform issues a `.cr3st4n1` credential binding
their identity to the Bonfire ecosystem.

This case study documents the first real credential issued by Bonfire Terminal,
verified in both Rust and Python.

## Credential Issued

```yaml
cr3st4n1:
  version: 1.0.0
  created_at: 2026-07-23T18:00:00Z
  generator:
    tool: bonfire-terminal
    version: 2.7.309
identity:
  type: human
  display_name: Operator Alpha
  email: operator@example.com
  organization: Bonfire Terminal Inc.
  verification:
    level: email_verified
    providers:
    - type: platform_registration
      provider: bonfire
      registered_at: 2026-07-23T18:00:00Z
device:
  binding_level: none
  registered_at: 2026-07-23T18:00:00Z
trust:
  level: 1
  credential_chain:
  - issuer: bonfire-platform
    issued_at: 2026-07-23T18:00:00Z
    method: email_verification
_signature:
  signer: bonfire-platform
  algorithm: Ed25519
  signed_at: 2026-07-23T18:00:00Z
  signature: OT1BMlc4/cTNTnfuB5BnSPzQqfueQ2LnfP93/onex8HzyZPfStFtjXIwe6pi3WIvGoWTyejs5FGwrC53pP36Cg==
```

## Schema Validation

```
$ cr3st4n1 credential validate --input case-studies/operator-alpha.cr3st4n1
Valid.
```

## Signature Verification (Rust)

```
$ cr3st4n1 credential verify --input case-studies/operator-alpha.cr3st4n1 --key case-studies/bonfire-platform-key.json
Signature valid.
```

## Content Hash

```
$ cr3st4n1 hash --input case-studies/operator-alpha.cr3st4n1
ade88d3bdc325bc55e1931b7770b75b476eb820869be836abe62d6d950393c87
```

This hash is the `actor_ref` value used in `.m3m3tic` files:

```yaml
# In a brand's .m3m3tic file
relationships:
  - actor_ref: "sha256:ade88d3bdc325bc55e1931b7770b75b476eb820869be836abe62d6d950393c87"
    actor_name: "Operator Alpha"
    type: "agency"
    authority:
      brand_voice: true
      spend: true
```

## Cross-Language Verification (Python)

```
$ python examples/verify.py case-studies/operator-alpha.cr3st4n1 "4kmbA1Ut38TeUWrxTC8vnbG+2zrqgsybx3u1LD1d4n4="
Valid.
```

The Python verifier uses only `pynacl` (no YAML library). It reproduces the
Rust canonical form via line-level string replacement, avoiding serialization
differences between serde_yaml and PyYAML.

## What This Proves

1. A real application (Bonfire Terminal v2.7.309) issued a real credential
2. The credential passes schema validation (JSON Schema Draft 2020-12)
3. The Ed25519 signature verifies in both Rust and Python
4. The content hash is deterministic and usable as `actor_ref` in `.m3m3tic`
5. The credential was issued at trust level 1 (email_verified) — the natural
   starting point for a platform registration flow

## Trust Level Progression

This credential starts at trust level 1. As the user completes additional
verification gates, Bonfire Terminal re-issues the credential with higher
trust levels:

| Gate | Trust Level | Method |
|------|-------------|--------|
| Platform registration | 1 | Email verified |
| Circle.so membership (customer tier) | 2 | Membership verification |
| Contract signed (HelloSign) | 3 | E-signature + membership |
| Government ID (Stripe Identity / Clear) | 4 | Gov ID scan |

Each re-issuance produces a new content hash. Any `.m3m3tic` files referencing
the previous `actor_ref` must be updated to reflect the new credential.

## Key Management

The signing key (`bonfire-platform-key.json`) contains the Ed25519 keypair.
The public key can be extracted for distribution:

```
$ cr3st4n1 key public --key case-studies/bonfire-platform-key.json
{
  "public": "4kmbA1Ut38TeUWrxTC8vnbG+2zrqgsybx3u1LD1d4n4="
}
```

Verifiers need only the public key. The private key stays on the issuing
machine and must never be shared.
