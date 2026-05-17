# .cr3st4n1

**Portable, Ed25519-signed credential binding a verified human identity to specific hardware.**

> A `.cr3st4n1` file answers one question: "Who is this person and can we trust them?"

---

## Two-File Ecosystem

| File | Purpose |
|---|---|
| `.cr3st4n1` | **Identity** — who the actor is, verified and hardware-bound |
| `.m3m3tic` | **Brand** — what the brand is + who can act on its behalf |

The `.m3m3tic` file references `.cr3st4n1` credentials. The credential itself knows nothing about any brand, role, or permission.

---

## What Problem Does This Solve?

Affiliate marketing has a fraud problem. Platforms cannot distinguish real humans from bot farms, cannot tie a person to one machine, and cannot prove authorization without phoning home to a central server.

A `.cr3st4n1` file combines three things into a single signed artifact:

1. **Verified identity** — real human who signed a legal contract (HelloSign) and holds an active membership (Circle.so). Dual-gate: both must pass.
2. **Hardware binding** — credential locked to a specific machine via SHA-256 composite fingerprint. Copy the file to another machine and it fails.
3. **Cryptographic signature** — Ed25519 over the entire document. Tamper with any field and verification fails. No API call needed — pure math, under 1ms.

---

## How It Works

```yaml
cr3st4n1:
  version: "0.4.0"

identity:
  display_name: "Maria Gonzalez"
  email: "maria@example.com"
  organization: "Salvo Media LLC"
  verification:
    level: "contract"
    providers:
      - type: "e_signature"
        provider: "hellosign"
        signature_request_id: "abc123"
      - type: "membership"
        provider: "circle"
        community_id: "363417"
        tier: "mentorship"
        tag_id: "246372"

device:
  binding_level: "fingerprinted"
  hardware_fingerprint: "sha256:a3f2b8c1..."

trust:
  level: 3    # dual-gate verified

_signature:
  algorithm: "Ed25519"
  signature: "base64:..."
```

### Issuance (one-time, online)

```
User clicks "Verify" in Bonfire Terminal
  -> Daemon checks HelloSign API (signed contract?)
  -> Daemon checks Circle.so API (Bonfire tag #246372?)
  -> BOTH must pass (dual-gate)
  -> Daemon captures hardware fingerprint
  -> Generates .cr3st4n1, signs with Ed25519
  -> Saves to ~/.bonfire/identity.cr3st4n1
```

### Verification (every boot, offline)

```
Daemon starts
  -> Load ~/.bonfire/identity.cr3st4n1
  -> Ed25519 signature check (no network)
  -> Hardware fingerprint matches current machine?
  -> Both pass: credential valid
  -> Under 1ms, zero network dependency
```

---

## Trust Levels

| Level | Name | Requirements |
|---|---|---|
| 0 | Anonymous | No verification |
| 1 | Email-verified | Email confirmation |
| 2 | Single-gate | One provider verified |
| 3 | Dual-gate | Two providers verified (shipped) |
| 4 | Identity-verified | Gov ID + dual-gate |
| 5 | Fully-attested | Gov ID + dual-gate + TPM |

---

## What This File Does NOT Contain

| Concern | Where It Lives |
|---|---|
| Roles (agency, affiliate, etc.) | `.m3m3tic` relationships[].type |
| Permissions (what actor can do) | `.m3m3tic` relationships[].authority |
| Compensation model | `.m3m3tic` relationships[].compensation |
| Brand info | `.m3m3tic` brand section |
| Jurisdiction rules | External policy packs (.rego) |

The credential is pure identity. Everything else is the brand owner's decision.

---

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
      spend_ceiling_monthly: 500000
```

One actor, one credential. Multiple brands can reference it independently.

---

## On-Chain Protocol

The `.cr3st4n1` credential is the identity layer for the M3M3TIC settlement protocol:

| Contract | Purpose | Chain |
|----------|---------|-------|
| `M3M3TICProtocol` | 3-way affiliate split + EIP-712 verified sale (USDC) | Base L2 |
| `M3M3TICCredential` | Soulbound affiliate NFT (ERC-5192) with auto-tier | Base L2 |
| `M3M3TICAudit` | Merkle-root payout audit trail | Base L2 |

---

## Specification

See [SPEC.md](SPEC.md) for the full v0.4.0 specification.

---

## Licensing

| Component | License |
|-----------|---------|
| Specification and Schema (this repo) | Apache 2.0 |
| Bonfire Terminal (daemon, UI) | BSL 1.1 |
| cr3st4n1-protocol Rust crate | MIT |
| Solidity contracts | MIT |

---

## Related Repositories

| Repo | Purpose |
|------|---------|
| [m3m3tic](https://github.com/johncrestani1/m3m3tic) | Brand identity + legal compliance standard |
| [bonfire-terminal](https://github.com/johncrestani1/bonfire-terminal) | Desktop app + Rust daemon (issues credentials) |
| [bonfire-contracts](https://github.com/johncrestani1/bonfire-contracts) | Solidity contracts (on-chain settlement) |
