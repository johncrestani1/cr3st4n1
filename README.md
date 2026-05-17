# .cr3st4n1

Portable, Ed25519-signed credential binding a verified human identity to specific hardware. Machine-readable. Offline-verifiable. On-chain enforceable.

---

## What Problem Does This Solve

Affiliate marketing has a fraud problem. Platforms cannot distinguish real humans from bot farms, cannot tie a person to one machine, and cannot prove authorization without phoning home to a central server. When a dispute happens, there is no cryptographic trail -- just database logs that either party can contest.

A `.cr3st4n1` file fixes this by combining three things that have never been combined into a single signed artifact:

1. **Verified identity** -- not a username, but a real human who signed a legal contract (HelloSign) and holds an active membership (Circle.so). Dual-gate: both must pass.
2. **Hardware binding** -- the credential is locked to a specific machine via SHA-256 composite fingerprint (disk serial + CPU ID + MAC address). Copy the file to another machine and it fails verification.
3. **Cryptographic signature** -- Ed25519 over the entire document. Tamper with any field and the signature breaks. No API call needed to verify -- pure math, under 1ms.

The result: a portable file that proves "this verified person, on this specific machine, is authorized to perform these actions" -- without any network dependency at runtime.

---

## How It Works

```yaml
cr3st4n1:
  version: "0.3.0"
  generator: { tool: "Bonfire Terminal", version: "2.7.246" }

identity:
  email: "maria@example.com"
  verification:
    level: "contract"
    hellosign: { signature_request_id: "abc123", contract_template: "bonfire_5k" }
    circle:   { community_id: "363417", membership_tier: "mentorship", tag_id: "246372" }

device:
  binding_level: "fingerprinted"
  hardware_fingerprint: "sha256:a3f2b8c1d4e5..."

authorization:
  roles: ["affiliate", "bonfire_user"]
  tier: "mentorship"
  features: ["ai_chat", "terminal", "bridge_messaging", "ad_creation"]

_signature:
  algorithm: "Ed25519"
  signature: "base64:..."
```

### Issuance (one-time, online)

```
User clicks "Verify" in Bonfire Terminal
  -> Daemon checks HelloSign API (signed contract?)
  -> Daemon checks Circle.so API (Bonfire tag #246372 present?)
  -> BOTH must pass (dual-gate)
  -> Daemon generates .cr3st4n1, signs with Ed25519
  -> Saves to ~/.bonfire/identity.cr3st4n1
```

### Verification (every boot, offline)

```
Daemon starts
  -> Load ~/.bonfire/identity.cr3st4n1
  -> Ed25519 signature check (no network call)
  -> SHA-256 hardware fingerprint matches current machine?
  -> Both pass: credential valid, features unlocked
  -> Under 1ms, zero network dependency
```

---

## On-Chain Protocol

The `.cr3st4n1` credential is the identity layer for the M3M3TIC affiliate settlement protocol. The credential authorizes an affiliate; the protocol settles their commissions on-chain.

```
.cr3st4n1 credential (offline, Ed25519-signed)
    |
    +-- identity.verification.circle -> affiliate enrollment
    +-- authorization.tier -> commission rate lookup
    |       Bronze: 15% | Silver: 22% | Gold: 30% | Diamond: 40%
    |
    v
cr3st4n1-protocol Rust crate
    |
    +-- bindings.rs: alloy sol!{} macro (compile-time Solidity ABI binding)
    +-- eip712.rs: EIP-712 type definitions, domain separator constants
    +-- constants.rs: protocol fee (1000 BPS), tier thresholds, max rates
    |
    v
daemon/src/signing.rs: EIP-712 signer (k256 secp256k1 + alloy SolStruct)
    |
    +-- Constructs M3M3TICReferral struct from referral event data
    +-- Computes struct hash via alloy eip712_hash_struct()
    +-- Signs digest: keccak256(0x1901 || domainSeparator || structHash)
    +-- Produces 65-byte recoverable signature (r || s || v)
    |
    v (relayer submits tx)
M3M3TICProtocol.sol (Base L2, Solidity 0.8.24)
    |
    +-- processVerifiedSale(): reconstructs EIP-712 digest, ecrecover signer
    +-- Nonce replay protection (sequential per-affiliate)
    +-- Timestamp expiry (MAX_SIGNATURE_AGE = 86,400 seconds)
    +-- 3-way split: protocol (10%) + affiliate (X%) + vendor (remainder)
    +-- Pull-pattern withdrawals (CEI, SafeERC20)
```

### Solidity Contracts

| Contract | Purpose | Chain |
|----------|---------|-------|
| `M3M3TICProtocol` | Core payment split + EIP-712 verified sale | Base L2 (USDC) |
| `M3M3TICCredential` | Soulbound affiliate NFT with auto-tier promotion (ERC-5192) | Base L2 |
| `M3M3TICAudit` | Merkle-root payout audit trail for on-chain verification | Base L2 |

### Cross-Language Proof

The Rust daemon and Solidity contracts are proven to produce identical EIP-712 encoding:

- **Rust test** (`daemon/tests/cross_language_eip712_test.rs`) signs with alloy + k256, locks struct hash
- **Foundry test** (`contracts/test/CrossLanguageParity.t.sol`) reconstructs same struct hash, runs `ecrecover` on the Rust-generated signature, and executes full `processVerifiedSale()` flow

Both sides assert the same hardcoded struct hash: `0x3a4de08824133d4d15038a05b635c4e4d754c7e400d038ae55a2f1689ec40132`

---

## Specification

See [SPEC.md](SPEC.md) for the full v0.3.0 specification.

| Layer | Question | Source |
|---|---|---|
| Identity | Who is this person? | HelloSign contract + Circle.so membership |
| Device | What machine are they on? | SHA-256 composite hardware fingerprint |
| Authorization | What can they do? | Roles, tier, feature flags |
| Signature | Is this credential authentic? | Ed25519 over content hash |

### Content Hash (v0.3.0)

The entire YAML document is hashed -- not individual fields. This ensures every field (including future additions) is automatically signed. The `_signature.signature` field is set to empty string before hashing.

### W3C Verifiable Credential Alignment (v0.3.0)

When the `@context` and `type` fields are present, a `.cr3st4n1` file is a valid W3C Verifiable Credential with selective disclosure support. The Ed25519 signature satisfies the VC Data Model proof requirement.

---

## Phases

| Phase | What | Status |
|---|---|---|
| 1 | HelloSign + Circle.so + hardware fingerprint + Ed25519 | **Shipped** (v2.7.245) |
| 2 | Stripe Identity ($1.50/user) -- gov ID + selfie verification | Planned |
| 3 | Reputation ledger -- Affiliate Reputation Score (ARS) | Planned |
| 4 | Network manifest -- IAM-style permissions per brand | Planned |
| 5 | TPM attestation -- hardware-rooted device binding | Planned |

---

## Schema

[schema.json](schema.json) -- JSON Schema (Draft 2020-12) for `.cr3st4n1` file validation.

```bash
ajv validate -s schema.json -d your-credential.cr3st4n1
```

---

## Implementations

| Implementation | Language | Location |
|---|---|---|
| Bonfire daemon (production) | Rust | [bonfire-terminal](https://github.com/johncrestani1/bonfire-terminal)/daemon/src/cr3st4n1.rs |
| cr3st4n1-protocol crate | Rust | [bonfire-terminal](https://github.com/johncrestani1/bonfire-terminal)/crates/cr3st4n1-protocol |
| EIP-712 alloy binding | Rust | `crates/cr3st4n1-protocol/src/bindings.rs` |
| On-chain verifier | Solidity 0.8.24 | [bonfire-contracts](https://github.com/johncrestani1/bonfire-contracts)/solidity |
| Reference implementation | Rust | [reference-impl.rs](reference-impl.rs) |

---

## Relationship to .m3m3tic

```
.m3m3tic (Brand File)              .cr3st4n1 (Person File)
---------------------              ------------------------
"What is this brand                "Who is this person,
 allowed to say?                    on what machine,
 What are its visual rules?         authorized to do what?"
 What legal constraints apply?"
```

Together they form a complete, machine-enforceable authorization chain: this verified person, on this verified device, is authorized to create this type of content, for this brand, on this platform, subject to these legal constraints.

---

## Licensing

| Component | License |
|-----------|---------|
| Specification and Schema (this repository) | Apache 2.0 |
| cr3st4n1-protocol Rust crate | MIT |
| Solidity contracts (M3M3TIC*) | MIT |
| Bonfire Terminal (daemon, UI) | BSL 1.1 |

The specification is open. Anyone can read, validate, and generate `.cr3st4n1` files. The Bonfire Terminal is the reference issuer, but the format is not locked to any single implementation.

---

## Related Repositories

| Repo | Purpose |
|------|---------|
| [bonfire-terminal](https://github.com/johncrestani1/bonfire-terminal) | Desktop app + Rust daemon -- issues and verifies .cr3st4n1 credentials |
| [bonfire-contracts](https://github.com/johncrestani1/bonfire-contracts) | CDD schemas + Solidity contracts (on-chain settlement) |
| [bonfire-dashboard](https://github.com/johncrestani1/bonfire-dashboard) | CI orchestrator + observability (Grafana/Prometheus) |
| [m3m3tic](https://github.com/johncrestani1/m3m3tic) | Brand identity + legal compliance standard (.m3m3tic files) |
