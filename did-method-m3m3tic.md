# did:m3m3tic Method Specification

## Status
Draft — v1.0.0

## Authors
Bonfire Terminal Inc.

## Abstract
The `did:m3m3tic` method binds a Decentralized Identifier to a .cr3st4n1 credential file. DIDs are derived from the SHA-256 hash of the credential content, making them deterministic, self-certifying, and verifiable without network access.

## DID Method Name
`m3m3tic`

## DID Format
```
did:m3m3tic:<sha256-hex-of-cr3st4n1-file>
```

Example:
```
did:m3m3tic:a3f2b8c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
```

## CRUD Operations

### Create
1. Generate .cr3st4n1 credential (identity + device + trust + signature)
2. Compute SHA-256 of the signed YAML file content
3. DID = `did:m3m3tic:<hex-encoded-sha256>`
4. Optionally register on-chain (M3M3TICCredential NFT on Base L2)

### Read (Resolve)
Resolution produces a DID Document:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://m3m3tic.dev/context/v1"],
  "id": "did:m3m3tic:a3f2b8c1...",
  "verificationMethod": [{
    "id": "did:m3m3tic:a3f2b8c1...#key-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:m3m3tic:a3f2b8c1...",
    "publicKeyMultibase": "z6Mk..."
  }],
  "authentication": ["did:m3m3tic:a3f2b8c1...#key-1"],
  "assertionMethod": ["did:m3m3tic:a3f2b8c1...#key-1"],
  "service": [{
    "id": "did:m3m3tic:a3f2b8c1...#bonfire",
    "type": "BonfireTerminal",
    "serviceEndpoint": "https://bonfire.dev/resolve/"
  }]
}
```

Resolution methods (in priority order):
1. Local file lookup (~/.bonfire/identity.cr3st4n1)
2. HTTPS resolution: GET https://bonfire.dev/resolve/{did}
3. On-chain lookup: M3M3TICCredential NFT metadata on Base L2 (chain ID 8453)

### Update
1. Modify .cr3st4n1 content (e.g., device re-binding, verification renewal)
2. Re-sign with Ed25519
3. New SHA-256 = NEW DID (DIDs are content-addressed, immutable)
4. Old DID remains valid until deactivated
5. Optionally update on-chain NFT metadata

### Deactivate
1. Set credential status to revoked (off-chain: delete file or mark in Bonfire daemon state)
2. On-chain: call revokeCredential() on M3M3TICCredential contract
3. Resolution returns deactivated DID Document (no verification methods)

## Security Considerations
- Ed25519 signatures prevent credential tampering
- Hardware fingerprint binding prevents credential copying
- Content-addressed DIDs mean any modification produces a different DID
- Private keys never leave the device (stored in OS secure storage)
- Trust levels (0-5) indicate verification strength

## Privacy Considerations
- .cr3st4n1 files contain PII (email, organization) — should not be published broadly
- DID resolution should require authorization for full credential content
- Minimal disclosure: DID Document contains only public key, not identity details
- Selective disclosure via SD-JWT VC serialization (future)

## Verifiable Data Registry
- Primary: Local filesystem (offline-first)
- Secondary: Base L2 (chain ID 8453) via M3M3TICCredential.sol
- Tertiary: HTTPS resolution via bonfire.dev

## Conformance
This method conforms to DID Core v1.0 (W3C Recommendation).
