"""Verify a .cr3st4n1 credential signature in Python (no Rust required).

Usage:
    pip install pynacl pyyaml
    python verify.py <credential.cr3st4n1> <pubkey_base64>

Two verification modes:
    verify_yaml() — full YAML deserialization (default, catches serialization drift)
    verify_raw()  — string replacement, no YAML round-trip (fallback if YAML differs)
"""
import base64
import hashlib
import re
import sys

import yaml
from nacl.signing import VerifyKey


def verify_yaml(cred_path: str, pubkey_b64: str) -> bool:
    """Verify with full YAML round-trip. Matches Rust's serde_yaml canonicalization."""
    with open(cred_path) as f:
        cred = yaml.safe_load(f)

    sig_b64 = cred["_signature"]["signature"]
    cred["_signature"]["signature"] = ""
    canonical = yaml.dump(cred, default_flow_style=False, sort_keys=False)
    digest = hashlib.sha256(canonical.encode()).digest()

    sig = base64.b64decode(sig_b64)
    key = VerifyKey(base64.b64decode(pubkey_b64))
    key.verify(digest, sig)  # raises nacl.exceptions.BadSignatureError on failure
    return True


def verify_raw(cred_path: str, pubkey_b64: str) -> bool:
    """Verify without YAML parsing. Replaces signature value via regex."""
    raw = open(cred_path).read()
    sig_match = re.search(r'(signature:\s*)"([^"]*)"', raw)
    if not sig_match:
        raise ValueError("No quoted signature field found in credential")
    sig_b64 = sig_match.group(2)

    # Zero the signature value in the raw text
    zeroed = raw[: sig_match.start(2)] + raw[sig_match.end(2) :]
    digest = hashlib.sha256(zeroed.encode()).digest()

    sig = base64.b64decode(sig_b64)
    key = VerifyKey(base64.b64decode(pubkey_b64))
    key.verify(digest, sig)
    return True


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python verify.py <credential.cr3st4n1> <pubkey_base64>")
        sys.exit(1)
    try:
        verify_yaml(sys.argv[1], sys.argv[2])
        print("Valid (YAML mode).")
    except Exception as e:
        print(f"YAML verification failed: {e}", file=sys.stderr)
        print("Credential signature could not be verified.", file=sys.stderr)
        sys.exit(1)
