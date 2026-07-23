"""Verify a .cr3st4n1 credential signature in Python (no Rust required).

Usage:
    pip install pynacl
    python verify.py <credential.cr3st4n1> <pubkey_base64>

Works on credentials signed by the cr3st4n1 CLI. The signed file is
serde_yaml output, so we replace the signature line in the raw text
to reproduce the canonical form without needing a YAML round-trip.
"""
import base64
import hashlib
import re
import sys

from nacl.signing import VerifyKey


def verify(cred_path: str, pubkey_b64: str) -> bool:
    """Verify a Rust-signed .cr3st4n1 credential.

    Reproduces the Rust canonical form by replacing the signature value
    in the raw file text. No YAML round-trip needed — avoids serialization
    differences between serde_yaml and PyYAML (datetime quoting, etc.).
    """
    with open(cred_path) as f:
        raw = f.read()

    # Extract the base64 signature from the last 'signature:' line
    lines = raw.split("\n")
    sig_b64 = None
    sig_line_idx = None
    for i in range(len(lines) - 1, -1, -1):
        stripped = lines[i].strip()
        if stripped.startswith("signature:"):
            # Extract value after 'signature: '
            value = stripped[len("signature:") :].strip()
            # Remove surrounding quotes if present
            if len(value) >= 2 and value[0] in ("'", '"') and value[-1] == value[0]:
                value = value[1:-1]
            sig_b64 = value
            sig_line_idx = i
            break

    if sig_b64 is None or not sig_b64:
        raise ValueError("No signature value found in credential")

    # Zero the signature to match Rust's canonical_yaml():
    # serde_yaml serializes empty string as '' (single-quoted YAML)
    indent = lines[sig_line_idx][: len(lines[sig_line_idx]) - len(lines[sig_line_idx].lstrip())]
    lines[sig_line_idx] = indent + "signature: ''"
    zeroed = "\n".join(lines)

    digest = hashlib.sha256(zeroed.encode()).digest()
    sig = base64.b64decode(sig_b64)
    key = VerifyKey(base64.b64decode(pubkey_b64))
    key.verify(digest, sig)  # raises nacl.exceptions.BadSignatureError on failure
    return True


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python verify.py <credential.cr3st4n1> <pubkey_base64>")
        sys.exit(1)
    try:
        verify(sys.argv[1], sys.argv[2])
        print("Valid.")
    except Exception as e:
        print(f"Verification failed: {e}", file=sys.stderr)
        sys.exit(1)
