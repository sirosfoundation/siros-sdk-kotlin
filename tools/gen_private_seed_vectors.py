#!/usr/bin/env python3
"""Generate spec/private-seed-vectors.json with INDEPENDENT code (hashlib/hmac only).

  private_seed = HKDF-SHA256(root, salt = empty, info = "org.siros.private_seed/v1" || credentialType)[:16]
  psc          = SHA256(private_seed)

HKDF is implemented here from RFC 5869 with hmac; it does not call the Kotlin code.
Usage: python3 tools/gen_private_seed_vectors.py [--check]
"""
import hashlib
import hmac
import json
import pathlib
import sys

OUT = pathlib.Path(__file__).resolve().parent.parent / "spec" / "private-seed-vectors.json"
LABEL = "org.siros.private_seed/v1"


def hkdf(ikm: bytes, salt: bytes, info: bytes, n: int) -> bytes:
    prk = hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


ROOT_A = bytes(range(32))
ROOT_B = bytes(range(0xE0, 0x100))
CASES = [
    ("mDL doctype", ROOT_A, "org.iso.18013.5.1.mDL"),
    ("PID doctype", ROOT_A, "eu.europa.ec.eudi.pid.1"),
    ("vct URL", ROOT_A, "https://example.com/credentials/nym_auth"),
    ("same type, other root", ROOT_B, "org.iso.18013.5.1.mDL"),
    ("empty type", ROOT_A, ""),
    ("multi-byte UTF-8 type", ROOT_A, "typ-åäö-日本-\U0001F512"),
    ("type that looks like part of the label", ROOT_A, "/v1"),
]


def build():
    vs = []
    for name, root, ctype in CASES:
        seed = hkdf(root, b"", (LABEL + ctype).encode(), 16)
        vs.append({"name": name, "root_hex": root.hex(), "credential_type": ctype,
                   "seed_hex": seed.hex(), "psc_hex": hashlib.sha256(seed).hexdigest()})
    return {
        "status": "self-generated, not yet cross-checked with the TypeScript wallet or the privatedata-spec owner",
        "label": LABEL,
        "generator": "tools/gen_private_seed_vectors.py",
        "vectors": vs,
    }


if __name__ == "__main__":
    text = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        sys.exit(0 if OUT.read_text() == text else "vectors out of date")
    OUT.write_text(text)
