#!/usr/bin/env python3
"""Generate spec/nym-pseudonym-vectors.json with INDEPENDENT code (hashlib only).

Does not call or import the Kotlin implementation. Formula, from the nym_auth
rulebook v0.3 ("Pseudonym generation function", "Configurations"):

  pseudonym = SHA256(DST || seed || prover_input || verifier_input)
  DST       = "nym_auth/v1/<config>" (UTF-8), no separators
  null input = 32 zero bytes

Usage: python3 tools/gen_nym_pseudonym_vectors.py [--check]
"""
import hashlib
import json
import pathlib
import sys

OUT = pathlib.Path(__file__).resolve().parent.parent / "spec" / "nym-pseudonym-vectors.json"


def h(*parts: bytes) -> bytes:
    m = hashlib.sha256()
    for p in parts:
        m.update(p)
    return m.digest()


Z = bytes(32)
SEED_A = bytes(range(0x00, 0x10))
SEED_B = bytes(range(0xF0, 0x100))


def pseudonym(config, seed, user_value=None, vid=None, vctx=None):
    if config.startswith("known-offender-matching"):
        prover, verifier = Z, h(vid.encode())
    elif config == "account-recovery-ssc":
        prover, verifier = Z, h(h(vid.encode()), h(vctx.encode()))
    elif config == "user-managed-pseudonym-xsite-ssc":
        prover, verifier = h(user_value), Z
    else:
        raise ValueError(config)
    return h(("nym_auth/v1/" + config).encode(), seed, prover, verifier)


# (name, config, seed, inputs)
CASES = [
    ("known-offender ssc, x509_san_dns prefix", "known-offender-matching-ssc", SEED_A, {"verifier_id": "x509_san_dns:verifier.example.com"}),
    ("known-offender ssc, semantic_id prefix", "known-offender-matching-ssc", SEED_A, {"verifier_id": "semantic_id:LEIXG-529900T8BM49AURSDO55"}),
    ("known-offender ssc, no prefix", "known-offender-matching-ssc", SEED_A, {"verifier_id": "verifier.example.com"}),
    ("known-offender ssc, other seed", "known-offender-matching-ssc", SEED_B, {"verifier_id": "verifier.example.com"}),
    ("known-offender psc, x509_san_dns prefix", "known-offender-matching-psc", SEED_A, {"verifier_id": "x509_san_dns:verifier.example.com"}),
    ("known-offender psc, no prefix", "known-offender-matching-psc", SEED_B, {"verifier_id": "verifier.example.com"}),
    ("known-offender psc vs ssc, same seed and id differ by DST", "known-offender-matching-psc", SEED_A, {"verifier_id": "verifier.example.com"}),
    ("account-recovery, ascii context", "account-recovery-ssc", SEED_A, {"verifier_id": "x509_san_dns:verifier.example.com", "verifier_context": "account-1234"}),
    ("account-recovery, no-prefix id", "account-recovery-ssc", SEED_B, {"verifier_id": "verifier.example.com", "verifier_context": "account-1234"}),
    ("account-recovery, multi-byte UTF-8 context", "account-recovery-ssc", SEED_A, {"verifier_id": "x509_san_dns:verifier.example.com", "verifier_context": "könto-€-日本-\U0001F512"}),
    ("account-recovery, 64-byte context (boundary)", "account-recovery-ssc", SEED_A, {"verifier_id": "x509_san_dns:verifier.example.com", "verifier_context": "c" * 64}),
    ("account-recovery, 65-byte context (derivation accepts any length)", "account-recovery-ssc", SEED_A, {"verifier_id": "x509_san_dns:verifier.example.com", "verifier_context": "c" * 65}),
    ("account-recovery, 64-byte multi-byte context (16 x 4-byte chars)", "account-recovery-ssc", SEED_A, {"verifier_id": "x509_san_dns:verifier.example.com", "verifier_context": "\U0001F512" * 16}),
    ("account-recovery, empty context (derivation accepts any length)", "account-recovery-ssc", SEED_A, {"verifier_id": "x509_san_dns:verifier.example.com", "verifier_context": ""}),
    ("xsite, 16-byte user value", "user-managed-pseudonym-xsite-ssc", SEED_A, {"prover_input_hex": "000102030405060708090a0b0c0d0e0f"}),
    ("xsite, UTF-8 user value", "user-managed-pseudonym-xsite-ssc", SEED_B, {"prover_input_hex": "my shared värde".encode().hex()}),
    ("xsite, 100-byte user value", "user-managed-pseudonym-xsite-ssc", SEED_A, {"prover_input_hex": ("ab" * 100)}),
]

REJECT = [
    ("unknown config", "known-offender-matching-xyz", SEED_A, {"verifier_id": "v"}, "UNKNOWN_CONFIG"),
    ("unknown config, bare name", "pseudonym-v1-sha256", SEED_A, {"verifier_id": "v"}, "UNKNOWN_CONFIG"),
    ("known-offender ssc, missing verifier_id", "known-offender-matching-ssc", SEED_A, {}, "MISSING_INPUT"),
    ("known-offender psc, missing verifier_id", "known-offender-matching-psc", SEED_A, {}, "MISSING_INPUT"),
    ("account-recovery, missing verifier_id", "account-recovery-ssc", SEED_A, {"verifier_context": "c"}, "MISSING_INPUT"),
    ("account-recovery, missing verifier_context", "account-recovery-ssc", SEED_A, {"verifier_id": "v"}, "MISSING_INPUT"),
    ("xsite, missing prover_input", "user-managed-pseudonym-xsite-ssc", SEED_A, {}, "MISSING_INPUT"),
    ("known-offender ssc, verifier_context supplied", "known-offender-matching-ssc", SEED_A, {"verifier_id": "v", "verifier_context": "c"}, "UNUSED_INPUT"),
    ("known-offender ssc, prover_input supplied", "known-offender-matching-ssc", SEED_A, {"verifier_id": "v", "prover_input_hex": "00"}, "UNUSED_INPUT"),
    ("account-recovery, prover_input supplied", "account-recovery-ssc", SEED_A, {"verifier_id": "v", "verifier_context": "c", "prover_input_hex": "00"}, "UNUSED_INPUT"),
    ("xsite, verifier_id supplied", "user-managed-pseudonym-xsite-ssc", SEED_A, {"prover_input_hex": "00", "verifier_id": "v"}, "UNUSED_INPUT"),
    ("xsite, verifier_context supplied", "user-managed-pseudonym-xsite-ssc", SEED_A, {"prover_input_hex": "00", "verifier_context": "c"}, "UNUSED_INPUT"),
    ("seed too short (15)", "known-offender-matching-ssc", SEED_A[:15], {"verifier_id": "v"}, "WRONG_SEED_LENGTH"),
    ("seed too long (17)", "known-offender-matching-psc", SEED_A + b"\x00", {"verifier_id": "v"}, "WRONG_SEED_LENGTH"),
    ("seed empty", "account-recovery-ssc", b"", {"verifier_id": "v", "verifier_context": "c"}, "WRONG_SEED_LENGTH"),
    ("seed 32 bytes", "user-managed-pseudonym-xsite-ssc", bytes(32), {"prover_input_hex": "00"}, "WRONG_SEED_LENGTH"),
]


def build():
    vectors = []
    for name, config, seed, inp in CASES:
        uv = bytes.fromhex(inp["prover_input_hex"]) if "prover_input_hex" in inp else None
        exp = pseudonym(config, seed, uv, inp.get("verifier_id"), inp.get("verifier_context"))
        vectors.append({"name": name, "config": config, "seed_hex": seed.hex(), **inp, "expected_hex": exp.hex()})
    rejects = [
        {"name": n, "config": c, "seed_hex": s.hex(), **i, "error": e} for n, c, s, i, e in REJECT
    ]
    return {
        "status": "self-generated, not yet cross-checked with the circuit developers",
        "rulebook": "nym_auth v0.3, pseudonym-v1-sha256",
        "generator": "tools/gen_nym_pseudonym_vectors.py",
        "vectors": vectors,
        "rejections": rejects,
    }


if __name__ == "__main__":
    text = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        sys.exit(0 if OUT.read_text() == text else "vectors out of date")
    OUT.write_text(text)
