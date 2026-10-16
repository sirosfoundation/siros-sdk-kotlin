#!/usr/bin/env python3
"""Generate spec/circuit-zk-presentation-vectors.json with INDEPENDENT code.

Uses a small hand-written CBOR encoder (stdlib only); it neither calls nor
imports the Kotlin implementation and uses no CBOR library. The structure is
the rulebook's "Presentation encoding" CDDL (nym_auth rulebook v0.3).

Usage: python3 tools/gen_circuit_zk_presentation_vectors.py [--check]
"""
import base64
import json
import pathlib
import sys

OUT = pathlib.Path(__file__).resolve().parent.parent / "spec" / "circuit-zk-presentation-vectors.json"

# --- minimal CBOR encoder (RFC 8949, definite lengths, shortest heads) ---


def head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | ai]) + n.to_bytes(size, "big")
    raise ValueError(n)


def uint(n): return head(0, n)
def bstr(b): return head(2, len(b)) + b
def tstr(s): b = s.encode(); return head(3, len(b)) + b
def arr(items): return head(4, len(items)) + b"".join(items)
def cmap(pairs): return head(5, len(pairs)) + b"".join(k + v for k, v in pairs)
def tag(n, item): return head(6, n) + item


TRUE, FALSE, NULL = b"\xf5", b"\xf4", b"\xf6"


def pseud(i): return bytes((i + k) & 0xFF for k in range(32))


CERT_A = bytes.fromhex("3082010a") + bytes(range(16))
CERT_B = bytes.fromhex("30820122") + bytes(range(16, 40))
PROOF = bytes(range(0x40, 0x60))
RB_ID = "urn:circuits:longfellow:nym_auth:v1"  # the rulebook example's (WIP) circuit id
TIME = "2026-05-01T12:00:00Z"


def results_enc(results):
    """results: {handle: ('p', bytes) | ('t',)}; keys sorted by UTF-8 bytes."""
    pairs = []
    for h in sorted(results, key=lambda s: s.encode()):
        v = results[h]
        pairs.append((tstr(h), bstr(v[1]) if v[0] == "p" else TRUE))
    return cmap(pairs)


def pres_enc(p):
    pairs = [(tstr("circuit_id"), tstr(p["circuit_id"])), (tstr("proof"), bstr(p["proof"]))]
    ks = p["issuer_key_set"]
    pairs.append((tstr("issuer_key_set"), arr([bstr(c) for c in ks[1]]) if ks[0] == "der" else ks[1]))
    if p.get("proof_time"):
        pairs.append((tstr("proof_time"), tag(0, tstr(p["proof_time"]))))
    pairs.append((tstr("results"), results_enc(p["results"])))
    for k, v in p.get("unknown", {}).items():
        pairs.append((tstr(k), v))
    return cmap(pairs)


def pres_json(p):
    ks = p["issuer_key_set"]
    out = {
        "circuit_id": p["circuit_id"],
        "proof_hex": p["proof"].hex(),
        "issuer_key_set": {"der_certificates_hex": [c.hex() for c in ks[1]]} if ks[0] == "der" else {"other_cbor_hex": ks[1].hex()},
    }
    if p.get("proof_time"):
        out["proof_time"] = p["proof_time"]
    out["results"] = {h: ({"pseudonym_hex": v[1].hex()} if v[0] == "p" else {"predicate": True}) for h, v in p["results"].items()}
    if p.get("unknown"):
        out["unknown_entries_cbor_hex"] = {k: v.hex() for k, v in p["unknown"].items()}
    return out


def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def base(**over):
    p = {
        "circuit_id": RB_ID, "proof": PROOF, "issuer_key_set": ("der", [CERT_A]),
        "results": {"nym-123": ("p", pseud(0x5F)), "age-range-123": ("t",)},
    }
    p.update(over)
    return p


VECTORS = [
    ("golden: rulebook example shape (pseudonym + predicate, no proof_time); circuit_id is the WIP rulebook string", base()),
    ("golden: same with proof_time", base(proof_time=TIME)),
    ("predicate only", base(results={"age": ("t",)})),
    ("pseudonym only, two certificates", base(issuer_key_set=("der", [CERT_A, CERT_B]), results={"nym": ("p", pseud(1))})),
    ("results keys are sorted by UTF-8 bytes on encode", base(results={"b": ("t",), "a": ("t",), "B": ("t",), "å": ("t",)})),
    ("empty proof and empty circuit_id are allowed by the CDDL", base(proof=b"", circuit_id="")),
    ("multi-byte circuit_id and handle", base(circuit_id="urn:test:日本", results={"über": ("t",)})),
    ("proof_time with fractional seconds", base(proof_time="2026-05-01T12:00:00.500Z")),
    ("unknown top-level key preserved", base(unknown={"x_future": tstr("later")})),
    ("unknown top-level key with structured value preserved", base(unknown={"x_ext": cmap([(tstr("a"), uint(1))])})),
]


def vector_entry(name, p):
    raw = pres_enc(p)
    return {"name": name, "presentation": pres_json(p), "cbor_hex": raw.hex(), "base64url": b64u(raw)}


# hook vectors: issuer_key_set is a CBOR map; the test hook accepts circuit_id "urn:test:custom-keys"
HOOK_ID = "urn:test:custom-keys"
CUSTOM = cmap([(tstr("kind"), tstr("x")), (tstr("data"), bstr(b"\x0a\x0b"))])
HOOK_P = base(circuit_id=HOOK_ID, issuer_key_set=("other", CUSTOM))


def good_map(**kw):
    """Valid top-level pairs, as a dict name -> encoded value, overridable/removable (None)."""
    d = {
        "circuit_id": tstr(RB_ID), "proof": bstr(PROOF), "issuer_key_set": arr([bstr(CERT_A)]),
        "results": cmap([(tstr("n"), bstr(pseud(7)))]),
    }
    d.update(kw)
    return cmap([(tstr(k), v) for k, v in d.items() if v is not None])


def rej(name, error, cbor=None, b64=None, strict=False, hook=False):
    e = {"name": name}
    if cbor is not None:
        e["cbor_hex"] = cbor.hex()
    if b64 is not None:
        e["base64url"] = b64
    e["strict"] = strict
    e["issuer_key_set_hook"] = hook
    e["error"] = error
    return e


def res(*pairs): return cmap(list(pairs))


GOOD = good_map()
dup = head(5, 5) + b"".join(k + v for k, v in [(tstr("circuit_id"), tstr("a")), (tstr("circuit_id"), tstr("b")), (tstr("proof"), bstr(b"")), (tstr("issuer_key_set"), arr([bstr(CERT_A)])), (tstr("results"), res((tstr("n"), TRUE)))])
REJECTIONS = [
    rej("top level is an array", "NOT_A_MAP", cbor=arr([])),
    rej("top level is a tagged map", "NOT_A_MAP", cbor=tag(55799, GOOD)),
    rej("missing circuit_id", "MISSING_KEY", cbor=good_map(circuit_id=None)),
    rej("missing proof", "MISSING_KEY", cbor=good_map(proof=None)),
    rej("missing issuer_key_set", "MISSING_KEY", cbor=good_map(issuer_key_set=None)),
    rej("missing results", "MISSING_KEY", cbor=good_map(results=None)),
    rej("circuit_id is a byte string", "WRONG_TYPE", cbor=good_map(circuit_id=bstr(b"x"))),
    rej("proof is a text string", "WRONG_TYPE", cbor=good_map(proof=tstr("x"))),
    rej("results is an array", "NOT_A_MAP", cbor=good_map(results=arr([]))),
    rej("issuer_key_set is empty", "EMPTY_ISSUER_KEY_SET", cbor=good_map(issuer_key_set=arr([]))),
    rej("issuer_key_set element is a text string", "BAD_ISSUER_KEY_ELEMENT", cbor=good_map(issuer_key_set=arr([bstr(CERT_A), tstr("x")]))),
    rej("issuer_key_set element is a tagged byte string", "BAD_ISSUER_KEY_ELEMENT", cbor=good_map(issuer_key_set=arr([tag(24, bstr(CERT_A))]))),
    rej("issuer_key_set is an integer (no hook)", "UNSUPPORTED_ISSUER_KEY_SET", cbor=good_map(issuer_key_set=uint(1))),
    rej("issuer_key_set is a map (no hook)", "UNSUPPORTED_ISSUER_KEY_SET", cbor=good_map(issuer_key_set=CUSTOM)),
    rej("results is empty", "EMPTY_RESULTS", cbor=good_map(results=cmap([]))),
    rej("pseudonym of 31 bytes", "BAD_PSEUDONYM_LENGTH", cbor=good_map(results=res((tstr("n"), bstr(pseud(0)[:31]))))),
    rej("pseudonym of 33 bytes", "BAD_PSEUDONYM_LENGTH", cbor=good_map(results=res((tstr("n"), bstr(pseud(0) + b"\x00"))))),
    rej("pseudonym empty", "BAD_PSEUDONYM_LENGTH", cbor=good_map(results=res((tstr("n"), bstr(b""))))),
    rej("predicate false", "BAD_PREDICATE", cbor=good_map(results=res((tstr("n"), FALSE)))),
    rej("predicate null", "BAD_PREDICATE", cbor=good_map(results=res((tstr("n"), NULL)))),
    rej("result is an unsigned integer", "WRONG_TYPE", cbor=good_map(results=res((tstr("n"), uint(1))))),
    rej("result is a text string", "WRONG_TYPE", cbor=good_map(results=res((tstr("n"), tstr("true"))))),
    rej("result is a tagged byte string", "WRONG_TYPE", cbor=good_map(results=res((tstr("n"), tag(24, bstr(pseud(0))))))),
    rej("results key is an integer", "WRONG_TYPE", cbor=good_map(results=res((uint(1), TRUE)))),
    rej("top-level key is an integer", "WRONG_TYPE", cbor=cmap([(uint(1), TRUE), (tstr("circuit_id"), tstr("a")), (tstr("proof"), bstr(b"")), (tstr("issuer_key_set"), arr([bstr(CERT_A)])), (tstr("results"), res((tstr("n"), TRUE)))])),
    rej("proof_time is an untagged text string", "BAD_PROOF_TIME", cbor=good_map(proof_time=tstr(TIME))),
    rej("proof_time is tag 1 (epoch)", "BAD_PROOF_TIME", cbor=good_map(proof_time=tag(1, uint(1777636800)))),
    rej("proof_time is tag 0 holding an integer", "BAD_PROOF_TIME", cbor=good_map(proof_time=tag(0, uint(1)))),
    rej("proof_time is tag 0 holding a non-date string", "BAD_PROOF_TIME", cbor=good_map(proof_time=tag(0, tstr("yesterday")))),
    rej("proof_time is tag 0 without a zone offset", "BAD_PROOF_TIME", cbor=good_map(proof_time=tag(0, tstr("2026-05-01T12:00:00")))),
    rej("trailing byte after the item", "TRAILING_BYTES", cbor=GOOD + b"\x00"),
    rej("a second CBOR item follows", "TRAILING_BYTES", cbor=GOOD + GOOD),
    rej("truncated item", "MALFORMED_CBOR", cbor=GOOD[:-3]),
    rej("empty input", "MALFORMED_CBOR", cbor=b""),
    rej("duplicate top-level key", "MALFORMED_CBOR", cbor=dup),
    rej("unknown top-level key, strict mode", "UNKNOWN_KEY", cbor=good_map(x_future=tstr("later")), strict=True),
    rej("base64url with padding", "BAD_BASE64URL", b64=b64u(GOOD) + "=" * ((4 - len(b64u(GOOD)) % 4) % 4) if len(b64u(GOOD)) % 4 else b64u(GOOD) + "="),
    rej("base64url with '+'", "BAD_BASE64URL", b64="+" + b64u(GOOD)[1:]),
    rej("base64url with '/'", "BAD_BASE64URL", b64="/" + b64u(GOOD)[1:]),
    rej("base64url with whitespace", "BAD_BASE64URL", b64=b64u(GOOD)[:10] + " " + b64u(GOOD)[10:]),
    rej("base64url length 1 mod 4", "BAD_BASE64URL", b64=b64u(GOOD) + "A" * ((1 - len(b64u(GOOD))) % 4)),
]

# base64url with non-zero trailing bits: set a padding bit (not a data bit) of the last character.
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def with_trailing_bits(raw):
    e = b64u(raw)
    assert len(e) % 4 in (2, 3), len(e) % 4
    spare = 4 if len(e) % 4 == 2 else 2  # unused low bits of the last character
    idx = ALPHABET.index(e[-1])
    assert idx & ((1 << spare) - 1) == 0
    return e[:-1] + ALPHABET[idx | 1]


_g = GOOD if len(b64u(GOOD)) % 4 in (2, 3) else good_map(proof=bstr(PROOF + b"\x01"))
REJECTIONS.append(rej("base64url with non-zero trailing bits", "BAD_BASE64URL", b64=with_trailing_bits(_g)))

HOOK_VECTORS = [{
    "name": "issuer_key_set is a map, accepted by the hook",
    "hook": "accepts circuit_id == 'urn:test:custom-keys' and returns Other(rawCborItem); returns null for any other circuit_id",
    "presentation": pres_json(HOOK_P), "cbor_hex": pres_enc(HOOK_P).hex(), "base64url": b64u(pres_enc(HOOK_P)),
}]
HOOK_REJECTIONS = [
    rej("same input without the hook", "UNSUPPORTED_ISSUER_KEY_SET", cbor=pres_enc(HOOK_P)),
    rej("hook declines another circuit_id (null), item is not a list", "UNSUPPORTED_ISSUER_KEY_SET", cbor=pres_enc(base(circuit_id="urn:test:other", issuer_key_set=("other", CUSTOM))), hook=True),
]

HANDLE_CHECKS = [
    {"name": "exact match", "presentation": "golden: rulebook example shape (pseudonym + predicate, no proof_time); circuit_id is the WIP rulebook string", "expected_handles": ["age-range-123", "nym-123"], "ok": True},
    {"name": "missing handle", "presentation": "golden: rulebook example shape (pseudonym + predicate, no proof_time); circuit_id is the WIP rulebook string", "expected_handles": ["age-range-123", "nym-123", "other"], "ok": False},
    {"name": "additional handle", "presentation": "golden: rulebook example shape (pseudonym + predicate, no proof_time); circuit_id is the WIP rulebook string", "expected_handles": ["nym-123"], "ok": False},
    {"name": "no overlap", "presentation": "predicate only", "expected_handles": ["x"], "ok": False},
]


def build():
    return {
        "status": "self-generated, not yet cross-checked with the circuit developers",
        "rulebook": "nym_auth v0.3, Presentation encoding (CircuitZkPresentation)",
        "generator": "tools/gen_circuit_zk_presentation_vectors.py",
        "vectors": [vector_entry(n, p) for n, p in VECTORS],
        "hook_vectors": HOOK_VECTORS,
        "rejections": REJECTIONS + HOOK_REJECTIONS,
        "handle_checks": HANDLE_CHECKS,
    }


if __name__ == "__main__":
    text = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        sys.exit(0 if OUT.read_text() == text else "vectors out of date")
    OUT.write_text(text)
