#!/usr/bin/env python3
"""Generate spec/circuit-zk-validator-vectors.json with INDEPENDENT code.

The verdicts come from `oracle()` below: a separate, straight reading of the
nym_auth rulebook v0.3 satisfiability rules written in Python (datetime for the
calendar-day arithmetic). It does not call or mirror the Kotlin implementation.
Every case is built to break at most one rule, and the generator asserts that
the oracle's rule id is the one the case names.

Usage: python3 tools/gen_circuit_zk_validator_vectors.py [--check]
"""
import datetime
import json
import pathlib
import re
import sys

OUT = pathlib.Path(__file__).resolve().parent.parent / "spec" / "circuit-zk-validator-vectors.json"
DOCTYPE = "eu.europa.ec.eudi.nym_auth.1"
CONFIGS = {  # config -> (uses verifier_input, requires verifier_context)
    "known-offender-matching-ssc": (True, False),
    "known-offender-matching-psc": (True, False),
    "account-recovery-ssc": (True, True),
    "user-managed-pseudonym-xsite-ssc": (False, False),
}
PSEUDONYM, AGE = "pseudonym-v1-sha256", "age_check"


def full_date(s):
    if not isinstance(s, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        return None
    try:
        return datetime.date.fromisoformat(s)
    except ValueError:
        return None


def oracle(case):
    """Return None when satisfiable, else the id of the first violated rule."""
    q, fns = case["plan"]["query"], case["plan"]["functions"]
    opts = case.get("options", {})
    if "vct_values" in q.get("meta", {}):
        return "meta-vct-values-reserved"
    if q.get("require_cryptographic_holder_binding", True) is not True:
        return "holder-binding-false"
    circuits = opts.get("circuits")
    if circuits is not None:
        flt = case["plan"].get("circuit_filter") or []
        rel = [c for c in circuits
               if DOCTYPE_OF(q) in c["doc_types"]
               and (not flt or any(f.get("system") in (None, c["system"]) and f["circuit_id"] == c["circuit_id"] for f in flt))]
        if rel and not any(c.get("functions") is None or all(f["id"] in c["functions"] for f in fns) for c in rel):
            return "function-not-declared"
    for f in fns:
        if f["id"] not in (PSEUDONYM, AGE):
            return "unknown-function"
    if sum(f["id"] == PSEUDONYM for f in fns) > 1:
        return "pseudonym-count"
    if sum(f["id"] == AGE for f in fns) > 1:
        return "age-check-count"
    for f in fns:
        p = f.get("params", {})
        if f["id"] == PSEUDONYM:
            cfg = CONFIGS.get(p.get("config")) if isinstance(p.get("config"), str) else None
            if cfg is None:
                return "pseudonym-config-unsupported"
            uses_vi, needs_ctx = cfg
            if needs_ctx and "verifier_context" not in p:
                return "verifier-context-required"
            if not needs_ctx and "verifier_context" in p:
                return "verifier-context-forbidden"
            if "verifier_context" in p:
                v = p["verifier_context"]
                if not isinstance(v, str) or not 1 <= len(v.encode("utf-8")) <= 64:
                    return "verifier-context-length"
            # A verifier_id_type member is neither checked nor refused: the wallet picks the type itself.
        else:
            if "ge" not in p and "le" not in p:
                return "age-check-no-bounds"
            if any(k in p and full_date(p[k]) is None for k in ("ge", "le")):
                return "age-check-bad-date"
            if "ge" in p and "le" in p:
                ge, le = full_date(p["ge"]), full_date(p["le"])
                if le < ge:
                    return "age-check-le-before-ge"
                if (le - ge).days + 1 < 365:
                    return "age-check-span-short"
    return None


def DOCTYPE_OF(q):
    return q.get("meta", {}).get("doctype_value")


def query(**extra):
    q = {"id": "nym", "format": "circuit_zk", "meta": {"doctype_value": DOCTYPE}}
    q.update(extra)
    return q


def fn(fid, handle, **params):
    return {"id": fid, "handle": handle, "params": params}


def pseud(config="known-offender-matching-ssc", handle="n", **p):
    params = {"config": config}
    if CONFIGS.get(config, (True, False))[0] and "verifier_id_type" not in p and not p.pop("_no_vit", False):
        params["verifier_id_type"] = "x509_san_dns"
    p.pop("_no_vit", None)
    params.update(p)
    return fn(PSEUDONYM, handle, **params)


def age(handle="a", **p):
    return fn(AGE, handle, **p)


def d(base, n):
    return (datetime.date.fromisoformat(base) + datetime.timedelta(days=n)).isoformat()


CASES = []


def case(name, fns, expect, q=None, flt=None, options=None):
    c = {"name": name, "plan": {"query": q or query(), "functions": fns}, "expect": expect}
    if flt is not None:
        c["plan"]["circuit_filter"] = flt
    if options:
        c["options"] = options
    CASES.append(c)


# --- passing: every function / config ---
case("ok: known-offender ssc, x509_san_dns", [pseud()], None)
case("ok: known-offender psc, semantic", [pseud("known-offender-matching-psc", verifier_id_type="semantic")], None)
case("ok: account-recovery with context", [pseud("account-recovery-ssc", verifier_context="acct-1")], None)
case("ok: xsite has no verifier_id_type", [pseud("user-managed-pseudonym-xsite-ssc")], None)
case("ok: pseudonym and age_check together", [pseud(), age(ge="2000-01-01")], None)
case("ok: explicit holder binding true", [pseud()], None, q=query(require_cryptographic_holder_binding=True))
# --- counts ---
case("fail: two pseudonym items", [pseud(handle="a"), pseud(handle="b")], "pseudonym-count")
case("fail: two age_check items", [age(handle="a", ge="2000-01-01"), age(handle="b", le="2020-01-01")], "age-check-count")
# --- meta / holder binding ---
case("fail: vct_values is reserved", [pseud()], "meta-vct-values-reserved", q={"id": "nym", "format": "circuit_zk", "meta": {"vct_values": ["urn:x"]}})
case("fail: holder binding is the string 'true'", [pseud()], "holder-binding-false", q=query(require_cryptographic_holder_binding="true"))
case("fail: holder binding is a number", [pseud()], "holder-binding-false", q=query(require_cryptographic_holder_binding=1))
case("fail: holder binding false", [pseud()], "holder-binding-false", q=query(require_cryptographic_holder_binding=False))
# --- unknown function ---
case("fail: unknown function id", [fn("future_fn", "f")], "unknown-function")
case("fail: unknown function next to a known one", [pseud(), fn("future_fn", "f")], "unknown-function")
# --- function not declared by the circuit ---
CIRC = lambda **k: dict({"system": "sys", "circuit_id": "c1", "doc_types": [DOCTYPE]}, **k)
case("fail: circuit declares functions and lacks age_check", [pseud(), age(ge="2000-01-01")], "function-not-declared",
     options={"circuits": [CIRC(functions=[PSEUDONYM])]})
case("ok: circuit declares all the functions", [pseud(), age(ge="2000-01-01")], None, options={"circuits": [CIRC(functions=[PSEUDONYM, AGE])]})
case("ok: circuit declares no functions, so no function filtering", [pseud(), age(ge="2000-01-01")], None, options={"circuits": [CIRC()]})
case("ok: no fitting circuit is the matcher's business, not this rule's", [pseud()], None, options={"circuits": [CIRC(doc_types=["other"], functions=[])]})
case("ok: another circuit declares the function", [pseud(), age(ge="2000-01-01")], None,
     options={"circuits": [CIRC(functions=[PSEUDONYM]), CIRC(circuit_id="c2", functions=[PSEUDONYM, AGE])]})
case("fail: circuit_filter narrows to the circuit lacking the function", [pseud(), age(ge="2000-01-01")], "function-not-declared",
     flt=[{"system": "sys", "circuit_id": "c1"}],
     options={"circuits": [CIRC(functions=[PSEUDONYM]), CIRC(circuit_id="c2", functions=[PSEUDONYM, AGE])]})
# --- pseudonym config ---
case("fail: unsupported config", [pseud("made-up-config")], "pseudonym-config-unsupported")
case("fail: config missing", [fn(PSEUDONYM, "n", verifier_id_type="x509_san_dns")], "pseudonym-config-unsupported")
case("fail: config not a string", [fn(PSEUDONYM, "n", config=5, verifier_id_type="x509_san_dns")], "pseudonym-config-unsupported")
# --- verifier_context ---
case("fail: account-recovery without verifier_context", [pseud("account-recovery-ssc")], "verifier-context-required")
case("fail: verifier_context on known-offender", [pseud(verifier_context="c")], "verifier-context-forbidden")
case("fail: verifier_context on xsite", [pseud("user-managed-pseudonym-xsite-ssc", verifier_context="c")], "verifier-context-forbidden")
case("fail: empty verifier_context", [pseud("account-recovery-ssc", verifier_context="")], "verifier-context-length")
case("ok: 1-byte verifier_context", [pseud("account-recovery-ssc", verifier_context="c")], None)
case("ok: 64-byte verifier_context", [pseud("account-recovery-ssc", verifier_context="c" * 64)], None)
case("fail: 65-byte verifier_context", [pseud("account-recovery-ssc", verifier_context="c" * 65)], "verifier-context-length")
case("ok: 16 four-byte characters are 64 bytes", [pseud("account-recovery-ssc", verifier_context="\U0001F512" * 16)], None)
case("fail: 17 four-byte characters are 68 bytes (17 characters)", [pseud("account-recovery-ssc", verifier_context="\U0001F512" * 17)], "verifier-context-length")
case("ok: 32 two-byte characters are 64 bytes", [pseud("account-recovery-ssc", verifier_context="å" * 32)], None)
case("fail: 33 two-byte characters are 66 bytes (33 characters)", [pseud("account-recovery-ssc", verifier_context="å" * 33)], "verifier-context-length")
case("fail: verifier_context not a string", [pseud("account-recovery-ssc", verifier_context=7)], "verifier-context-length")
# --- verifier_id_type ---
# The request no longer carries verifier_id_type (the wallet picks the type); absent is satisfiable.
case("ok: known-offender without verifier_id_type", [pseud(_no_vit=True)], None)
case("ok: account-recovery without verifier_id_type", [pseud("account-recovery-ssc", verifier_context="c", _no_vit=True)], None)
# A request that still carries verifier_id_type is accepted and the member ignored (rulebook v0.3 removed it).
case("ok: legacy verifier_id_type is accepted and ignored (xsite, which has no verifier input)", [pseud("user-managed-pseudonym-xsite-ssc", verifier_id_type="semantic")], None)
case("ok: legacy verifier_id_type of an unknown value is ignored", [pseud(verifier_id_type="x509_hash")], None)
case("ok: legacy verifier_id_type that is not a string is ignored", [pseud(verifier_id_type=1)], None)
# --- age_check ---
case("fail: age_check with no bounds", [age()], "age-check-no-bounds")
case("ok: ge only", [age(ge="2000-01-01")], None)
case("ok: le only", [age(le="2000-01-01")], None)
case("fail: le before ge", [age(ge="2001-01-02", le="2001-01-01")], "age-check-le-before-ge")
case("fail: le before ge by a year", [age(ge="2020-01-01", le="2019-01-01")], "age-check-le-before-ge")
case("fail: le == ge is a one-day span", [age(ge="2001-01-01", le="2001-01-01")], "age-check-span-short")
case("fail: 364-day span", [age(ge="2001-01-01", le=d("2001-01-01", 363))], "age-check-span-short")
case("ok: 365-day span", [age(ge="2001-01-01", le=d("2001-01-01", 364))], None)
case("ok: 366-day span", [age(ge="2001-01-01", le=d("2001-01-01", 365))], None)
case("fail: 364 days inside a non-leap year (Jan 1 to Dec 30)", [age(ge="2023-01-01", le="2023-12-30")], "age-check-span-short")
case("ok: Jan 1 to Dec 31 of a non-leap year is 365 days", [age(ge="2023-01-01", le="2023-12-31")], None)
case("fail: leap year Jan 1 to Dec 30 is 365 days, so Jan 1 to Dec 29 is 364", [age(ge="2024-01-01", le="2024-12-29")], "age-check-span-short")
case("ok: leap year Jan 1 to Dec 30 is 365 days", [age(ge="2024-01-01", le="2024-12-30")], None)
case("fail: across Feb 29, 2023-03-01 to 2024-02-28 is 365 days minus one (364)", [age(ge="2023-03-01", le="2024-02-27")], "age-check-span-short")
case("ok: across Feb 29, 2023-03-01 to 2024-02-28 is 365 days", [age(ge="2023-03-01", le="2024-02-28")], None)
case("fail: across Feb 29, 2024-03-01 to 2025-02-27 is 364 days", [age(ge="2024-03-01", le="2025-02-27")], "age-check-span-short")
case("ok: across Feb 29, 2024-03-01 to 2025-02-28 is 365 days", [age(ge="2024-03-01", le="2025-02-28")], None)
case("ok: a long range", [age(ge="1900-01-01", le="2100-12-31")], None)
case("fail: ge is not a full-date", [age(ge="2000-1-1")], "age-check-bad-date")
case("fail: le is not a calendar date", [age(le="2001-02-30")], "age-check-bad-date")
case("fail: ge is a date-time", [age(ge="2000-01-01T00:00:00Z")], "age-check-bad-date")
case("fail: ge has an expanded year", [age(ge="+02000-01-01")], "age-check-bad-date")
case("fail: ge is a number", [age(ge=20000101)], "age-check-bad-date")


def build():
    out = []
    for c in CASES:
        want = oracle(c)
        assert want == c["expect"], (c["name"], want, c["expect"])
        e = {"name": c["name"], "plan": c["plan"]}
        if "options" in c:
            e["options"] = c["options"]
        e["verdict"] = {"ok": True} if want is None else {"access_denied": want}
        out.append(e)
    return {
        "status": "self-generated, not yet cross-checked with the circuit developers",
        "rulebook": "nym_auth v0.3, satisfiability rules (query structure, pseudonym and age_check functions)",
        "generator": "tools/gen_circuit_zk_validator_vectors.py",
        "cases": out,
    }


if __name__ == "__main__":
    text = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        sys.exit(0 if OUT.read_text() == text else "vectors out of date")
    OUT.write_text(text)
