#!/usr/bin/env python3
"""Generate spec/circuit-zk-consent-vectors.json with INDEPENDENT code.

Maps what phase 1 of a circuit_zk request established (plan functions per query, the credential that
will be proved, the trust outcome, the resolved verifier_id and its type, the request's verified
client-id display name, the attested origin) to the LOCALE-FREE consent request: item kinds, config,
scope, remappable flags, age bounds as dates and integers. Both SDKs generate their text from the
same items and test against this file. It neither calls nor imports the Kotlin implementation.

Item semantics (the generator is the reference):
  - items are in the plan's function order; claims of a legacy function are one item each, then the
    legacy pseudonym when requested.
  - age_check: both bounds -> between (min_years = years(le, today), max_years = years(ge, today));
    only `le` -> at_least(years(le, today)); only `ge` -> at_most(years(ge, today)). years() is the
    number of completed years from the date to `today`, never below 0. Dates are strict YYYY-MM-DD.
  - pseudonym: only per-verifier configs are modelled (known-offender-matching-ssc: the issuer can
    remap it; known-offender-matching-psc: it cannot). Any other config, a verifier_context on a
    per-verifier config, or no verifier_id: the request is REFUSED (expected "refused": true).
  - an unknown function id, a plan with no function, or an unknown/ill-formed age_check: REFUSED.
  - input.verifier_id / verifier_id_type are what the wallet resolved; a query is given the verifier_id only
    when its plan has a pseudonym-v1-sha256 or a legacy pseudonym (the wallet resolves one only then), and the
    request's verifier.verifier_id is the first such query's.
  - verifier label: trust entity name, else the verified client-id display name (null for an
    unsigned request), else the attested origin.

Usage: python3 tools/gen_circuit_zk_consent_vectors.py [--check]
"""
import json
import pathlib
import re
import sys
from datetime import date

OUT = pathlib.Path(__file__).resolve().parent.parent / "spec" / "circuit-zk-consent-vectors.json"
TODAY = "2026-10-19"
FULL_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

CONFIGS = {
    "known-offender-matching-ssc": ("per_verifier", True),
    "known-offender-matching-psc": ("per_verifier", False),
}


def parse_date(s):
    if not isinstance(s, str) or not FULL_DATE.match(s):
        return None
    try:
        return date.fromisoformat(s)
    except ValueError:
        return None


def years(born, today):
    n = today.year - born.year - ((today.month, today.day) < (born.month, born.day))
    return max(0, n)


def age_item(params, today):
    if any(k not in ("ge", "le") for k in params):
        return None
    ge, le = params.get("ge"), params.get("le")
    if ge is None and le is None:
        return None
    gd, ld = parse_date(ge) if ge is not None else None, parse_date(le) if le is not None else None
    if (ge is not None and gd is None) or (le is not None and ld is None):
        return None
    if gd and ld:
        form = {"kind": "between", "from": ge, "to": le, "min_years": years(ld, today), "max_years": years(gd, today)}
    elif ld:
        form = {"kind": "at_least", "years": years(ld, today)}
    else:
        form = {"kind": "at_most", "years": years(gd, today)}
    return {"kind": "age_range", "ge": ge, "le": le, "form": form}


def items_of(plan, verifier_id, today):
    today = date.fromisoformat(today)
    out = []
    for f in plan:
        p = f.get("params", {})
        if f["id"] == "pseudonym-v1-sha256":
            cfg = p.get("config")
            if cfg not in CONFIGS:
                return None
            scope, remap = CONFIGS[cfg]
            ctx = p.get("verifier_context")
            if scope == "per_verifier" and ctx is not None:
                return None
            if not verifier_id:
                return None
            out.append({"kind": "pseudonym", "config": cfg, "scope": scope, "remappable_by_issuer": remap,
                        "cross_site": scope == "cross_site", "verifier_id": verifier_id, "verifier_context": ctx})
        elif f["id"] == "age_check":
            it = age_item(p, today)
            if it is None:
                return None
            out.append(it)
        elif f["id"] == "zk-claim-disclosure-v1":
            for c in p["claims"]:
                out.append({"kind": "claim", "name": c})
            if p.get("pseudonym"):
                out.append({"kind": "legacy_pseudonym", "verifier_context": p.get("verifier_context")})
        else:
            return None
    return out or None


def label(trust, client_name, origin):
    for v in (trust.get("entity_name"), client_name):
        if v and v.strip():
            return v
    return origin


def fn(id_, handle, **params):
    return {"id": id_, "handle": handle, "params": params}


SSC = fn("pseudonym-v1-sha256", "n", config="known-offender-matching-ssc")
PSC = fn("pseudonym-v1-sha256", "n", config="known-offender-matching-psc")
LEGACY = fn("zk-claim-disclosure-v1", "d", claims=["family_name", "given_name"], systems=[{"id": "c", "system": "longfellow-libzk-v1"}])
LEGACY_PSEUDO = fn("zk-claim-disclosure-v1", "d", claims=["age_over_18"], systems=[{"id": "c", "system": "longfellow-libzk-v1"}],
                   pseudonym=True, verifier_context="ctx-1")
LONG_DID = "did:web:verifier.example.org:very:long:path:segment:identifying:this:verifier"
CRED = {"name": "Nym credential", "issuer": "Example Issuer"}
TRUST = {"entity_name": "Example RP", "framework": "etsi-tl", "identifier": "rp.example", "intermediary_risk": False}


def case(name, queries, verifier_id="rp.example", verifier_id_type="x509_san_dns", trust=TRUST, client_name="rp.example",
         origin="https://rp.example", today=TODAY):
    """queries: list of (plan functions, credential). verifier_id applies to every query that has a pseudonym."""
    qs = [{"plan": plan, "credential": cred} for plan, cred in queries]
    entries = []
    refused = False
    for plan, cred in queries:
        items = items_of(plan, verifier_id, today)
        if items is None:
            refused = True
            break
        entries.append({"credential": cred, "items": items})
    exp = {"refused": True} if refused else {"request": {
        "verifier": {
            "label": label(trust, client_name, origin),
            "trust_framework": trust.get("framework"), "trust_identifier": trust.get("identifier"),
            "verifier_id": verifier_id if any(i["kind"] == "pseudonym" for e in entries for i in e["items"]) or
            any(f["id"] == "zk-claim-disclosure-v1" and f["params"].get("pseudonym") for q, _ in queries for f in q) else None,
            "verifier_id_type": verifier_id_type,
            "intermediary_risk": bool(trust.get("intermediary_risk")),
        },
        "entries": entries, "request_signed": True,
    }}
    return {"name": name, "today": today,
            "input": {"queries": qs, "trust": trust, "verified_client_id_display_name": client_name, "attested_origin": origin,
                      "verifier_id": verifier_id, "verifier_id_type": verifier_id_type},
            "expected": exp}


def age(**p): return fn("age_check", "a", **p)


CASES = [
    case("ssc pseudonym: per verifier, the issuer can remap it", [([SSC], CRED)]),
    case("psc pseudonym: per verifier, the issuer cannot remap it", [([PSC], CRED)]),
    case("pseudonym and age keep the plan's order", [([SSC, age(ge="1990-01-01", le="2008-10-19")], CRED)]),
    case("age first, then pseudonym", [([age(ge="1990-01-01", le="2008-10-19"), SSC], CRED)]),
    case("age: both bounds", [([age(ge="1990-01-01", le="2008-10-19")], CRED)]),
    case("age: at least (only le); birthday is today", [([age(le="2008-10-19")], CRED)]),
    case("age: at least, birthday is tomorrow (one year less)", [([age(le="2008-10-20")], CRED)]),
    case("age: at most (only ge)", [([age(ge="2000-01-01")], CRED)]),
    case("age: leap-day bound", [([age(le="2008-02-29")], CRED)]),
    case("age: bound in the future clamps to 0", [([age(le="2030-01-01")], CRED)]),
    case("age: other today", [([age(ge="1990-01-01", le="2008-10-19")], CRED)], today="2027-10-18"),
    case("age: no bound is refused", [([age()], CRED)]),
    case("age: unknown parameter is refused", [([age(ge="2000-01-01", gt="1999-01-01")], CRED)]),
    case("age: malformed date is refused", [([age(ge="2000-1-1")], CRED)]),
    case("age: impossible date is refused", [([age(ge="2000-02-30")], CRED)]),
    case("pseudonym without a verifier_id is refused", [([SSC], CRED)], verifier_id=None, verifier_id_type=None),
    case("account-recovery-ssc is not modelled: refused", [([fn("pseudonym-v1-sha256", "n", config="account-recovery-ssc", verifier_context="acct")], CRED)]),
    case("user-managed-pseudonym-xsite-ssc is not modelled: refused", [([fn("pseudonym-v1-sha256", "n", config="user-managed-pseudonym-xsite-ssc")], CRED)]),
    case("a verifier_context on a per-verifier config is refused", [([fn("pseudonym-v1-sha256", "n", config="known-offender-matching-ssc", verifier_context="x")], CRED)]),
    case("unknown config is refused", [([fn("pseudonym-v1-sha256", "n", config="nope")], CRED)]),
    case("unknown function is refused", [([fn("mystery", "m")], CRED)]),
    case("empty plan is refused", [([], CRED)]),
    case("legacy claim disclosure lists the claim names", [([LEGACY], CRED)], verifier_id=None, verifier_id_type=None),
    case("legacy claim disclosure with a pseudonym", [([LEGACY_PSEUDO], CRED)]),
    case("two queries: one request, both queries' items", [([SSC], CRED), ([age(le="2008-10-19")], {"name": "Other", "issuer": None})]),
    case("credential without a name or issuer", [([SSC], {"name": None, "issuer": None})]),
    case("label: trust entity name wins", [([SSC], CRED)], client_name="client.example"),
    case("label: verified client-id display name when the trust decision has no name", [([SSC], CRED)],
         trust={"entity_name": None, "framework": "etsi-tl", "identifier": "rp.example"}),
    case("label: blank entity name is no name", [([SSC], CRED)],
         trust={"entity_name": "  ", "framework": None, "identifier": None}),
    case("label: attested origin for an unsigned request (client id is unauthenticated)", [([SSC], CRED)],
         trust={"entity_name": None, "framework": None, "identifier": None}, client_name=None),
    case("a long DID verifier id is carried whole", [([SSC], CRED)], verifier_id=LONG_DID, verifier_id_type="semantic"),
    case("intermediary risk flag", [([SSC], CRED)], trust=dict(TRUST, intermediary_risk=True)),
]

# Display shortening of a verifier_id (the value used for hashing is never altered): more than 40 code points
# keeps the first 18 and the last 18 joined by U+2026; 40 or fewer is shown whole. Counts are code points.
SHORTENING = [
    {"id": "rp.example", "display": "rp.example"},
    {"id": "a" * 40, "display": "a" * 40},
    {"id": "a" * 41, "display": "a" * 18 + "…" + "a" * 18},
    {"id": LONG_DID, "display": LONG_DID[:18] + "…" + LONG_DID[-18:]},
    {"id": "\U0001F600" * 41, "display": "\U0001F600" * 18 + "…" + "\U0001F600" * 18},
]


def build():
    return {
        "status": "self-generated; the Kotlin and Swift SDKs test against this file byte-for-byte",
        "generator": "tools/gen_circuit_zk_consent_vectors.py",
        "note": "Locale-free: the SDK-owned wording is generated from these items and is not part of this file.",
        "cases": CASES,
        "verifier_id_shortening": SHORTENING,
    }


if __name__ == "__main__":
    text = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        sys.exit(0 if OUT.read_text() == text else "vectors out of date")
    OUT.write_text(text)
