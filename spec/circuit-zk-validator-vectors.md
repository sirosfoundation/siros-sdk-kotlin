# circuit_zk validator test vectors

`circuit-zk-validator-vectors.json` holds `plan -> verdict` cases for the
wallet-side satisfiability rules of the nym_auth rulebook v0.3 (the
data-independent MUST rules for a planned `circuit_zk` request), implemented in
the Kotlin SDK as `RulebookCircuitZkValidator`. It is meant to be copied
unchanged into siros-sdk-swift and the TypeScript wallet, each with a parity
check against this copy.

**Status: self-generated, not yet cross-checked with the circuit developers.**
The rulebook text can still change; that is why the rules are data.

## Format

`cases[]`:

| Field | Meaning |
|---|---|
| `name` | description |
| `plan.query` | the `circuit_zk` credential query (`meta`, optional `require_cryptographic_holder_binding`) |
| `plan.functions[]` | the planned `req` items: `id`, `handle`, `params` (raw JSON object) |
| `plan.circuit_filter` | optional verifier circuit list: `[{system?, circuit_id}]` |
| `options.registered_verifier_id_types` | the verifier-id types the wallet has a source for; default `default_registered_verifier_id_types` (`semantic`, `x509_san_dns`) |
| `options.circuits` | the wallet's circuit table: `{system, circuit_id, doc_types, functions?}`; absent means the function-declaration rule has no circuits to consult; `functions` absent means the circuit declares none |
| `verdict` | `{"ok": true}` or `{"access_denied": "<rule id>"}` |

The wallet's supported pseudonym configurations are the four rulebook ones in
every case. Each case breaks at most one rule, so the rule id does not depend
on rule order. Rule ids are for local logs and tests: they are never sent to
the verifier, which only ever sees `access_denied` with no description.

Rule ids: `meta-vct-values-reserved`, `holder-binding-false`,
`function-not-declared`, `unknown-function`, `pseudonym-count`,
`age-check-count`, `pseudonym-config-unsupported`,
`verifier-context-required`, `verifier-context-forbidden`,
`verifier-context-length` (1-64 UTF-8 bytes), `verifier-id-type-required`,
`verifier-id-type-forbidden`, `verifier-id-type-unregistered`,
`age-check-no-bounds`, `age-check-bad-date`, `age-check-le-before-ge`,
`age-check-span-short` (`le - ge + 1` below 365 calendar days).

Two readings the rulebook text leaves open, chosen here: a date that is not an
RFC 3339 `full-date` (`YYYY-MM-DD`, a real calendar date) is unsatisfiable
(`age-check-bad-date`); and `function-not-declared` applies only when some
circuit fits the query's doctype and circuit list, and then fails unless at
least one of those circuits declares no functions or declares every planned one.

## How the expected values were generated

`tools/gen_circuit_zk_validator_vectors.py` holds a separate `oracle()`, a
straight Python reading of the rulebook (`datetime` for the calendar-day
arithmetic), and asserts that its verdict for every case equals the verdict the
case was written to have. It does not call the Kotlin code. Regenerate with
`python3 tools/gen_circuit_zk_validator_vectors.py`; verify with `--check`.
