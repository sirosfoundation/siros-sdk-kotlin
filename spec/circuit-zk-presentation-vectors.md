# circuit_zk presentation test vectors

`circuit-zk-presentation-vectors.json` holds test vectors for the
`CircuitZkPresentation` encoding (nym_auth rulebook v0.3, "Presentation
encoding"). The codec is generic `circuit_zk` functionality: nothing in it
names a credential type, a circuit or a verifier, and `circuit_id` is an opaque
string that the caller checks against the circuit catalog.

**Status: self-generated, not yet cross-checked with the circuit developers.**
The rulebook example is marked WIP and its `circuit_id`
(`urn:circuits:longfellow:nym_auth:v1`) matches no catalog entry; the golden
vector uses that string as an opaque value.

The Kotlin SDK's `CircuitZkPresentationTest` consumes the file. It is meant to
be copied unchanged into siros-sdk-swift next to a parity check that the copy
equals this one (as for `bridge-capabilities.json`).

## Format

Binary values are lowercase hex; the `*_hex` suffix says so.

`vectors[]` (decode with no hook, not strict; also encode):

| Field | Meaning |
|---|---|
| `name` | description; `handle_checks` refer to it |
| `presentation` | the logical value: `circuit_id`, `proof_hex`, `issuer_key_set` (`{der_certificates_hex: [...]}` or `{other_cbor_hex}`), optional `proof_time` (RFC 3339), `results` (`handle -> {pseudonym_hex}` or `{predicate: true}`), optional `unknown_entries_cbor_hex` (`key -> encoded CBOR value`) |
| `cbor_hex` | the exact encoding |
| `base64url` | the same, base64url without padding |

An implementation must satisfy, for each vector: `encode(presentation) ==
cbor_hex`, `encodeBase64Url(presentation) == base64url`, and decoding either
form gives back `presentation`. `results` is compared as a map (order is not
significant); unknown entries are compared by key and raw CBOR value.

Encoding rules the vectors fix: top-level keys in the order `circuit_id`,
`proof`, `issuer_key_set`, `proof_time` (if present, CBOR tag 0 around a text
string), `results`, then unknown entries in their given order; `results` keys
sorted by UTF-8 bytes; definite lengths, shortest integer heads. `proof_time`
is written as an ISO-8601 UTC instant as `java.time.Instant.toString()` does
(`Z` suffix, seconds always present, fractional digits in groups of three); it
is decoded from any RFC 3339 date-time with an offset.

`hook_vectors[]`: like `vectors[]`, but the `issuer_key_set` is a CBOR map and
decoding needs the test hook: *called with (`circuit_id`, encoded
`issuer_key_set` item), it returns `Other(that item)` when `circuit_id` is
`urn:test:custom-keys` and returns "no opinion" (null) for any other circuit
id, which leaves the item to the default `[+ bstr]` rule.*

`rejections[]`: `cbor_hex` or `base64url` (exactly one), `strict` (reject
unknown top-level keys), `issuer_key_set_hook` (decode with the test hook
above), and `error`, which an implementation must report as the reason:

`BAD_BASE64URL`, `MALFORMED_CBOR` (incl. duplicate map keys), `TRAILING_BYTES`,
`NOT_A_MAP`, `MISSING_KEY`, `WRONG_TYPE`, `EMPTY_ISSUER_KEY_SET`,
`BAD_ISSUER_KEY_ELEMENT`, `UNSUPPORTED_ISSUER_KEY_SET`, `EMPTY_RESULTS`,
`BAD_PSEUDONYM_LENGTH`, `BAD_PREDICATE`, `BAD_PROOF_TIME`, `UNKNOWN_KEY`.
When an input breaks several rules, the vector breaks exactly one.

`handle_checks[]`: the opt-in `requireResultHandles(expected_handles)` on the
named vector's decoded presentation either passes (`ok: true`) or fails with
`RESULT_HANDLES_MISMATCH`. The decoder never applies it by itself.

## How the expected values were generated

`tools/gen_circuit_zk_presentation_vectors.py` uses a hand-written minimal CBOR
encoder (Python standard library only, no CBOR library), builds each
presentation and each malformed input directly from the CDDL, and does not call
the Kotlin implementation. Regenerate with
`python3 tools/gen_circuit_zk_presentation_vectors.py`; check the committed
file is current with `--check`.
