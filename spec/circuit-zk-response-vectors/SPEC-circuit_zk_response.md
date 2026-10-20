# `circuit_zk` response shape

Normative description of what a wallet returns for a `circuit_zk` credential
query, and what a verifier-side check accepts. It is the counterpart of the
request side (`req` items with `return` handles; see the planner in
`crates/siros-dc-matcher-core/src/circuit_zk.rs`). Conformance vectors:
`crates/siros-dc-matcher-core/tests/vectors/circuit_zk_response/`. Reference
check: `circuit_zk_response::validate_response`.

This checks **shape and binding to the request**. It does not verify the proof.

## Shape

The response rides in `vp_token`, keyed by the DCQL credential query `id`. The
value is an **array** of presentations, one element per matched credential.

```json
{
  "nym_attestation": [
    {
      "circuit_id": "urn:circuits:longfellow:nym_auth:v1",
      "proof_system": "longfellow-libzk-v1",
      "proof": "<base64url, unpadded>",
      "x5chain": ["<base64 DER leaf (Document Signer)>", "<base64 DER CA>"],
      "results": {
        "nym-123": { "pseudonym": "<base64url, unpadded, 32 bytes>" },
        "age-range-123": { "satisfied": true }
      }
    }
  ]
}
```

There is **one proof per credential**, not per `req` item. Handles key the
`results`, not proofs.

## Rules

A presentation that breaks any rule is refused (the whole response is refused;
there is no partial acceptance). Reason codes are stable identifiers.

1. **Envelope.** `vp_token` is a JSON object with an entry for the query `id`
   (`response_not_parseable`, `query_id_missing`); that entry is a non-empty
   array (`presentations_not_array`, `presentations_empty`) of objects
   (`presentation_not_object`). Entries for other query ids are ignored. Every
   array element is checked against the same request. More than one element is
   allowed only when the credential query sets `multiple: true` (DCQL: omitted
   means false); otherwise `presentations_multiple_not_allowed`.
2. **No in-band errors.** A presentation with an `error` or `error_description`
   member is refused (`presentation_error_member`). A wallet that cannot
   satisfy the request declines at the OpenID4VP level: a plain form post to
   `response_uri` with `error` / `error_description`. It never sends a
   presentation that describes a failure.
3. **Members.** Exactly `circuit_id`, `proof_system`, `proof` (strings),
   `x5chain` (array, rule 5a) and `results` (object). Another member is refused
   (`presentation_unknown_member`); a missing one (`presentation_member_missing`)
   or one of the wrong type (`presentation_member_wrong_type`) likewise. A
   repeated member name anywhere outside `results` is refused
   (`duplicate_member`).
4. **Binding to the offer.** `circuit_id` MUST be in the request's
   `client_metadata.vp_formats_supported.circuit_zk.circuit_id_values`, and
   `proof_system` in `circuit_proof_system_values`
   (`circuit_id_not_offered`, `proof_system_not_offered`). The holder states
   both; the verifier does not trust them beyond membership. If the request
   stated no such list, nothing was offered and the response is refused
   (fail closed).
5. **Proof encoding.** `proof` is non-empty (`proof_empty`) base64url without
   padding: alphabet `A-Z a-z 0-9 - _`, no `=`, no `+` `/`, no whitespace, a
   canonical final character (`proof_not_base64url`). The proof is not
   decoded or verified here.
   5a. **Issuer certificate chain.** `x5chain` is the holder-supplied issuer
   chain, RFC 7515 `x5c` style: a JSON array of strings, each the **standard**
   base64 (RFC 4648 §4, alphabet `A-Z a-z 0-9 + /`, **with** `=` padding, no
   whitespace, canonical final character) of one DER certificate, the leaf
   (Document Signer) first. Normative limits: at most **8** certificates
   and at most **4096** decoded bytes per certificate (both inclusive). Refused:
   not an array (`x5chain_not_array`), empty (`x5chain_empty`), more than 8
   (`x5chain_too_many`), an element that is not a string
   (`x5chain_element_not_string`), not padded standard base64 (base64url
   alphabet, unpadded, invalid, whitespace: `x5chain_element_not_base64`), the
   empty string (`x5chain_element_empty`), over 4096 decoded bytes
   (`x5chain_element_too_large`). Elements are checked in array order. The
   matcher checks **encoding and limits only**: it does not parse X.509. The
   verifier validates the chain through its trust evaluation (go-trust) and
   takes the issuer's P-256 key Q from the validated leaf; it never looks up
   issuer keys itself.
6. **Handles.** The keys of `results` are exactly the `return` handles of the
   request's `req` items: an extra handle (`result_handle_unexpected`), a
   missing handle (`result_handle_missing`) and a repeated handle key
   (`duplicate_handle`) are all refused. Key order is irrelevant.
7. **Result values are objects** (`result_not_object`), by function:
   - `pseudonym-v1-sha256` -> `{"pseudonym": "<base64url unpadded>"}` that
     decodes to exactly 32 bytes (`pseudonym_not_base64url`,
     `pseudonym_wrong_length`).
   - `age_check` -> `{"satisfied": true}`. `satisfied: false` is never valid
     (`result_not_satisfied`): an unsatisfiable predicate is a decline, not a
     result. A non-boolean is `result_member_wrong_type`.
   - A function the validator has no result shape for is refused
     (`result_function_unknown`); a result object for a known function with
     any member other than its own (`result_unknown_member`), or without it
     (`result_member_missing`), is refused.

## JSON `null`

A JSON `null` is a value of the wrong type, wherever it appears. It is never
"absent" (so it is not `presentation_member_missing`) and never an empty
value (not an empty string, array or object). Concretely: `vp_token` ->
`response_not_parseable`; the query-id entry -> `presentations_not_array`; a
presentation -> `presentation_not_object`; `circuit_id` / `proof_system` /
`proof` / `results` -> `presentation_member_wrong_type`; `x5chain` ->
`x5chain_not_array`; an `x5chain` element -> `x5chain_element_not_string`; a
result value -> `result_not_object`; a `pseudonym` or `satisfied` member ->
`result_member_wrong_type`. Vectors: `err_null_*`.

## Order of checks

The first failure in this order is the one reported: envelope (rule 1), then
per presentation in array order: in-band error, unknown members, presence of
all five members, member types (strings; `x5chain` an array; `results` an
object), offer binding, proof encoding, `x5chain` contents (count, then each
element: string, empty, encoding, size), then handles (extra, then missing, all before any
value), then result values per `req` item in request order.

## Decisions worth knowing

- **Two distinct refusals, and which wins.** `result_handle_unexpected` (a
  `results` key that is not a `return` handle of the request) and
  `result_function_unknown` (a request item whose function has no result
  shape) are different codes. Rule 6 (handles) runs before rule 7 (result
  values), so when both apply the handle refusal wins; vector
  `err_precedence_unexpected_handle_over_unknown_function` pins this.
- **Duplicates are judged on raw text.** Vectors for repeated keys use
  `vp_token_text` (raw JSON with the key literally repeated), never an
  object, because decoders silently keep the last key.

- **Strict on unknown members** in presentations and in results of known
  functions, matching the request side's strictness. New members or functions
  need a new vector and a validator change; they do not slip through.
- **Unknown request functions refuse the response.** A request may legally
  contain a function the planner passes through opaquely; a response to it
  cannot be validated, so it is refused (`result_function_unknown`).
- **Empty array refused.** A response with zero presentations is a decline in
  disguise (rule 2).
- **Duplicate JSON members** are detected on the raw text; a parsed object
  cannot represent them. Implementations MUST validate before merging into a
  map.
