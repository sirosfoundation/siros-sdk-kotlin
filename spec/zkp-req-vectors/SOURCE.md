# Provenance

Verbatim copy of the `zkp_req` conformance vectors of the shared matcher,
`crates/siros-dc-matcher-core/tests/vectors/{zkp_req,zkp_req_response,zkp_req_unsat,proof_time}/` in
[sirosfoundation/siros-dc-matcher](https://github.com/sirosfoundation/siros-dc-matcher) pull request 50 (rulebook v0.4),
merged as squash commit `93047bc7b8a22117fbc9b4c8cd59ce7cd742e8d3` on main (not tagged or released yet). The vectors are
byte-identical to the pull request's head `69e6be128340c6baed57ca16256956d5107b87ac` (only `scripts/vectors_digest.sh` differs
between the two). Counts: 54 / 143 / 43 / 1 json files (plus each directory's README).

Vector set digest (`scripts/vectors_digest.sh` of the matcher: the sha256 of the sorted `sha256sum` manifest of the json
files, paths relative to `tests/vectors`, README.md excluded):

    9f482d7a3fb87cb1381d0dfb7a2fc396b6cd3c1eba07c5d76f44e47142b751ac

The SDK test `ZkpReqVectorSetTest` recomputes it. Not authored here and not to be edited here: the matcher owns them.
Re-pin to the matcher release (and re-copy) once one containing this commit is cut.

The normative text is `docs/zkp_req_request.md` and `docs/zkp_req_response.md` of the matcher at that commit.
