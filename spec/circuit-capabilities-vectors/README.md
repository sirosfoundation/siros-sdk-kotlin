# circuit capabilities match vectors

`match.json` is the corpus for the capability rule the matcher applies
(`Capabilities::serves`). **This repository owns it.** It started as a draft in
the circuit-catalog work (go-zk-circuits issue 35, sha256
`9bee1868fd957fd4ad56a91dbca93b922ede04bfa57bb0f8b3a3c9bd5f383866` at the point
it was copied); the catalog stores capability metadata only and has no matching
code or vectors. The SDKs copy this file from a release tag of this repository,
the way they copy the planner vectors, and record the tag and hash beside their
copy. The matcher is held to it by `tests/circuit_capabilities.rs`.

Change a vector here only together with the rule, in the same PR, and say so in
the changelog: a changed vector changes what every wallet must do.

## What the matcher is held to, and what it is not

The matcher implements the capability rule (`Capabilities::serves`: presentation
and credential, per-function params and `max`, `always`). For each case the
test applies the wallet's side (the `proofSystems` and `circuitIds` filters,
aliases, `revoked`) and then compares the set of
served circuit ids with `expect`.

- **Ranking is not checked.** `expect` is ordered (active before deprecated,
  profile preference, id tie-break); the matcher does not rank circuits, a
  wallet does, so the test compares sets. The `profile-*`,
  `deprecated-ranks-below-active` and `id-tiebreak` cases therefore pin
  membership only. `conformsToProfiles` and `credential.profile` are not read
  by the matcher.
- **`expectError` cases** (a request without presentation, credential format or
  credential type) cannot arise in the matcher, whose presentation is fixed
  at `circuit_zk` and whose format and type come from the profile and `meta`.
  The test requires that nothing is served for them.
- **`credential.format`** is compared against the formats the profile maps
  `circuit_zk` onto (stored `mso_mdoc`), not against a request member, because
  a `circuit_zk` request does not carry one.
- **`empty-req`** is served by `serves` as the vectors say. A real request
  never reaches it: the planner rejects an empty `req` as structurally invalid.
