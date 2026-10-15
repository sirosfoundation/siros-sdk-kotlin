# Provenance

`match.json` and `README.md` here are a verbatim copy of the circuit capability
match vectors of the shared matcher,
`crates/siros-dc-matcher-core/tests/vectors/circuit_capabilities/` in
[sirosfoundation/siros-dc-matcher](https://github.com/sirosfoundation/siros-dc-matcher),
at commit `9237638ea8e2673f82cdfe27d52a2e8be67e0921` (`main` after matcher PR #45; NOT a tag: the latest tag,
`v0.9.0`, predates it). The files are byte-identical to those at `v0.9.0`; only the recorded commit changes.

| file | sha256 |
| --- | --- |
| `match.json` | `9bee1868fd957fd4ad56a91dbca93b922ede04bfa57bb0f8b3a3c9bd5f383866` |
| `README.md` | `aeb7972b16ab4183a473aa9ebcf42d7046994d26129451c5d4aa3e8bbd754d72` |

Not authored here, and not to be edited here: the matcher owns these vectors.
Change them there and copy them again when the SDK takes a new matcher release
(the version in `sdk/credentials/build.gradle.kts`). Copy with:

```sh
M=siros-dc-matcher; V=crates/siros-dc-matcher-core/tests/vectors/circuit_capabilities
git -C $M show <tag>:$V/match.json > spec/circuit-capabilities-vectors/match.json
git -C $M show <tag>:$V/README.md  > spec/circuit-capabilities-vectors/README.md
```

The SDK does not implement the capability rule: the matcher does, and the
wallet only hands it each circuit's `capabilities` as an opaque JSON string at
registration (`CircuitZkCircuit.capabilities`). So these vectors are not run
through any SDK code of its own. `SirosCredentialRegistryCapabilityVectorsTest`
(a device test, because the matcher is native) registers each case's circuits
through `SirosCredentialRegistry` and checks that the matcher offers exactly
the circuits the case expects, which proves the registration reaches the rule
unaltered. Ranking, the profile cases and `expectError` cases are the
catalog's, not the matcher's; see the README for what is and is not checked.
