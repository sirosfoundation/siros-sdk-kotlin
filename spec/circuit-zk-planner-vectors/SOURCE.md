# Provenance

These files are a verbatim copy of the `circuit_zk` planner conformance vectors
of the shared matcher, `crates/siros-dc-matcher-core/tests/vectors/circuit_zk/`
in [sirosfoundation/siros-dc-matcher](https://github.com/sirosfoundation/siros-dc-matcher),
at tag `v0.9.1` (commit `5630bd6023904c4c84d2496b61befe4ea76d5087`). `README.md` beside this file is the matcher's own, and defines the format.

The vectors are byte-identical to those at matcher commit `9237638` (main after PR #45), which this directory held before; `v0.9.1` only bumped versions. PR #45 aligned the vectors with the rulebook request shape (no `verifier_id_type`): five request vectors lost the
parameter and `ok_legacy_verifier_id_type_accepted.json` was added (a request that still carries it is accepted and
the value passes through opaquely). Planner behaviour did not change, so the SDK's pinned matcher AAR (0.9.0, kept: 0.9.1 is
not yet on Maven Central and behaves the same) needs no bump; the vectors pass against it.

| file | sha256 |
| --- | --- |
| `ok_normative_plain.json` | `1cd414d36529eb92d530ff6754779ed8ca600ce459ffdb33a4ee3acd8ac848e5` |
| `ok_example_envelope.json` | `6df46456fc8db63dc1da1c1707916122be8ed153d78f539cf3d14e9f6613e83f` |
| `ok_opaque_strings.json` | `c039c8fd0c129d0f6283b1e08d5775e1c490726b2e39e2162ca5b402ad8c9e3e` |
| `err_duplicate_handle.json` | `0a94dbb8a02535d4ce657b6cdc747bf58de160d91a2a50a80e645c16da8801ed` |
| `err_example_duplicate_handle.json` | `0811cad0d2d7ff7b22697537cb55aafecb4de3415199a512227b1e2142629cd9` |
| `ok_legacy_verifier_id_type_accepted.json` | `0cd2976e365f69ca9830434e2b89a1fb064f1b1a2a7a82e1410c59103e7b643c` |

Not authored here, and not to be edited here: change them in the matcher and
copy them again when the SDK takes a new matcher release (the version in
`sdk/credentials/build.gradle.kts`). Copy with:

```sh
git -C siros-dc-matcher archive <tag-or-commit> crates/siros-dc-matcher-core/tests/vectors/circuit_zk \
  | tar -x --strip-components=5 -C spec/circuit-zk-planner-vectors
```

The matcher's planner is the reference; this SDK's `SharedCircuitZkPlanner`
reads it through the matcher's FFI, and
`SharedCircuitZkPlannerInstrumentedTest` (a device test, because the matcher
is native) checks that the plan the FFI's `circuit_zk_plan` returns equals each `ok_*`
case's `expect.plan` (compared without `raw`, which must equal the query) and
that each `err_*` case is refused with its `expect.error` code. The siros-sdk-swift copy should carry the
same files and the same check.
