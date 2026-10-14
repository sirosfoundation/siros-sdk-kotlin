# Provenance

These files are a verbatim copy of the `circuit_zk` planner conformance vectors
of the shared matcher, `crates/siros-dc-matcher-core/tests/vectors/circuit_zk/`
in [sirosfoundation/siros-dc-matcher](https://github.com/sirosfoundation/siros-dc-matcher),
at tag `v0.8.0` (commit `d68cf52b77e62b0dd0b37311dcff37d1e8fd5362`). `README.md`
beside this file is the matcher's own, and defines the format.

Not authored here, and not to be edited here: change them in the matcher and
copy them again when the SDK takes a new matcher release (the version in
`sdk/credentials/build.gradle.kts`). Copy with:

```sh
git -C siros-dc-matcher archive <tag> crates/siros-dc-matcher-core/tests/vectors/circuit_zk \
  | tar -x --strip-components=5 -C spec/circuit-zk-planner-vectors
```

The matcher's planner is the reference; this SDK's `SharedCircuitZkPlanner`
reads it through the matcher's FFI, and
`SharedCircuitZkPlannerInstrumentedTest` (a device test, because the matcher
is native) checks that the plan the FFI returns equals each `ok_*` case's
`expect.plan` (compared without `raw`, which must equal the query) and that
each `err_*` case is not planned. The siros-sdk-swift copy should carry the
same files and the same check.
