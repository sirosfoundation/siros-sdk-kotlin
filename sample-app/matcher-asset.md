# `assets/matcher.wasm`

A checked-in binary, so it needs provenance.

## What it is

The Phase 1 build of the SIROS DC API matcher, from
[sirosfoundation/siros-dc-matcher](https://github.com/sirosfoundation/siros-dc-matcher).
BSD-2-Clause, same as this repository — it is our own code, not a
redistribution of anyone else's matcher.

| | |
|---|---|
| Source | `sirosfoundation/siros-dc-matcher`, branch `phase-1-hardware-proof` |
| Built with | `cargo build -p siros-dc-matcher-wasm --target wasm32-wasip1 --release` |
| Size | 85,070 bytes |

## Why it is committed rather than fetched

Phase 1 exists to answer one question — does the platform accept and run a
matcher we supply? — and a checked-in artifact is the shortest path to an
answer on real hardware. It is not the shipping arrangement.

From Phase 6 the matcher arrives as a released artifact with a published
digest, resolved like any other dependency, and this file goes away. Until
then, treat it as a build output that happens to live in Git: do not edit it,
and do not assume it matches the upstream `main`.

## Rebuilding

```sh
git clone git@github.com:sirosfoundation/siros-dc-matcher.git
cd siros-dc-matcher
cargo build -p siros-dc-matcher-wasm --target wasm32-wasip1 --release
cp target/wasm32-wasip1/release/matcher.wasm \
   ../siros-sdk-kotlin/sample-app/src/main/assets/matcher.wasm
```

## What it does today

Emits one fixed entry for any protocol it recognises, and reports what it
observed through the host ABI — host version, verified calling package and
origin, and the size of the registered blob. It does not match credentials
yet; the DCQL engine is Phase 3.
