# nymauth-native

Native nymauth provers for the SIROS SDKs (Kotlin first), through UniFFI.

**Longfellow** proves the nym_auth mdoc circuits (the nym-auth-circuits archive's LFC2 pair: the age range and
the `known-offender-matching-ssc` pseudonym with `prf` `sha-256`) on **Google's longfellow-zk Rust runtime**
(`61a8a73`). It does so through community-demo's own `nym-longfellow` crate, the code community-demo's verifier
runs, so the prover and that verifier share one implementation. It is an alternative to zk-cred-longfellow
(ISRG's Rust Longfellow) for the SDK's `longfellow-nymauth` system. The SDK chooses an implementation per system
(`NymAuthBinding`, `UniffiNymAuthNativeProver.withBindings`).

| | This library (Google runtime) | zk-cred-longfellow (ISRG) |
| --- | --- | --- |
| Proof, teen's demo mdoc | 344,260 bytes | 619,220 bytes |
| Prove (x86-64 container, one thread) | ~0.53 s | – |
| Each verifies the other's proofs | yes (`cross-check/`) | yes |

## API (UniFFI)

- `LongfellowProver.load(circuit, params, artifactHash)` takes:
  - `circuit`: the decompressed artifact (signature circuit, then hash circuit);
  - `params`: the catalog descriptor's `block_enc_hash`, `block_enc_sig`, `hash_circuit_id` and `sig_circuit_id`;
  - `artifactHash`: `sha256:<hex>` of the compressed artifact.

  Only an approved build loads (`APPROVED` in `src/longfellow.rs`): the descriptor's values, and the artifact's
  exact length and SHA-256, must match. The build's `params.tsv` and `hash-semantic.tsv` (the slot map) are
  compiled in from `circuits/`.
- `prove(LongfellowProveRequest)`: the request's fields are the SDK's `NymAuthProveRequest`, field for field.
  1. It checks the inputs: sizes, T, E ≤ C, the transcript, and that e2 is the DeviceAuthentication digest of the
     transcript.
  2. It checks the holder's data as the circuits will:
     - the credential and the issuer key;
     - the issuer and device signatures;
     - `SHA-256(secret_seed) == ssc`;
     - validity at T, and the birth date in [E, C].

     Each misfit is a refusal with a reason, not a failed proof.
  3. It returns the proof, the pseudonym and the metrics: witness and prove times, `heap_mb` and `witness_mb` in
     community-demo's meaning, counted by the library's own allocator.
- `LongfellowVerifier.load(...)` and `.verify(values, proof, pseudonym)`.
- `nymauthChallengeDigest(transcript, docType)`, `nymauthVerifierInput(verifierId)`, `nymauthNativeVersion()`.

Errors are coarse kinds that mirror the SDK's `NymAuthNativeErrorKind` and `NymAuthRefusal`, and carry nothing
the native side computed.

## Build and test

`nym-longfellow` is taken by path from a readdit-demo checkout next to siros-sdk-kotlin (`../readdit-demo` from the repository root) (AltmannPeter/readdit-demo, `main` or `launchpad-perf` from commit `50c47ac`, which adds
`Circuits::from_pair` and `Layout::parse`).

```sh
cargo test --release                       # prove with the teen's demo mdoc; this library's verifier and
                                           # community-demo's verifier accept it; refusals; approved build only
(cd cross-check && cargo test --release)   # with zk-cred-longfellow next to siros-sdk-kotlin: each verifies the other's proofs
scripts/build-android.sh                   # arm64-v8a and x86_64 .so (PMULL checked), Kotlin bindings, AAR,
                                           # published to ~/.m2 as org.siros:nymauth-native:<version>
```

## Notices

- Google's longfellow-zk runtime (Apache-2.0, vendored in community-demo's `native/longfellow/vendor`).
- `nym-longfellow` and the circuits are community-demo's, from the SIROS nym-auth-circuits archive.
- This library's own license is to be decided.
