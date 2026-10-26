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

**BBS** proves the nym_auth attestation in its `bbs_cd` encoding (rulebook v0.4: ETSI BBS committed disclosures
v0.7 with the `ecdsa-pop`, `pseudonym` and `date-range` plugins of sirosfoundation/bbs-cd-plugins 0.1), through
community-demo's own `nym-bbs` crate, the code its BBS verifier runs. The device key never comes here: the one
ecdsa-pop signature (hashed mode, ECDSA-P256-SHA256 over the plugin's device message) is made by the host's
`BbsDeviceSigner`, a StrongBox key in the SDK, and checked against the device key before it is used. The SDK's
existing `zk-cred-bbs` (blind BBS with Schnorr binding) is a different scheme and is not touched.

| | BBS (`bbs_cd`), teen's demo credential, 13–17 and pseudonym |
| --- | --- |
| Presentation (envelope) | 126,472 bytes (126,240) |
| Prove (x86-64 container, one thread) | ~0.16 s, heap 2.3 MB |

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
- `BbsProver.load()` builds the date-range tables once. `prove(requestObject, credentialQueryId, handover,
  credential, devicePublicKey, signer, parallel)`:
  - `requestObject` is the verified Request Object (JSON), `handover` its OpenID4VPHandover values (B.2.6.1:
    client_id, nonce, response_uri, the response-encryption key's thumbprint), from which `nym-bbs` derives the
    BBS request and its audience as the verifier does;
  - `credential` is the stored `bbs_cd` credential (community-demo's `CredentialJson`), checked against the
    profile's schema and its issuer's signature;
  - the age range is checked before the device is asked, so an unmet request signs nothing (`Unsatisfied`);
  - `signer.sign(message)` returns raw `r || s`; its own error comes back as it raised it, and a signature that
    does not verify under `devicePublicKey` is refused (`DeviceSignature`).

  It returns the `ZkpPresentation` (CBOR), the pseudonym (48-byte G1 point) under its `return` handle, the
  predicate handles, and the metrics (offline and online steps, the device signature's time, `heap_mb`).
- `nymauthChallengeDigest(transcript, docType)`, `nymauthVerifierInput(verifierId)`, `nymauthNativeVersion()`.

## Demo issuer (`demo-issuer/`, DEMO ONLY)

The ZKP demo wallet issues the adult's `bbs_cd` credential on the phone, to a StrongBox key, under a demo issuer
derived from a seed the app bundles (community-demo's BBS verifier learns a new issuer key on first use). That
code is its own small library, `nymauth-demo-issuer` (UniFFI namespace `uniffi.nymauth_demo_issuer`:
`bbsDemoIssue(issuerSeed, devicePublicKey, birthDate, secretSeed)`, `bbsDemoIssuerParams(issuerSeed)`), so the
SDK's library carries no issuer code. It is never an SDK dependency; the demo app depends on it directly.

Errors are coarse kinds that mirror the SDK's `NymAuthNativeErrorKind` and `NymAuthRefusal`, and carry nothing
the native side computed.

## Build and test

`nym-longfellow` and `nym-bbs` are taken by path from a readdit-demo checkout next to siros-sdk-kotlin
(`../readdit-demo` from the repository root): AltmannPeter/readdit-demo, `main` from commit `50c47ac` (which adds
`Circuits::from_pair` and `Layout::parse`) with commit `0250f90` (branch `feat/bbs-prove-with-signer`, which adds
`nym-bbs`'s `Prover::prove_with`).

```sh
cargo test --release                       # prove with the teen's demo mdoc; this library's verifier and
                                           # community-demo's verifier accept it; refusals; approved build only
                                           # BBS: community-demo's BBS verifier accepts the presentation; the
                                           # signer's errors, bad signatures and refusals sign nothing
(cd demo-issuer && cargo test --release)   # a demo-issued credential, presented with this library, verifies
(cd cross-check && cargo test --release)   # with zk-cred-longfellow next to siros-sdk-kotlin: each verifies the other's proofs
scripts/build-android.sh                   # arm64-v8a and x86_64 .so (PMULL checked), Kotlin bindings, AAR,
                                           # published to ~/.m2 as org.siros:nymauth-native:<version>
scripts/build-android.sh --demo-issuer     # also org.siros:nymauth-demo-issuer:<version>, for the demo app
```

## Notices

- Google's longfellow-zk runtime (Apache-2.0, vendored in community-demo's `native/longfellow/vendor`).
- `nym-longfellow` and the circuits are community-demo's, from the SIROS nym-auth-circuits archive.
- `nym-bbs` is community-demo's; sirosfoundation/bbs-cd-plugins 0.1 is vendored unchanged in its `native/bbs/vendor`
  (research code: not constant-time, not audited).
- This library's own license is to be decided.
