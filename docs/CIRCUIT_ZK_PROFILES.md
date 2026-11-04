# Circuit-ZK profiles

Circuit-ZK composition is profile-driven. **nym_auth is one registered profile, not the generic
circuit-ZK engine.** The catalog dispatcher and presenter use the same registration shape for nym_auth,
the legacy mdoc selective-disclosure profile, and additional profiles.

## What is already registered

`CatalogCircuitZkProver.standardProfiles` returns these registrations, followed by any additional
profiles supplied by the host:

1. `NymAuthCircuitZkAdapter.profile`: the nym_auth pseudonym and declared nym predicates, backed by
   `NymAuthNativeProver` (currently Google Longfellow, ISRG Longfellow, or Vega implementations).
2. `LegacyZkCircuitZkAdapter.profile`: generic mdoc selective disclosure through the existing
   Longfellow and Vega `ZkProofSystem` implementations.

`org.siros:nymauth-native` is the native implementation of the first profile. Its fixed nym_auth
statement, approved circuit, seed handling, and pseudonym layout are intentionally nym-specific. Do not
use it as the definition of circuit-ZK or make every other credential imitate it.

## Register another profile through configuration

A host does not change SDK source code. It supplies a `CircuitZkProfile` in `WalletConfig`:

```kotlin
val config = WalletConfig(
    backendUrl = "https://wallet.example.com",
    circuitZkProfiles = listOf(
        CircuitZkProfile(
            adapter = ExampleProfileAdapter(),
            handlers = listOf(ExampleFunctionHandler()),
        ),
    ),
)
```

`ExampleProfileAdapter` implements `CircuitZkSystemAdapter` and declares the exact catalog
`(system, systemVersion)` keys it proves. Its `prove` method returns a `CircuitZkProveOutput` only after
validating the descriptor, request, credential, artifact, and native proof. `ExampleFunctionHandler`
implements `CircuitZkProfileFunctionHandler` for the function's witness requirements, credential checks,
and verifier identity. The optional subinterface leaves existing `CircuitZkFunctionHandler` binaries
untouched; absence of its metadata is a refusal. A profile handler must also:

- return non-empty, structured `ConsentItem`s from `consentItems`; the default `null` refuses before
  consent or proving;
- declare `CircuitZkResultKind.PREDICATE_TRUE` from `resultKind` when its result is a satisfied
  predicate. False and non-boolean results remain invalid. The default `null` fails response validation;
- be accepted by the configured `CircuitZkRequestValidator`. Registration alone never makes a function
  valid in the request policy.

This is configuration, not a new built-in branch. The SDK appends these registrations to the built-in
profiles. `WalletConfig` rejects duplicate catalog keys or function IDs, including collisions with the
built-ins and configured predicates, at construction rather than silently replacing a profile or failing
later in a presentation.

## Longfellow, Vega, and future proof systems

A credential profile and a proof system are different extension points:

- `CircuitZkSystemRegistry` routes a catalog profile to its adapter.
- `ZkProofSystemRegistry` selects a cryptographic implementation such as Longfellow or Vega.
- `ZkMdocPresentation.standard(extra = ...)` adds another proof-system implementation.
- `LongfellowZkProofSystem` and `VegaProofSystem` have overloads accepting additional mdoc credential
  types while retaining their original constructors and mDL/PID defaults.

For wallet use, supply the configured implementations through `ZkMdocPresentation.standard(extra = ...)`,
build `CatalogCircuitZkProver.standard` with that presentation, and set `WalletConfig.circuitZkProver`.
The wallet's default presentation retains the mDL/PID defaults; registering a `CircuitZkProfile` alone
does not change its proof-system credential types.

A future proof system must implement the real prover and verifier contract. It is not enabled by a name
alone. Profile and proof-system IDs used on the wire remain unchanged; compatibility identifiers such as
`longfellow-nymauth`, `vega-nymauth`, `longfellow-libzk-v1`, and `vega-mc-p256-v1` are not renamed.

## Requirements before a profile can answer

Registration never broadens a request by itself. A profile is eligible only when all of these agree:

1. the verifier offered the circuit and proof system;
2. the active catalog publishes an exact matching descriptor;
3. the profile adapter claims the descriptor's `(system, systemVersion)` and admits the plan;
4. the function handlers, validator, and consent model understand every function;
5. the credential's doctype and namespace layout match the circuit;
6. the native circuit and proof system support the request.

Unknown function IDs still fail before consent. Unknown preference IDs select nothing unless all of the
above accept them. There is no fallback to nym_auth, another profile, or the fake prover.

## mdoc namespaces

A one-element predicate path reads an element in the doctype namespace (the nym_auth layout). A
two-element path is `[namespace, element]`, for credentials such as mDL whose namespace differs from
their doctype. Duplicate elements and decoy namespaces are never used as a fallback.

## Testing a new profile

At minimum, cover:

- nym_auth and the new profile registered together;
- real or recorded proof generation through `CircuitZkPresenter` and `CatalogCircuitZkProver`;
- no nym-only `secret_seed`, `NymPseudonym`, or `namespace == docType` assumption;
- wrong descriptors, doctypes, namespaces, artifacts, and duplicate claims refused before signing;
- independent verification by the native verifier, plus the existing nym_auth golden tests unchanged.
