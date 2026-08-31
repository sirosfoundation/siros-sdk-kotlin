# Changelog

All notable changes to the SIROS SDK for Android will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.11.0]

Highlights since v0.10.0 (1 commit). Sample app: versionName 0.11.0, versionCode 11.

### Fixed
- NFC static handover: send the mandatory "Complete List of 128-bit Service
  UUIDs" AD (type `0x07`) in little-endian byte order, sending only the
  single UUID matching the LE-Role-preferred mode - a real reader rejected
  a 2-UUID AD outright and otherwise saw no UUIDs at all in our handover
  message (#147)
- BLE central-client mode: restart the scan window at the moment a real NFC
  tap actually completes handover, instead of trusting a window that
  started when the presentation screen mounted - the first scan attempt
  reliably timed out before a real tap completed (#147)
- BLE central-client/peripheral-server: distinguish a peer's own
  session-termination status from an unexpected data-carrying message once
  the session is already established, replying only in the latter case
  (#147)
- BLE central-client mode: add a grace delay before signaling end-of-transfer
  after the final response chunk - sending it immediately raced a real
  reader's background verification thread (#147)

## [0.10.0]

Highlights since v0.9.0 (1 commit). Sample app: versionName 0.10.0, versionCode 10.

### Fixed
- Register `mdoc-openid4vp://` (ISO 18013-7 Annex B's mdoc-specific OpenID4VP
  scheme) in the manifest's intent-filter and `DeepLinkClassifier` - a link
  using this scheme was silently dropped as `Unknown` before reaching the
  app at all, since Android has no intent-filter to route it through
  (#145)

## [0.9.0]

Highlights since v0.8.0 (16 commits). Sample app: versionName 0.9.0, versionCode 9.

### Added
- DC API/OpenID4VP: run the shared DCQL matching engine alongside the built-in
  matcher, then let it decide which credentials actually qualify (#138, #140)
- Delete button next to Renew on fully-exhausted ("shadow") credential cards -
  previously the only way to remove one was renewing it first
- Wired RICAL reader-trust controls into the in-session Settings tab (#129)

### Fixed
- BLE peripheral-server mode: fixed a permanent-hang bug where a stale session
  from a prior connection attempt silently swallowed every retry with no
  response and no completion callback, leaving the presentation screen stuck
  indefinitely - added a bounded overall timeout and an explicit session-
  termination status instead of silently dropping late messages (#143)
- BLE: both roles now report failure when their own connection attempt never
  completes, instead of hanging forever waiting for the other role (#135, #137)
- `eligibleInstances` (and the credential-list "shadow" display state) now
  also checks signing-key availability, not just consumption count, so a
  credential with a lost key can no longer masquerade as usable (#139)
- A `null` `kid` on a stored credential no longer silently masks a lost key
  binding (#142)
- The default ("softkey") WSCD plugin's private keys now correctly survive an
  app restart - a JSON-shape mismatch at the Rust/Kotlin FFI boundary
  (`UniFFISigner.exportPrivateKeypairs()`) was silently dropping every
  generated key before it ever reached persisted storage, making any
  softkey-issued credential look "shadow" (no available key) after the very
  next cold start
- A property-ordering bug (`fido2RegisteredTransport` read before its own
  declaration during `wallet`'s eager construction) silently degraded FIDO2
  plugin registration to a stateless instance every cold start
- `SessionStore.privateDataJwe` now persists with a blocking, durable write
  instead of `SharedPreferences.apply()`'s async flush, closing a window
  where a hard-kill shortly after credential issuance could lose the
  just-written encrypted key container
- Engine WebSocket: disconnect a prior session before reconnecting, instead of
  leaking a duplicate concurrent client (#141)
- DC API/OpenID4VP x5c trust checks now have a local-anchor fallback path
  (#132), and a decline now returns a real structured OpenID4VP error
  response instead of an opaque exception (#130)
- Fail closed on an explicit trust-evaluation denial rather than falling back
  to local validation (#127)
- CI: trigger the Play Store upload from the tag, not `release: published`
  (#128)

### Changed
- DC API registration now lives in the SDK, on our own matcher (Phase 6, #131)
- Target API 36 (Android 16) (#134)

## [0.8.0]

Highlights since v0.7.0 (12 commits). Sample app: versionName 0.8.0, versionCode 8.

### Added
- `VegaProofSystem`: real Vega ZK mdoc proving, end-to-end tested against a live
  verifier on device (#116)
- `BbsProofSystem`: the blind BBS presentation path (#117), plus the wallet's half
  of blind BBS issuance (#123)
- Our own DC API credential matcher, Phase 1, behind the `-PcustomDcMatcher` build
  flag (#118)
- VICAL-based issuer-trust evaluation for mdoc presentation (#114)
- Sample app: a "Computing proof…" indicator during Vega ZK proof generation, so the
  multi-second prove step is no longer a silent freeze (#124)
- `prepProve`/`prove` timing logs for ZK proof generation (#119)

### Changed
- `ZkProofSystem` generalized beyond mdoc-only, so non-mdoc credential formats can
  plug into the same proving interface (#115)
- `zk-cred-vega` bumped to 0.0.5 (r12 circuit revision) (#119, #125)
- Sample app requests `largeHeap`, which the Vega prover-key decompression needs (#120)

### Fixed
- Circuit decompression no longer double-buffers the decompressed artifact, roughly
  halving peak memory for both Vega and Longfellow (#122)
- AndroidSVG full-bleed `<image>` dark-band mis-render in credential logo previews (#121)
- BLE session-establishment callback race during proximity presentation (#114)
- Blank logo square for SVG credential logos (#114)

## [0.1.0]

### Added
- Initial SDK with 7 modules: transport, auth, keystore, flow, credentials, wallet, passkey-provider
- Sample app demonstrating registration, login, issuance, and presentation flows
- CI pipeline with build, test, and coverage gate (25%)
- CONTRIBUTING.md and ARCHITECTURE.md

### Fixed
- WmpSessionException and WmpTimeoutException now extend SirosException
- Redacted credential IDs and session UUIDs from log output

---

Releases v0.2.0 through v0.7.0 predate this changelog being kept up to date; their
notes are auto-generated on the corresponding
[GitHub release](https://github.com/sirosfoundation/siros-sdk-kotlin/releases).
