# Changelog

All notable changes to the SIROS SDK for Android will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
