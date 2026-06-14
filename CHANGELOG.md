# Changelog

All notable changes to the SIROS SDK for Android will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial SDK with 7 modules: transport, auth, keystore, flow, credentials, wallet, passkey-provider
- Sample app demonstrating registration, login, issuance, and presentation flows
- CI pipeline with build, test, and coverage gate (25%)
- CONTRIBUTING.md and ARCHITECTURE.md

### Fixed
- WmpSessionException and WmpTimeoutException now extend SirosException
- Redacted credential IDs and session UUIDs from log output
