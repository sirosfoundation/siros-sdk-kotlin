# Bridge capability vocabulary

`bridge-capabilities.json` is the single source of truth for the capability
descriptor a SIROS web-view wrapper app advertises to the page it hosts. It is
the SDK's half of the native capability bridge: the wrapper (Kotlin or Swift)
*builds* a descriptor from what it can actually do, the page (TypeScript)
*reads* it and picks native or in-page paths accordingly. One versioned
descriptor replaces probing for functions, classes on the root element and
per-feature globals.

The shape follows the Wallet Messaging Protocol's capability map
(`WmpProfile.capabilities` / `WmpRegistry.allCapabilities()` in
`sdk/transport`): a map from capability id to that capability's parameters.
Present means offered; absent means not offered. A future native WMP engine is
therefore one more id (`engine`) rather than a new detection mechanism.

## Generated code

`tools/gen_bridge_capabilities.py` turns the spec into three files that are
committed, so no consumer runs the generator:

| Target     | File                                                                   | Used by |
|------------|------------------------------------------------------------------------|---------|
| Kotlin     | `sdk/transport/src/main/kotlin/org/siros/sdk/transport/bridge/BridgeCapabilities.kt` | the Android wrapper, via `org.siros:siros-sdk-transport` |
| Swift      | `Sources/SirosTransport/BridgeCapabilities.swift` in siros-sdk-swift   | the iOS wrapper |
| TypeScript | `generated/bridge-capabilities.ts`, attached to each release as `bridge-capabilities-<version>.ts` | the frontend's bridge contract package |

CI fails when the spec changed without regenerating. The Swift SDK carries a
copy of the spec and its own check that the copy matches this repository's.

## Descriptor

```json
{
  "bridge": { "version": 1 },
  "vocabulary": 1,
  "platform": "android",
  "host": { "name": "org.siros.wwwallet", "version": "3.1.0", "sdk_version": "0.15.0" },
  "capabilities": {
    "webauthn": { "prf": true, "security_key_transports": ["nfc", "usb"] },
    "zk": { "systems": ["longfellow-libzk-v1"], "circuit_cache": true },
    "proximity.session": { "transports": ["ble_peripheral"], "nfc_static_handover": true },
    "oidc": {}
  }
}
```

- `bridge.version` is the schema of this document; `vocabulary` is the
  version of the id list the host was generated against, so a page can tell
  an unknown id from an older host.
- A capability with no parameters is an empty object. Unset parameters are
  omitted, never `null`.

Building one in Kotlin:

```kotlin
BridgeDescriptorBuilder(platform = "android", host = BridgeHost(name = appId, version = appVersion, sdkVersion = BuildConfig.SDK_VERSION))
    .zk(ZkCapability(systems = wallet.zkPresentation.systemIds(), circuitCache = true))
    .proximitySession(ProximitySessionCapability(transports = listOf("ble_peripheral"), nfcStaticHandover = true))
    .webauthn(WebauthnCapability(prf = true))
    .encode()   // the JSON the page receives
```

## Evolving the vocabulary

- Ids are stable once published. Never rename; retire with `deprecated` and
  keep the entry, so old hosts and new pages still agree on what the id
  meant.
- Adding an id or an optional parameter is backwards compatible and bumps
  `vocabulary_version`. Pages treat unknown ids as not offered.
- Removing an id, or changing a parameter's type, is a `bridge.version` bump
  and a coordinated change with the frontend's contract package.
- `stage` records where each capability sits in the bridge plan (`reached`,
  `A`..`E`, `never`); it is documentation, not wire format.
