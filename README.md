# SIROS SDK for Android (Kotlin)

[![CI](https://github.com/sirosfoundation/siros-sdk-kotlin/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/siros-sdk-kotlin/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/sirosfoundation/siros-sdk-kotlin/graph/badge.svg)](https://codecov.io/gh/sirosfoundation/siros-sdk-kotlin)
[![Kotlin 2.1+](https://img.shields.io/badge/Kotlin-2.1+-purple.svg)](https://kotlinlang.org)
[![Android SDK 28+](https://img.shields.io/badge/Android-SDK%2028%2B-green.svg)](https://developer.android.com)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sirosfoundation/siros-sdk-kotlin/badge)](https://scorecard.dev/viewer/?uri=github.com/sirosfoundation/siros-sdk-kotlin)
[![License](https://img.shields.io/badge/license-BSD--2--Clause-blue.svg)](LICENSE)

Native Android SDK for integrating SIROS ID wallet infrastructure into existing apps.

## Modules

| Module | Description |
|--------|-------------|
| `sdk:transport` | Transport-independent WMP client (WebSocket, HTTPS+SSE) |
| `sdk:auth` | WebAuthn/passkey authentication with PRF key derivation |
| `sdk:keystore` | JWE-encrypted keystore for credential signing keys |
| `sdk:flow` | OID4VCI/OID4VP flow orchestration over WMP |
| `sdk:credentials` | Credential storage and metadata |
| `sdk:passkey-provider` | Android Credential Provider Service for passkeys |
| `sample-app` | Minimal example wallet app |

## Architecture

```
┌─────────────────────────────────────────┐
│            Your Native App              │
│  ┌───────────────────────────────────┐  │
│  │          SIROS SDK                │  │
│  │  ┌─────────┐  ┌───────────────┐  │  │
│  │  │  Flow   │  │  Credentials  │  │  │
│  │  │ Client  │  │    Store      │  │  │
│  │  └────┬────┘  └───────────────┘  │  │
│  │       │                          │  │
│  │  ┌────┴────┐  ┌───────────────┐  │  │
│  │  │   WMP   │  │   Keystore    │  │  │
│  │  │ Session │  │  (JWE/PRF)    │  │  │
│  │  └────┬────┘  └───────────────┘  │  │
│  │       │                          │  │
│  │  ┌────┴────────────────────────┐ │  │
│  │  │    Transport (WebSocket)    │ │  │
│  │  └─────────────────────────────┘ │  │
│  │                                  │  │
│  │  ┌─────────────────────────────┐ │  │
│  │  │  Auth (Credential Manager)  │ │  │
│  │  └─────────────────────────────┘ │  │
│  │                                  │  │
│  │  ┌─────────────────────────────┐ │  │
│  │  │  Passkey Provider Service   │ │  │
│  │  └─────────────────────────────┘ │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

## Key Features

### WMP (Wallet Messaging Protocol) Support

The SDK includes a full WMP implementation as an alternative to the legacy WebSocket engine protocol:

- **`WmpPeer`** — JSON-RPC 2.0 dispatch with profile-based routing
- **`OpenID4xProfile`** — OID4VCI/OID4VP flow handling (sign, match, trust evaluation)
- **`WmpHttpSseTransport`** — HTTP+SSE transport for firewall-restricted environments
- **`WmpWebSocketTransport`** — WebSocket transport with `wmp.v1` subprotocol

Enable via `WalletConfig(useWmpProtocol = true)`. Requires backend with WMP endpoint.

### Engine URL Auto-Discovery

The SDK auto-discovers the engine WebSocket URL from `/.well-known/wallet-configuration`:

```kotlin
// Resolution order: explicit engineUrl > discovery > backendUrl
val config = WalletConfig(
    backendUrl = "https://wallet.example.com",
    // engineUrl = null → auto-discovered
)
```

### Pre-Login Settings (Sample App)

Debug builds expose a gear icon on the login screen for configuring:
- Backend URL, Tenant ID, Engine URL
- WMP protocol toggle

Controlled by `SHOW_PRE_LOGIN_SETTINGS` build config (true in debug, false in release).

## Adding the SDK to an app

Every module is published as `org.siros:siros-sdk-<module>` with a BOM, to
GitHub Packages, on each release tag. GitHub Packages requires an
authenticated token even to read public packages, so a consumer configures the
SDK's repository and the repositories of its native dependencies with a
personal access token that has `read:packages`:

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        listOf(
            "siros-sdk-kotlin",     // the SDK itself
            "siros-wscd-manager",   // WSCD key management (UniFFI)
            "siros-dc-matcher",     // DC API matcher + DCQL engine
            "zk-cred-longfellow", "zk-cred-vega", "zk-cred-bbs", // ZK proof systems
        ).forEach { repo ->
            maven {
                url = uri("https://maven.pkg.github.com/sirosfoundation/$repo")
                credentials {
                    username = providers.gradleProperty("gpr.user").orNull
                    password = providers.gradleProperty("gpr.key").orNull
                }
            }
        }
    }
}
```

```kotlin
// app/build.gradle.kts
dependencies {
    implementation(platform("org.siros:siros-sdk-bom:0.13.0"))
    implementation("org.siros:siros-sdk-wallet")          // the facade; pulls in every other module
    // implementation("org.siros:siros-sdk-passkey-provider") // only if the app is also a passkey provider (API 34+)
}
```

### Supported Android versions

`minSdk` **28** (Android 9) is the SDK's floor - BiometricPrompt and
hardware-backed key attestation start there - and `compileSdk` must be 36 or
higher. Everything above 28 is gated at runtime, never assumed:

| feature | needs | otherwise |
|---|---|---|
| passkey login, credentials, presentation | 28 + Google Play Services | - |
| Digital Credentials API | 28 + a Play Services build with Credential Manager (in practice Android 14+) | picker never shows this wallet |
| `siros-sdk-passkey-provider` (this app as a passkey *provider*) | **34** (`CredentialProviderService`) | module is inert |
| USB CTAP2 security keys | 33 for the exported-receiver flags; works on 28+ | - |
| user-auth-bound keys (`setUserAuthenticationParameters`) | 30 | falls back to the pre-30 API |

The DC API entry
Activity and the NFC HCE Service are declared by the SDK's own manifests and
merged into the app; the app keeps `WalletSessionHolder` pointed at its
unlocked wallet and calls `SirosCredentialRegistry.refresh` when it has
credentials (see the sample app's `WalletViewModel`). What the app must still
declare itself: the deep-link schemes it handles (`openid-credential-offer`,
`openid4vp`, `mdoc-openid4vp`, `haip`, `haip-vp`, `haip-vci`) plus its own
authorization-callback scheme, the permissions it uses (camera, Bluetooth,
NFC), and its passkey relying-party assets on the backend side.

To build against an unreleased checkout, `./gradlew publishToMavenLocal
-PsdkVersion=<anything>` installs the same artifacts into `~/.m2`, resolvable
with `mavenLocal()`.

## Quick Start

```kotlin
// 1. Create transport and session
val transport = WmpWebSocketTransport("wss://wallet.example.com/wmp")
val session = WmpSession(transport)

// 2. Authenticate and create session
session.create(authToken = accessToken)

// 3. Set up flow client
val flowClient = FlowClient(session, keystore)
flowClient.start()

// 4. Observe flow events
flowClient.events().collect { event ->
    when (event) {
        is FlowEvent.Complete -> handleCredentialReceived(event.result)
        is FlowEvent.Progress -> updateUI(event.step)
        is FlowEvent.SignRequest -> { /* auto-handled or manual */ }
        is FlowEvent.MatchRequest -> respondToMatch(event)
        is FlowEvent.Error -> showError(event.message)
    }
}

// 5. Start credential issuance
flowClient.startIssuance(OID4VCIFlowParams(credentialOfferUri = uri))
```

## Building

```bash
./gradlew assemble
```

## Testing

```bash
./gradlew test
```

## Requirements

- Android SDK 28+ (Android 9.0)
- JDK 17
- Kotlin 2.1+

## Documentation

API documentation is generated using [Dokka](https://kotl.in/dokka).

```bash
# Generate HTML documentation
./gradlew dokkaGenerate
```

## License

BSD 2-Clause — see [LICENSE](LICENSE).
