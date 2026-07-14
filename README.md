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
