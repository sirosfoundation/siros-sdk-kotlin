# SIROS SDK for Android (Kotlin)

[![CI](https://github.com/sirosfoundation/siros-sdk-kotlin/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/siros-sdk-kotlin/actions/workflows/ci.yml)
[![Kotlin 2.1+](https://img.shields.io/badge/Kotlin-2.1+-purple.svg)](https://kotlinlang.org)
[![Android SDK 28+](https://img.shields.io/badge/Android-SDK%2028%2B-green.svg)](https://developer.android.com)
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

## License

BSD 2-Clause — see [LICENSE](LICENSE).
