# Standalone mdoc verification

`sdk:verifier` adds ISO/IEC 18013-5 reader capabilities without changing the wallet's holder APIs. It does not construct `SirosWallet`, unlock a credential container, or require an account.

## Trust boundary

The verifier-core UniFFI `Reader` owns the SessionTranscript, DeviceRequest and optional ReaderAuth, session encryption, DeviceResponse verification, and request-policy enforcement. The SDK owns engagement parsing and transport. go-trust alone decides whether each authenticated issuer is authorized.

`MdocReaderSession.openResponse` returns claims only after:

1. the complete SessionData message decrypts and verifies;
2. the response satisfies the retained document, namespace, and element request;
3. every document's exact AuthZEN request receives an explicit permit.

Denial, a malformed PDP response, an HTTP failure, or an unavailable PDP yields no accepted claims. There is no local trust fallback.

## Account-free PDP configuration

`HttpAuthZenPdp` posts to a complete evaluation URL with `X-Tenant-ID`. It never adds `Authorization` or `Cookie` headers and has no dependency on `sdk:auth`:

```kotlin
val pdp = HttpAuthZenPdp(
    endpoint = "http://10.0.2.2:9095/v1/evaluate",
    tenantId = "default",
)
val verifier = MdocProximityVerifier(
    pdp = pdp,
    mdocIssuerRole = "pid-provider",
)
```

An emulator can use `10.0.2.2` for a go-trust instance listening on the host. A physical device needs the host's reachable address. Production applications may supply their own `AuthZenPdp` implementation with deployment-appropriate authentication; the trust decision must still come from go-trust.

## Starting a session

Parse the holder's `mdoc:` QR value without re-encoding it, then start one reader session:

```kotlin
val engagement = MdocQrEngagementParser.parse(scannedValue)
val request = listOf(
    MdocDocumentRequest(
        docType = "org.iso.18013.5.1.mDL",
        namespaces = listOf(
            MdocRequestedNamespace(
                namespace = "org.iso.18013.5.1",
                elements = listOf(
                    MdocRequestedElement("given_name"),
                    MdocRequestedElement("family_name"),
                ),
            ),
        ),
    ),
)
val session = verifier.start(engagement, request)
```

Use an elected `MdocMessageTransport` to send `session.establishmentMessage()` and receive one complete SessionData message. BLE chunks and APDUs never cross the transport boundary. Call `session.openResponse` and release attributes only for `MdocReaderInbound.Verified`. Close the session and transport when finished.

ReaderAuth uses a dedicated P-256 verifier identity key and leaf-first DER certificate chain. Its signer receives the exact COSE input and returns raw `r || s`; it must not be a holder credential key, an issuer key, or a compact JWS.

## Native dependency

The SDK consumes `org.siros:siros-verifier-core-ffi`. The AAR contains the native libraries and Kotlin bindings generated from the same core revision. For local development, build it with `ffi/scripts/android-aar.sh` in verifier-core and publish the AAR and a minimal POM into a Maven directory, then run Gradle with:

```sh
-PsirosNativeRepo=/path/to/maven-directory
```

Release AARs never enable verifier-core's `vector-tests` feature.

## Validation boundary

JVM tests cover engagement parsing, request/session orchestration, exact AuthZEN forwarding, fail-closed decisions, and transport state machines. They do not prove native Android ABI loading or radio interoperability. Run the native/instrumented tests and physical-device BLE/NFC matrix before a release.
