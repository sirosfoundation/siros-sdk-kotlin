package org.siros.sdk.keystore

/**
 * Hardware-key-specific WSCD operations not part of the generic [Signer]/
 * [KeystoreManager] surface: additional-plugin registration (FIDO2
 * rawSign, R2PS remote HSM) and hardware-key lifecycle
 * (enroll/rotate/destroy).
 *
 * Only a WSCD-backed keystore (one wrapping a [UniFFISigner]) supports
 * this - obtain it via `SirosWallet.wscdManager`, which is `null` for the
 * default JWE-encrypted keystore or any other [KeystoreManager] that
 * isn't WSCD-backed.
 */
interface WscdManager : SignerLifecycleManager {
    /**
     * Register the FIDO2 previewSign (rawSign) plugin for hardware
     * authenticators (e.g. a YubiKey). All CTAP2 CBOR request-building/
     * response-parsing happens in Rust - [transport] only needs to move
     * raw command/response bytes over USB/BLE/NFC.
     */
    fun registerFido2Plugin(transport: Ctap2TransportProvider)

    /** Register the R2PS remote HSM plugin. */
    fun registerR2psPlugin(config: R2psConfig, transport: R2psTransportProvider)
}

/**
 * R2PS server connection parameters.
 *
 * @param clientKeyPem PEM-encoded P-256 client private key for the R2PS
 *   message envelope's JWS signing. Required for every session regardless
 *   of [authMode] - this identifies the client's own message channel, not
 *   the user-level authentication factor.
 * @param serverPublicKeyPem PEM-encoded P-256 server public key for JWE
 *   envelope encryption. Required for every session regardless of
 *   [authMode].
 */
data class R2psConfig(
    val serverUrl: String,
    val clientId: String,
    val context: String,
    val clientKeyPem: String,
    val serverPublicKeyPem: String,
    val authMode: R2psAuthMode,
)

/**
 * R2PS user-authentication mode. OPAQUE (RFC 9807) PAKE crypto is handled
 * entirely in Rust (`r2ps-client`) - no PAKE client is needed here.
 */
sealed class R2psAuthMode {
    /** Password-based OPAQUE authentication. */
    data object Opaque : R2psAuthMode()

    /** WebAuthn/FIDO2-based authentication (SCAL2-compliant SAD binding). */
    data class WebAuthn(
        val rpId: String,
        val allowedCredentialIds: List<String>,
    ) : R2psAuthMode()
}

/** HTTP transport for R2PS protocol messages. */
fun interface R2psTransportProvider {
    suspend fun send(body: ByteArray): ByteArray
}
