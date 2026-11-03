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

    /**
     * Register the FIDO2 plugin restored from a previously
     * [exportFido2State]-exported blob (credential handles + public keys,
     * no private material) - use instead of [registerFido2Plugin] when
     * restoring a wallet whose keys were enrolled in an earlier process,
     * so those keys stay addressable. Without this, an enrolled key's
     * `kid` still exists in credential/session metadata after an app
     * restart, but the plugin has no record of the credential handle
     * needed to sign with it again.
     */
    fun registerFido2PluginWithState(transport: Ctap2TransportProvider, state: ByteArray)

    /**
     * Export the FIDO2 plugin's current key state, to persist and later
     * restore via [registerFido2PluginWithState]. Throws if the fido2
     * plugin isn't registered.
     */
    fun exportFido2State(): ByteArray

    /**
     * Read-only description of the FIDO2 authenticator behind the registered `fido2` plugin: what it is, whether it has a PIN,
     * the minimum PIN length, the remaining PIN attempts and whether it can be enrolled. Never asks for or sends a PIN, never
     * changes the key, and uses the registered transport as it is (an already-open USB connection is reused; an NFC key
     * must be held to the phone for it). Throws if the fido2 plugin is not registered.
     */
    suspend fun describeFido2Authenticator(): Fido2AuthenticatorInfo

    /** Register the R2PS remote HSM plugin. */
    fun registerR2psPlugin(config: R2psConfig, transport: R2psTransportProvider)

    /**
     * Register the Android Keystore plugin: EC P-256 keys backed by this
     * device's own TEE or StrongBox, generated with Android Key Attestation.
     * [backend] defaults to the real [SystemAndroidKeyStore]; [authenticator]
     * is asked for per-use authentication on a key that requires it (none do
     * today - see [AndroidKeystoreWscdCallbackBridge]'s doc comment).
     *
     * One registered instance serves BOTH Wallet Instance Attestation's
     * fixed hardware root (always reached via
     * [generateAndroidKeystoreKeyWithChallenge], never [generateKeyForLevel])
     * and Key Attestation's pluggable path (via [generateKeyForLevel], when
     * `"android-keystore"` is one of its candidates) - mirrors how a single
     * registered `fido2` plugin already serves both a specific credential's
     * KA and (if ever used that way) other purposes. Register this at most
     * once per process, like every other plugin.
     */
    fun registerAndroidKeystorePlugin(
        backend: AndroidKeyStoreBackend = SystemAndroidKeyStore(),
        authenticator: UserAuthenticator? = null,
    )

    /**
     * Register the Android Keystore plugin restored from a previously
     * [exportAndroidKeystoreState]-exported blob (kid-to-alias mapping,
     * attestation chains, confirmed security levels - no private key
     * material, that never leaves the Keystore) - use instead of
     * [registerAndroidKeystorePlugin] when restoring a wallet whose keys
     * were generated in an earlier process, so those keys stay addressable.
     * Without this, a generated key's `kid` still exists in
     * credential/session metadata after an app restart, but the plugin has
     * no record of the alias needed to sign with it again - mirrors
     * [registerFido2PluginWithState]'s doc comment exactly.
     */
    fun registerAndroidKeystorePluginWithState(
        state: ByteArray,
        backend: AndroidKeyStoreBackend = SystemAndroidKeyStore(),
        authenticator: UserAuthenticator? = null,
    )

    /**
     * Export the Android Keystore plugin's current key state, to persist
     * and later restore via [registerAndroidKeystorePluginWithState].
     * Throws if the android-keystore plugin isn't registered.
     */
    fun exportAndroidKeystoreState(): ByteArray

    /**
     * Generate a key with the Android Keystore plugin under a
     * CALLER-SUPPLIED Android Key Attestation challenge, instead of the
     * random one [generateKeyForLevel]/the plain `Signer.generateKey` path
     * would use.
     *
     * **This is what Wallet Instance Attestation's instance-key
     * provisioning must use** - per the wallet module's
     * `InstanceKeyEvidence.challengeHash`, WIA's Android Key Attestation
     * challenge is `SHA-256("siros-instance-key-v1" || C)` for a
     * server-issued `C`; compute that and pass it as
     * [attestationChallenge]. A random challenge cannot satisfy that fixed
     * formula, making the resulting attestation unverifiable against the
     * backend's own check.
     *
     * @return the new key's id (a JWK thumbprint, like every other
     *   WSCD-generated key).
     */
    suspend fun generateAndroidKeystoreKeyWithChallenge(attestationChallenge: ByteArray): String

    /**
     * Generate a key that actually meets [requiredLevel], trying each of
     * [candidatePluginIds] in order and confirming the real, objective
     * outcome - never trusting a plugin's self-reported capability - before
     * committing to it. See `WscdManager::generate_key_for_level`'s Rust
     * doc comment (siros-wscd-manager) for the full generate-then-confirm-
     * then-retry-the-next-candidate contract.
     *
     * [requiredLevel] is wscd-manager's own OBJECTIVE tier
     * ([WscdCertificationLevel]: `unattested`/`attested_shared_environment`/
     * `attested_dedicated_hardware` - purely structural facts about the
     * generation response, never a certification-SCHEME judgment), deliberately NOT the
     * ISO-18045 vocabulary ([WscdPluginCapabilities]'s
     * `iso_18045_basic`/`moderate`/`high`): that mapping, and the ordered
     * candidate list for a given ISO-18045 requirement
     * ([WscdSelectionPolicy.resolveCandidates]), are owned entirely by this
     * SDK, as deployment-configurable data - never hardcoded in
     * wscd-manager, which has no business deciding what counts as
     * "iso_18045_high" for any given deployment's own compliance posture.
     *
     * @return the new key's id AND which candidate actually won - the
     *   caller needs the plugin id to call
     *   [WscdSelectionPolicy.confirmAutoPickWinner] with the VERIFIED
     *   winner (which may be any candidate in the list, not necessarily
     *   the first), not just a bare kid with no way to tell which plugin
     *   it ended up bound to.
     */
    suspend fun generateKeyForLevel(requiredLevel: WscdCertificationLevel, candidatePluginIds: List<String>): GeneratedKeyWithPlugin
}

/**
 * The result of [WscdManager.generateKeyForLevel]: the new key's id, and
 * which of the offered candidates actually won (generated the key AND had
 * its result confirmed to meet the required level) - see that method's doc
 * comment for why both are needed.
 */
data class GeneratedKeyWithPlugin(val keyId: String, val pluginId: String)

/**
 * wscd-manager's own objective, purely STRUCTURAL certification-level
 * vocabulary - mirrors `CertificationLevel`/`FfiCertificationLevel`
 * (siros-wscd-manager) exactly: three tiers based only on what is
 * structurally present in/alongside a key's attestation artifact
 * (`UNATTESTED`: no artifact, or a structurally incomplete one;
 * `ATTESTED_SHARED_ENVIRONMENT`: a complete artifact claiming a
 * shared-silicon execution environment, e.g. a TEE; `ATTESTED_DEDICATED_HARDWARE`:
 * a complete artifact claiming a physically separate secure element) -
 * never a certification-SCHEME judgment (no "self-assessed"/"third-party
 * evaluated"/"national scheme" concept exists here, by design: wscd-manager
 * has no way to know who evaluated a given piece of hardware or how).
 * Deliberately NOT the ISO-18045 vocabulary ([WscdPluginCapabilities]'s
 * `iso_18045_basic`/`moderate`/`high`) - see
 * [WscdManager.generateKeyForLevel]'s doc comment for why the two must stay
 * distinct.
 */
enum class WscdCertificationLevel { UNATTESTED, ATTESTED_SHARED_ENVIRONMENT, ATTESTED_DEDICATED_HARDWARE }

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
