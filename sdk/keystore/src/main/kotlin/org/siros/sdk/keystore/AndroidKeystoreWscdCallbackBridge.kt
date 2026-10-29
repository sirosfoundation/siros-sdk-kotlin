// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import com.nimbusds.jose.jwk.JWK
import kotlinx.coroutines.runBlocking
import timber.log.Timber
import uniffi.siros_wscd_manager.FfiAndroidKeystoreCallback
import uniffi.siros_wscd_manager.FfiAndroidKeystoreSecurityLevel
import uniffi.siros_wscd_manager.FfiWscdException

/**
 * Bridges [AndroidKeyStoreBackend] - already fully implemented and tested
 * (see [SystemAndroidKeyStore], [AndroidKeystoreSigner]) - to the
 * [FfiAndroidKeystoreCallback] UniFFI callback interface siros-wscd-manager's
 * `AndroidKeystorePlugin` drives. This is a thin adapter: every method here
 * is a direct 1:1 forward to the corresponding [AndroidKeyStoreBackend] call
 * (or, for [sign], the same `newSignature`/authenticate/finish sequence
 * [AndroidKeystoreSigner.sign] already performs) - no new low-level Keystore
 * logic is added here. See [AndroidKeystoreCallback]'s Rust-side doc
 * comment (siros-wscd-manager's `callbacks.rs`) for the full contract this
 * implements, including why [sign] collapses `newSignature`/authenticate/
 * `finish` into one call rather than exposing a stateful `Signature` across
 * UniFFI (a `java.security.Signature`/`CryptoObject` cannot cross it).
 *
 * Every method is invoked from Rust's own background FFI thread pool, never
 * the Android main thread - same as [Ctap2TransportBridge] - so a blocking
 * [AndroidKeyStoreBackend] call (StrongBox key generation can take seconds)
 * or a blocking [runBlocking] (for [sign]'s suspend [UserAuthenticator] call)
 * is safe here.
 *
 * @param backend The platform seam this plugin's generation/signing/deletion
 *   ultimately runs against.
 * @param authenticator Asks the user to authenticate for a key that requires
 *   it, exactly as [AndroidKeystoreSigner] uses it - `null` if the host app
 *   never registers a key requiring per-use authentication through this
 *   path (today: never - see [AndroidKeystoreSigner.sign]'s doc comment on
 *   this plugin's generate paths never requesting user-authentication
 *   methods yet).
 */
class AndroidKeystoreWscdCallbackBridge @JvmOverloads constructor(
    private val backend: AndroidKeyStoreBackend = SystemAndroidKeyStore(),
    private val authenticator: UserAuthenticator? = null,
) : FfiAndroidKeystoreCallback {

    override fun generate(
        alias: String,
        attestationChallenge: ByteArray?,
        strongBox: Boolean,
        userAuthenticationMethods: List<String>,
        unlockedDeviceRequired: Boolean,
    ): FfiAndroidKeystoreSecurityLevel {
        // An unrecognized name is rejected, not dropped: silently generating
        // with fewer methods than requested can turn "requires biometric or
        // device credential" into "requires nothing" (an empty set means no
        // user-authentication requirement at all to the Keystore) the moment
        // the only requested method here is one this bridge does not
        // recognize - an unenforceable policy must never silently succeed as
        // an unauthenticated key.
        val methods = userAuthenticationMethods.map {
            it.toAuthenticationMethodOrNull()
                ?: throw FfiWscdException.Plugin("Unsupported Android Keystore authentication method requested: '$it'")
        }.toSet()
        return wrapPlatformExceptions("generate $alias") {
            try {
                backend.generate(alias, attestationChallenge, strongBox, methods, unlockedDeviceRequired).toFfi()
            } catch (e: AndroidKeyStoreBackend.StrongBoxUnavailable) {
                throw FfiWscdException.StrongBoxUnavailable("StrongBox is unavailable on this device")
            }
        }
    }

    override fun certificateChain(alias: String): List<ByteArray> =
        wrapPlatformExceptions("certificateChain $alias") { backend.certificateChain(alias) }

    /**
     * Includes the RFC 7638 JWK thumbprint as `kid`, computed the same way
     * [KeypairIdentity]'s own thumbprint matching does (`nimbus-jose-jwt`'s
     * [JWK.computeThumbprint]) - this MUST equal the key id
     * `AndroidKeystorePlugin::finish_generate_key` (siros-wscd-manager)
     * independently derives via its own `jwk_thumbprint`, which reads only
     * the canonical `crv`/`kty`/`x`/`y` members and ignores any `kid`
     * already present, so embedding the matching thumbprint here is
     * self-consistent, not circular. Without it, `SirosWallet
     * .extractProofKeyId` cannot recover which key a proof was made with in
     * a multi-key wallet - see [EcdsaSignatures.publicJwk]'s doc comment.
     */
    override fun publicKeyJwk(alias: String): String = wrapPlatformExceptions("publicKeyJwk $alias") {
        val key = backend.publicKey(alias)
        val kid = JWK.parse(EcdsaSignatures.publicJwk(key)).computeThumbprint().toString()
        EcdsaSignatures.publicJwk(key, kid)
    }

    override fun securityLevel(alias: String): FfiAndroidKeystoreSecurityLevel =
        wrapPlatformExceptions("securityLevel $alias") { backend.securityLevel(alias).toFfi() }

    override fun userAuthenticationMethods(alias: String): List<String> =
        wrapPlatformExceptions("userAuthenticationMethods $alias") {
            backend.userAuthenticationMethods(alias).map { it.toWireName() }
        }

    /**
     * Mirrors [AndroidKeystoreSigner.sign]/its private `finish` exactly: a
     * [java.security.Signature]/`CryptoObject` cannot cross UniFFI, so the
     * whole per-use-authentication dance happens here, host-side, in one
     * call - see this class's own doc comment and
     * [AndroidKeystoreCallback]'s Rust-side one for why.
     */
    override fun sign(alias: String, data: ByteArray): ByteArray {
        val methods = wrapPlatformExceptions("userAuthenticationMethods $alias") { backend.userAuthenticationMethods(alias) }
        val signature = wrapPlatformExceptions("could not start a signature with $alias") { backend.newSignature(alias) }
        if (methods.isNotEmpty()) {
            val auth = authenticator
                ?: throw FfiWscdException.AuthRequired("key $alias requires user authentication and no authenticator was configured")
            val used = try {
                runBlocking { auth.authenticate(UserAuthenticationRequest(alias, methods, signature)) }
            } catch (e: Exception) {
                Timber.w(e, "User authentication failed for Android Keystore key $alias")
                throw FfiWscdException.AuthCancelled("user authentication failed or was cancelled: ${e.message}")
            }
            if (used !in methods) {
                throw FfiWscdException.AuthCancelled("authenticated with $used, which key $alias does not allow")
            }
        }
        val der = wrapPlatformExceptions("Android Keystore could not sign with $alias") {
            signature.update(data)
            signature.sign()
        }
        return EcdsaSignatures.derToRawLowS(der)
    }

    override fun aliases(): List<String> = wrapPlatformExceptions("aliases") { backend.aliases() }

    override fun delete(alias: String) {
        wrapPlatformExceptions("delete $alias") { backend.delete(alias) }
    }

    /**
     * Every method here runs on Rust's own FFI callback thread, never the
     * Android main thread (see this class's doc comment) - an ordinary
     * platform exception escaping uncaught would reach UniFFI as an
     * `UnexpectedUniFFICallbackError` instead of a typed [FfiWscdException],
     * bypassing the Rust side's typed cleanup/fallback handling (e.g. a
     * generate-then-fails-to-read-back-the-attestation sequence that should
     * delete the orphaned key). A [FfiWscdException] already thrown deeper
     * (e.g. [FfiWscdException.StrongBoxUnavailable], [sign]'s
     * [FfiWscdException.AuthRequired]/`AuthCancelled`) passes through
     * unchanged; anything else becomes a plain [FfiWscdException.Plugin].
     */
    private inline fun <T> wrapPlatformExceptions(what: String, block: () -> T): T = try {
        block()
    } catch (e: FfiWscdException) {
        throw e
    } catch (e: Exception) {
        throw FfiWscdException.Plugin("Android Keystore $what failed: ${e.message}")
    }

    private fun AndroidKeystoreSigner.SecurityLevel.toFfi(): FfiAndroidKeystoreSecurityLevel = when (this) {
        AndroidKeystoreSigner.SecurityLevel.STRONGBOX -> FfiAndroidKeystoreSecurityLevel.STRONG_BOX
        AndroidKeystoreSigner.SecurityLevel.TRUSTED_ENVIRONMENT -> FfiAndroidKeystoreSecurityLevel.TRUSTED_EXECUTION
        AndroidKeystoreSigner.SecurityLevel.SOFTWARE -> FfiAndroidKeystoreSecurityLevel.SOFTWARE
        AndroidKeystoreSigner.SecurityLevel.UNKNOWN -> FfiAndroidKeystoreSecurityLevel.UNKNOWN
    }

    private fun AndroidKeystoreSigner.AuthenticationMethod.toWireName(): String = when (this) {
        AndroidKeystoreSigner.AuthenticationMethod.BIOMETRIC -> "biometric"
        AndroidKeystoreSigner.AuthenticationMethod.DEVICE_CREDENTIAL -> "device_credential"
    }

    /**
     * The reverse of [toWireName] - `null` for an unrecognized string, which
     * [generate] turns into a thrown [FfiWscdException.Plugin] rather than
     * silently dropping the method (see [generate]'s doc comment on why
     * dropping is unsafe).
     */
    private fun String.toAuthenticationMethodOrNull(): AndroidKeystoreSigner.AuthenticationMethod? = when (this) {
        "biometric" -> AndroidKeystoreSigner.AuthenticationMethod.BIOMETRIC
        "device_credential" -> AndroidKeystoreSigner.AuthenticationMethod.DEVICE_CREDENTIAL
        else -> null
    }
}
