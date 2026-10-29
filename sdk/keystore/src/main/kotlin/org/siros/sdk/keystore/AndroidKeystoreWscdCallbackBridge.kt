// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import kotlinx.coroutines.runBlocking
import org.siros.sdk.credentials.KeystoreException
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
        val methods = userAuthenticationMethods.mapNotNull { it.toAuthenticationMethodOrNull() }.toSet()
        return try {
            backend.generate(alias, attestationChallenge, strongBox, methods, unlockedDeviceRequired).toFfi()
        } catch (e: AndroidKeyStoreBackend.StrongBoxUnavailable) {
            throw FfiWscdException.StrongBoxUnavailable("StrongBox is unavailable on this device")
        }
    }

    override fun certificateChain(alias: String): List<ByteArray> = backend.certificateChain(alias)

    override fun publicKeyJwk(alias: String): String = EcdsaSignatures.publicJwk(backend.publicKey(alias))

    override fun securityLevel(alias: String): FfiAndroidKeystoreSecurityLevel = backend.securityLevel(alias).toFfi()

    override fun userAuthenticationMethods(alias: String): List<String> =
        backend.userAuthenticationMethods(alias).map { it.toWireName() }

    /**
     * Mirrors [AndroidKeystoreSigner.sign]/its private `finish` exactly: a
     * [java.security.Signature]/`CryptoObject` cannot cross UniFFI, so the
     * whole per-use-authentication dance happens here, host-side, in one
     * call - see this class's own doc comment and
     * [AndroidKeystoreCallback]'s Rust-side one for why.
     */
    override fun sign(alias: String, data: ByteArray): ByteArray {
        val methods = backend.userAuthenticationMethods(alias)
        val signature = try {
            backend.newSignature(alias)
        } catch (e: KeystoreException) {
            throw FfiWscdException.Plugin("could not start a signature with $alias: ${e.message}")
        }
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
        val der = try {
            signature.update(data)
            signature.sign()
        } catch (e: Exception) {
            throw FfiWscdException.Plugin("Android Keystore could not sign with $alias: ${e.message}")
        }
        return EcdsaSignatures.derToRawLowS(der)
    }

    override fun aliases(): List<String> = backend.aliases()

    override fun delete(alias: String) {
        backend.delete(alias)
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

    /** The reverse of [toWireName]; an unrecognized string is dropped rather than thrown - see that function's doc comment. */
    private fun String.toAuthenticationMethodOrNull(): AndroidKeystoreSigner.AuthenticationMethod? = when (this) {
        "biometric" -> AndroidKeystoreSigner.AuthenticationMethod.BIOMETRIC
        "device_credential" -> AndroidKeystoreSigner.AuthenticationMethod.DEVICE_CREDENTIAL
        else -> {
            Timber.w("Unrecognized Android Keystore authentication method '$this' from siros-wscd-manager; ignoring")
            null
        }
    }
}
