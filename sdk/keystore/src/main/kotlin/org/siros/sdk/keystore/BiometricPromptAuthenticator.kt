// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import android.os.Build
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import org.siros.sdk.credentials.KeystoreException

/**
 * A [UserAuthenticator] over Android's `BiometricPrompt`, bound to the key's `Signature`
 * (`CryptoObject`): a class 3 (strong) biometric, the device PIN, pattern or password, or either,
 * as the key's policy allows.
 *
 * The device credential as a per-use factor needs Android 11 (API 30); before that a key that
 * allows both is offered the biometric only.
 *
 * @param activity The activity the prompt is shown over, asked for at each authentication (so a
 *   recreated activity is used, not a stale one).
 * @param title The prompt's title, for example "Confirm with your fingerprint or PIN".
 * @param subtitle An optional line under it.
 * @param negativeButtonText The cancel button, shown when the device credential is not offered
 *   (the system shows its own otherwise).
 */
class BiometricPromptAuthenticator @JvmOverloads constructor(
    private val activity: () -> FragmentActivity,
    private val title: String,
    private val subtitle: String? = null,
    private val negativeButtonText: String = "Cancel",
) : UserAuthenticator {

    /**
     * Only one `BiometricPrompt` can sensibly be on screen at a time - AndroidX shares prompt state per activity with
     * the LATEST prompt's callback, so a second `authenticate()` starting while a first is still pending can leave
     * the first's continuation suspended forever, or deliver the second prompt's result to it (a different
     * `CryptoObject` than the one it asked to unlock). This serializes every call through every
     * [BiometricPromptAuthenticator] instance process-wide, not just this one, since two different instances sharing
     * (or not) a host activity are exactly as unsafe to run concurrently.
     */
    override suspend fun authenticate(request: UserAuthenticationRequest): AndroidKeystoreSigner.AuthenticationMethod =
        lock.withLock {
            withContext(Dispatchers.Main) {
                val authenticators = authenticatorsFor(request.allowed, Build.VERSION.SDK_INT)
                if (authenticators == 0) {
                    throw KeystoreException(
                        "No authentication method this Android can offer for the key",
                        errorCode = "user_authentication_unavailable",
                    )
                }
                val host = activity()
                suspendCancellableCoroutine { continuation ->
                    // The callback's two methods are mutually exclusive (Android fires at most one per authenticate()
                    // call), but the new ON_DESTROY path below is not: it can race either of them. This guards every
                    // resume so only the first one lands - a second `resume`/`resumeWithException` on an already
                    // resumed CancellableContinuation throws, which would otherwise crash whichever path lost the race.
                    val settled = java.util.concurrent.atomic.AtomicBoolean(false)
                    lateinit var lifecycleObserver: LifecycleEventObserver
                    fun cleanup() = host.lifecycle.removeObserver(lifecycleObserver)
                    fun resume(method: AndroidKeystoreSigner.AuthenticationMethod) {
                        if (settled.compareAndSet(false, true)) {
                            cleanup()
                            continuation.resume(method)
                        }
                    }
                    fun fail(exception: KeystoreException) {
                        if (settled.compareAndSet(false, true)) {
                            cleanup()
                            continuation.resumeWithException(exception)
                        }
                    }
                    val callback = object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            val method = when (result.authenticationType) {
                                BiometricPrompt.AUTHENTICATION_RESULT_TYPE_BIOMETRIC -> AndroidKeystoreSigner.AuthenticationMethod.BIOMETRIC
                                BiometricPrompt.AUTHENTICATION_RESULT_TYPE_DEVICE_CREDENTIAL ->
                                    AndroidKeystoreSigner.AuthenticationMethod.DEVICE_CREDENTIAL
                                else -> null
                            }
                            if (method == null) {
                                // Fail closed: a factor that cannot be named cannot be claimed.
                                fail(KeystoreException("The prompt did not say how the user authenticated", errorCode = "user_authentication_unknown"))
                            } else {
                                resume(method)
                            }
                        }

                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                            fail(KeystoreException("User authentication ended: $errString", errorCode = "user_authentication_failed"))
                        }
                        // onAuthenticationFailed: one attempt was not recognised; the prompt stays open.
                    }
                    val info = BiometricPrompt.PromptInfo.Builder()
                        .setTitle(title)
                        .apply { subtitle?.let { setSubtitle(it) } }
                        .setAllowedAuthenticators(authenticators)
                        .apply { if (authenticators and DEVICE_CREDENTIAL == 0) setNegativeButtonText(negativeButtonText) }
                        .setConfirmationRequired(false)
                        .build()
                    val prompt = BiometricPrompt(host, host.mainExecutor, callback)
                    // If the host activity is destroyed while the prompt is pending (a rotation with no matching
                    // configuration, the user backgrounding and the system killing the activity, ...), BiometricPrompt
                    // has no way to reconnect its callback to a recreated activity, so nothing would ever complete
                    // this continuation again. Fail it closed instead of leaving the caller suspended indefinitely.
                    lifecycleObserver = LifecycleEventObserver { _, event ->
                        if (event == Lifecycle.Event.ON_DESTROY) {
                            fail(KeystoreException("The host activity ended before authentication completed", errorCode = "user_authentication_failed"))
                        }
                    }
                    host.lifecycle.addObserver(lifecycleObserver)
                    continuation.invokeOnCancellation {
                        cleanup()
                        prompt.cancelAuthentication()
                    }
                    prompt.authenticate(info, BiometricPrompt.CryptoObject(request.signature))
                }
            }
        }

    internal companion object {
        /** Process-wide: see [authenticate]'s doc comment for why this is shared across every instance. */
        private val lock = Mutex()

        /** The `BiometricPrompt` authenticators for [allowed] on Android [sdk]. */
        fun authenticatorsFor(allowed: Set<AndroidKeystoreSigner.AuthenticationMethod>, sdk: Int): Int {
            var a = 0
            if (AndroidKeystoreSigner.AuthenticationMethod.BIOMETRIC in allowed) a = a or BIOMETRIC_STRONG
            if (AndroidKeystoreSigner.AuthenticationMethod.DEVICE_CREDENTIAL in allowed && sdk >= Build.VERSION_CODES.R) {
                a = a or DEVICE_CREDENTIAL
            }
            return a
        }
    }
}
