// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import android.content.Context
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.suspendCancellableCoroutine
import java.security.MessageDigest
import java.util.Base64
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Provides Google Play Integrity attestation for wallet instance authentication.
 *
 * This provider generates Play Integrity tokens that the backend can verify to
 * issue platform-attested WIA JWTs. The token proves the app is genuine, running
 * on a device that meets integrity requirements.
 *
 * Usage:
 * ```kotlin
 * val provider = PlayIntegrityProvider(context, cloudProjectNumber)
 * val evidence = provider.generateEvidence(challenge, keyId)
 * // Send evidence to backend as native_attestation
 * ```
 */
class PlayIntegrityProvider(
    private val context: Context,
    private val cloudProjectNumber: Long,
) : NativeAttestationProvider {
    private val integrityManager = IntegrityManagerFactory.create(context)

    // Real unavailability (e.g. Play Services missing) surfaces as an
    // exception from the Play Integrity call itself, caught by the same
    // best-effort wrapper as every other WIA-issuance failure mode - there's
    // no cheap synchronous check to do here, unlike App Attest's isSupported.
    override val isAvailable: Boolean = true

    override suspend fun generateEvidence(challenge: String, keyId: String): NativeAttestationEvidence {
        val token = requestIntegrityToken(nonceForChallenge(challenge))
        return NativeAttestationEvidence(
            type = "google_play_integrity",
            token = token,
            keyId = keyId,
            challenge = challenge,
        )
    }

    companion object {
        /**
         * The Play Integrity nonce for a given WIA challenge:
         * base64url-no-pad(SHA-256(challenge)), matching go-wallet-backend's
         * `native_attestation.go` verifier exactly. Play Integrity requires
         * the caller to pre-hash the nonce - passing the raw challenge (an
         * earlier version of this contract's doc said to do that) sends a
         * nonce the backend can never independently re-derive and verify.
         *
         * A plain function of its input (no `context`/`integrityManager`
         * dependency) - kept in the companion object rather than as an
         * instance method so it's unit-testable without constructing a real
         * `PlayIntegrityProvider` (which eagerly calls
         * `IntegrityManagerFactory.create(context)` and so needs a real
         * Android environment).
         */
        internal fun nonceForChallenge(challenge: String): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(challenge.toByteArray(Charsets.UTF_8))
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
        }
    }

    /**
     * Request a Play Integrity token bound to the given nonce.
     *
     * Low-level primitive - prefer [generateEvidence], which computes the
     * nonce correctly from a raw WIA challenge. `nonce` here must already be
     * base64url-no-pad(SHA-256(challenge)); passing a raw, un-hashed
     * challenge produces a nonce the backend cannot verify.
     *
     * @param nonce The pre-hashed, base64url-no-pad-encoded nonce to bind to the token.
     * @return The integrity token string to send to the backend.
     * @throws PlayIntegrityException if the request fails.
     */
    suspend fun requestIntegrityToken(nonce: String): String {
        return suspendCancellableCoroutine { continuation ->
            val request = IntegrityTokenRequest.builder()
                .setNonce(nonce)
                .setCloudProjectNumber(cloudProjectNumber)
                .build()

            val task = integrityManager.requestIntegrityToken(request)
            task.addOnSuccessListener { response ->
                    if (continuation.isActive) {
                        continuation.resume(response.token())
                    }
                }
                .addOnFailureListener { exception ->
                    if (continuation.isActive) {
                        continuation.resumeWithException(
                            PlayIntegrityException("Play Integrity request failed", exception)
                        )
                    }
                }

            continuation.invokeOnCancellation {
                // Task cannot be cancelled, but we ensure no resume after cancel
            }
        }
    }
}

/**
 * Exception thrown when Play Integrity token request fails.
 */
class PlayIntegrityException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)
