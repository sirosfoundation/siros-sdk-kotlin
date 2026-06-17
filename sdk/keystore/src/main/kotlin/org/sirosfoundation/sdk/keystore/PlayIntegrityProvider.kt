// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.sirosfoundation.sdk.keystore

import android.content.Context
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.suspendCancellableCoroutine
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
 * val token = provider.requestIntegrityToken(challenge)
 * // Send token to backend as native_attestation.token
 * ```
 */
class PlayIntegrityProvider(
    private val context: Context,
    private val cloudProjectNumber: Long,
) {
    private val integrityManager = IntegrityManagerFactory.create(context)

    /**
     * Request a Play Integrity token bound to the given challenge nonce.
     *
     * The nonce should be the challenge from the backend's `/wia/challenge` endpoint,
     * base64url-encoded.
     *
     * @param nonce The challenge nonce (base64url-encoded) to bind to the token.
     * @return The integrity token string to send to the backend.
     * @throws PlayIntegrityException if the request fails.
     */
    suspend fun requestIntegrityToken(nonce: String): String {
        return suspendCancellableCoroutine { continuation ->
            val request = IntegrityTokenRequest.builder()
                .setNonce(nonce)
                .setCloudProjectNumber(cloudProjectNumber)
                .build()

            integrityManager.requestIntegrityToken(request)
                .addOnSuccessListener { response ->
                    continuation.resume(response.token())
                }
                .addOnFailureListener { exception ->
                    continuation.resumeWithException(
                        PlayIntegrityException("Play Integrity request failed", exception)
                    )
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
