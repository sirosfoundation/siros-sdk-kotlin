// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.sirosfoundation.sdk.keystore

/**
 * Platform attestation evidence to include in WIA generation requests.
 *
 * Send this to the backend's `/wallet-provider/wia/generate` endpoint
 * in the `native_attestation` field alongside the WIA-PoP.
 */
data class NativeAttestationEvidence(
    /** The attestation type: "apple_app_attest" or "google_play_integrity" */
    val type: String,
    /** Base64-encoded attestation token */
    val token: String,
    /** The key identifier bound to this attestation */
    val keyId: String,
    /** The challenge nonce that was attested */
    val challenge: String,
)

/**
 * Interface for platform-specific attestation providers.
 *
 * Implementations provide attestation evidence from the native platform
 * (App Attest on iOS, Play Integrity on Android) that the backend uses
 * to issue platform-attested WIA JWTs.
 */
interface NativeAttestationProvider {
    /** Whether native attestation is available on this device/platform. */
    val isAvailable: Boolean

    /**
     * Generate attestation evidence for a WIA challenge.
     *
     * @param challenge The challenge nonce from `/wia/challenge`.
     * @param keyId The instance key ID to bind to the attestation.
     * @return Attestation evidence to include in the WIA generate request.
     */
    suspend fun generateEvidence(challenge: String, keyId: String): NativeAttestationEvidence
}
