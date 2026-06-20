package org.sirosfoundation.sdk.keystore

/**
 * Provides user authentication credentials when requested by the WSCD.
 *
 * Implement this interface in the wallet application to handle
 * PIN entry prompts and WebAuthn assertion ceremonies during
 * signing operations that require 2FA (e.g. R2PS remote signing).
 *
 * Note: These methods are called synchronously from a background thread.
 * Implementations that show UI should use platform mechanisms to
 * block until the user completes the interaction (e.g. runBlocking on Main).
 */
interface AuthProvider {
    /**
     * Request the user's PIN (e.g. for OPAQUE authentication).
     *
     * @return The PIN as raw bytes (UTF-8 encoded).
     * @throws Exception if the user cancels.
     */
    fun requestPin(): ByteArray

    /**
     * Request a WebAuthn assertion for the given parameters.
     *
     * @param challenge The authentication challenge bytes.
     * @param rpId The Relying Party ID.
     * @param allowedCredentials List of allowed credential IDs.
     * @return The CBOR-encoded authenticator assertion response.
     * @throws Exception if the user cancels or no credential is available.
     */
    fun requestWebauthnAssertion(
        challenge: ByteArray,
        rpId: String,
        allowedCredentials: List<ByteArray>,
    ): ByteArray
}
