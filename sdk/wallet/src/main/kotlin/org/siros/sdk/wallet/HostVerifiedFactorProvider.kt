// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.keystore.AuthenticationFactor

/**
 * Lets the host app contribute ONE authentication factor to an SCA signing
 * operation (EC TS12 v1.0.1 3.6 `amr`): a user verification it performs itself,
 * typically a biometric prompt.
 *
 * It is consulted only when the key's signer says (through
 * `ScaAuthenticationCapability.requiresHostVerifiedFactor`) that it reaches
 * possession alone and a second category only if the host supplies one: a
 * WebAuthn assertion with the UV flag set, or a transport that runs the user
 * verification ceremony itself, where the signer knows verification happened
 * but not by which method. A signer that can establish two categories itself
 * (it asks for a PIN) never calls this, and a factor given here never replaces
 * one the signer measured.
 *
 * The factors that end up in the KB-JWT `amr` always come from the signing
 * operation itself, never from a registered provider alone.
 */
fun interface HostVerifiedFactorProvider {
    /**
     * Performs the user verification for [operation] NOW, after the user has
     * confirmed the transaction, and returns the factor it verified: a
     * knowledge or inherence factor, with the method the platform actually
     * reports (`fingerprint_device`, `face_device`, or `other` when it does not say).
     *
     * Return `null` when verification was cancelled, failed, or its outcome is
     * not confirmed: the presentation is then refused. A cached or earlier
     * verification must not be reported; a factor claimed here is host-asserted
     * and cannot be checked by the SDK.
     */
    suspend fun verify(operation: SigningOperation): AuthenticationFactor?
}

/** The signing operation a [HostVerifiedFactorProvider] is asked to verify the user for. */
class SigningOperation(
    /** The credential whose key signs the key binding JWT. */
    val credential: StoredCredential,
)
