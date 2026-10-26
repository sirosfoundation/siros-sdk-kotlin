// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import java.security.Signature

/**
 * Asks the user to authenticate for ONE use of an [AndroidKeystoreSigner] key that requires it
 * ([AndroidKeystoreSigner.UserAuthentication.EveryUse]). The SDK cannot show UI itself, so the
 * host supplies this; [BiometricPromptAuthenticator] is the ready-made one.
 *
 * The authentication must be bound to [UserAuthenticationRequest.signature] (a `BiometricPrompt`
 * `CryptoObject`): the Keystore then lets exactly that `Signature` object sign once. An
 * authentication that is not bound to it does not unlock the key, and the sign fails.
 */
fun interface UserAuthenticator {
    /**
     * Authenticates the user for [request] and returns the method actually used.
     *
     * @throws Exception when the user cancels or the authentication fails; the sign is then refused.
     */
    suspend fun authenticate(request: UserAuthenticationRequest): AndroidKeystoreSigner.AuthenticationMethod
}

/**
 * One authentication: for the key [keyId], with any of [allowed], unlocking [signature] (already
 * initialised for signing with that key; the caller signs with it afterwards).
 */
class UserAuthenticationRequest internal constructor(
    val keyId: String,
    val allowed: Set<AndroidKeystoreSigner.AuthenticationMethod>,
    val signature: Signature,
) {
    override fun toString() = "UserAuthenticationRequest(keyId=$keyId, allowed=$allowed)"
}
