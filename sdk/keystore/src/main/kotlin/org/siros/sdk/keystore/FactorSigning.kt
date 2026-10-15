// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import uniffi.siros_wscd_manager.FfiAuthCallback
import uniffi.siros_wscd_manager.FfiAuthFactor
import uniffi.siros_wscd_manager.FfiFactorCapability
import uniffi.siros_wscd_manager.FfiFactorCategory
import uniffi.siros_wscd_manager.FfiSignOptions
import uniffi.siros_wscd_manager.FfiSignOutcome
import uniffi.siros_wscd_manager.FfiWscdException
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction

/** The part of the WSCD manager SCA signing needs; a seam so the logic is testable without the native library. */
internal interface FactorSigningBackend {
    fun capability(kid: String): FfiFactorCapability
    fun pluginIdOf(kid: String): String?
    fun signWithFactors(kid: String, data: ByteArray, options: FfiSignOptions, auth: FfiAuthCallback): FfiSignOutcome
}

/**
 * SCA signing through the WSCD manager's `signWithFactors` (siros-wscd-manager
 * 0.10.0): a FRESH user authentication, and the factors returned together with
 * the signature.
 *
 * The factors a KB-JWT claims are inside the signed bytes, so they have to be
 * stated before the signature exists. [begin] therefore settles them first: the
 * possession factor from the key's plugin, and the second factor either from
 * the host (a factor it verified for this sign) or from a PIN asked for NOW,
 * whose class is measured here and which is then handed to the plugin when it
 * asks, so the user is prompted once. After the sign, the plugin's own report
 * must equal the claim ([ScaSignSession.requireMatching]); any difference
 * refuses. Nothing is cached between signs.
 */
internal class FactorSigning(
    private val backend: FactorSigningBackend,
    /** The host's authentication callbacks (PIN, WebAuthn); a PIN the user typed ahead is served before this is asked again. */
    private val callbacks: FfiAuthCallback,
) {
    fun capability(kid: String): ScaAuthenticationCapability = try {
        val c = backend.capability(kid)
        ScaAuthenticationCapability(c.canReachTwoCategories, c.requiresHostVerifiedFactor, c.reason)
    } catch (e: Exception) {
        ScaAuthenticationCapability.cannot("The signer could not say which authentication it can perform (${e.javaClass.simpleName})")
    }

    fun begin(kid: String, hostVerifiedFactor: AuthenticationFactor?): ScaSignSession {
        val capability = capability(kid)
        if (!capability.isPossible) {
            throw ScaSignSession.insufficient(capability.reason ?: "The signer cannot reach two authentication categories")
        }
        val pluginId = backend.pluginIdOf(kid)
            ?: throw ScaSignSession.insufficient("The plugin holding the key is unknown")
        val possession = when (pluginId) {
            "r2ps" -> AuthenticationFactor(AuthenticationCategory.POSSESSION, "key_in_remote_wscd")
            "fido2" -> AuthenticationFactor(AuthenticationCategory.POSSESSION, "key_in_local_external_wscd")
            else -> throw ScaSignSession.insufficient("The '$pluginId' plugin establishes no possession factor")
        }
        return if (capability.canReachTwoCategories) {
            pinSession(kid, pluginId, possession)
        } else {
            val host = hostVerifiedFactor
                ?: throw ScaSignSession.insufficient("A host-verified authentication factor is required and none was supplied")
            if (host.category == AuthenticationCategory.POSSESSION) {
                throw ScaSignSession.insufficient("A host-verified factor must be knowledge or inherence")
            }
            Session(kid, listOf(possession, host), host, null)
        }
    }

    private fun pinSession(kid: String, pluginId: String, possession: AuthenticationFactor): ScaSignSession {
        val pin = try {
            callbacks.requestPin(pluginId)
        } catch (e: FfiWscdException) {
            throw ScaSignSession.insufficient("The user did not enter a PIN")
        }
        try {
            val method = classifySecret(pin)
                ?: throw ScaSignSession.insufficient("The class of the entered secret cannot be determined")
            return Session(kid, listOf(possession, AuthenticationFactor(AuthenticationCategory.KNOWLEDGE, method)), null, pin)
        } catch (e: Throwable) {
            pin.fill(0)
            throw e
        }
    }

    private inner class Session(
        private val kid: String,
        override val declaredFactors: List<AuthenticationFactor>,
        private val host: AuthenticationFactor?,
        /** The PIN typed for this sign; served once to the plugin, wiped on close. */
        private var pin: ByteArray?,
    ) : ScaSignSession {
        private var used = false

        override suspend fun sign(data: ByteArray): ScaSignature {
            check(!used) { "An SCA sign session signs once" }
            used = true
            val options = FfiSignOptions(
                requireFreshUserAuthentication = true,
                hostVerifiedFactor = host?.let { FfiAuthFactor(it.category.toFfi(), it.method) },
            )
            val handedToPlugin = mutableListOf<ByteArray>()
            val outcome = try {
                backend.signWithFactors(kid, data, options, oneShotPin(handedToPlugin))
            } catch (e: FfiWscdException.Unsupported) {
                throw ScaSignSession.insufficient("This authenticator cannot guarantee a fresh user authentication for the sign")
            } finally {
                // The native call copies a returned PIN and never clears ours: wipe every buffer given to it.
                handedToPlugin.forEach { it.fill(0) }
            }
            val applied = try {
                outcome.factors.factors.map { AuthenticationFactor(it.category.toSdk(), it.method) }
            } catch (e: IllegalArgumentException) {
                throw ScaSignSession.insufficient("The signer reported an authentication factor outside the TS12 vocabulary")
            }
            if (!outcome.factors.satisfiesTwoCategories) {
                throw ScaSignSession.insufficient("The signing operation applied fewer than two authentication categories")
            }
            return ScaSignature(outcome.signature.data, applied)
        }

        override fun close() {
            pin?.fill(0)
            pin = null
        }

        /**
         * Serves the PIN typed ahead of the sign to its FIRST request; any later request asks the user
         * normally. Every buffer returned is recorded in [handedOut] so it can be wiped when the sign ends.
         */
        private fun oneShotPin(handedOut: MutableList<ByteArray>): FfiAuthCallback = object : FfiAuthCallback {
            override fun requestPin(pluginId: String): ByteArray {
                val held = pin
                val answer = if (held != null) {
                    pin = null
                    // The plugin gets its own copy; the held one is wiped.
                    held.copyOf().also { held.fill(0) }
                } else {
                    callbacks.requestPin(pluginId)
                }
                handedOut += answer
                return answer
            }

            override fun requestWebauthnAssertion(
                pluginId: String,
                challenge: ByteArray,
                rpId: String,
                allowedCredentials: List<ByteArray>,
            ): ByteArray = callbacks.requestWebauthnAssertion(pluginId, challenge, rpId, allowedCredentials)
        }
    }

    companion object {
        /**
         * The TS12 knowledge method for a secret, as siros-wscd-manager measures it
         * (`classify_secret`): all ASCII digits is a PIN (under 6 / 6 or more), anything
         * else a passphrase by length in characters (under 8 / 8 to 11 / 12 or more).
         * Null for an empty or non-UTF-8 secret: the class is then unknown, never guessed.
         */
        fun classifySecret(secret: ByteArray): String? {
            // Decoded into a buffer this function owns and wipes on every path; no String (an
            // immutable copy of the secret that cannot be erased) is ever made.
            val chars = CharBuffer.allocate(secret.size)
            try {
                val decoder = Charsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                val input = ByteBuffer.wrap(secret)
                if (decoder.decode(input, chars, true).isError || decoder.flush(chars).isError) return null
                val array = chars.array()
                val length = chars.position()
                val n = Character.codePointCount(array, 0, length)
                if (n == 0) return null
                return if ((0 until length).all { array[it] in '0'..'9' }) {
                    if (n < 6) "pin_less_than_6_digits" else "pin_6_or_more_digits"
                } else when {
                    n < 8 -> "passphrase_less_than_8_chars"
                    n < 12 -> "passphrase_8_to_11_chars"
                    else -> "passphrase_12_or_more_chars"
                }
            } finally {
                chars.array().fill('\u0000')
            }
        }

        private fun AuthenticationCategory.toFfi() = when (this) {
            AuthenticationCategory.KNOWLEDGE -> FfiFactorCategory.KNOWLEDGE
            AuthenticationCategory.POSSESSION -> FfiFactorCategory.POSSESSION
            AuthenticationCategory.INHERENCE -> FfiFactorCategory.INHERENCE
        }

        private fun FfiFactorCategory.toSdk() = when (this) {
            FfiFactorCategory.KNOWLEDGE -> AuthenticationCategory.KNOWLEDGE
            FfiFactorCategory.POSSESSION -> AuthenticationCategory.POSSESSION
            FfiFactorCategory.INHERENCE -> AuthenticationCategory.INHERENCE
        }
    }
}
