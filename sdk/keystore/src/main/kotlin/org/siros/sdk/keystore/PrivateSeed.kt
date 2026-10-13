// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import java.security.MessageDigest

/**
 * A wallet root secret that can derive labelled secrets without ever handing
 * out the key itself.
 *
 * [JweKeystore] implements it with the container `mainKey`, which is private
 * to the keystore; tests supply a fixed root instead.
 */
interface RootSecret {
    /**
     * `HKDF-SHA256(root, salt = empty, info)[:length]`.
     *
     * @param info The full HKDF info input, label included; see [PrivateSeed] for the one in use.
     * @param length Output length in bytes, at most 32.
     * @throws org.siros.sdk.credentials.KeystoreException if the root is not available (a locked keystore).
     */
    fun deriveSecret(info: ByteArray, length: Int): ByteArray
}

/**
 * The holder's `private_seed` for a credential type, and its commitment.
 *
 * `private_seed = HKDF-SHA256(root, info = "org.siros.private_seed/v1" || credentialType)[:16]`,
 * `psc = SHA256(private_seed)`. The seed is stable per credential type: it
 * does not depend on a credential id, a batch or an issuance, so every
 * batch, issuance and renewal of one type commits to the same `psc`.
 * `credentialType` is an opaque caller-supplied string (a doctype, a vct);
 * it is UTF-8 encoded and never interpreted.
 *
 * The root is the container `mainKey` (via [JweKeystore]), not a PRF output:
 * `mainKey` is the same on every passkey and device of an account, while PRF
 * outputs differ per passkey and would change the seed on a second passkey.
 * The label is defined in privatedata-spec SPEC.md section 5.4.
 *
 * # Permanence
 *
 * `mainKey` MUST NEVER be rotated or re-keyed: doing so changes every seed
 * and so every `psc`. No such code exists today. `mainKey` is generated once,
 * when a first container is created ([JweKeystore.unlock] with an empty
 * container), and every later export re-encrypts under the same key; adding
 * a passkey only wraps the same `mainKey` for another PRF key. Losing the
 * container and creating a new one is, necessarily, a new root.
 *
 * The seed never leaves this module: it is not returned, logged, stored or
 * cached, and appears in no exception message. Every call derives it afresh,
 * so a locked keystore yields nothing.
 */
class PrivateSeed(private val root: RootSecret) {

    /** `SHA256(private_seed)` for [credentialType]: the value the issuer receives in the credential request. */
    fun psc(credentialType: String): ByteArray {
        val seed = derive(credentialType)
        try {
            return MessageDigest.getInstance("SHA-256").digest(seed)
        } finally {
            seed.fill(0)
        }
    }

    /**
     * Whether [psc] is the commitment this wallet derives for [credentialType].
     * Fail-closed: anything but an exact 32-byte match is `false`, and a
     * wallet that gets `false` must not use the seed.
     *
     * @throws org.siros.sdk.credentials.KeystoreException if the keystore is locked.
     */
    fun matchesCommitment(credentialType: String, psc: ByteArray): Boolean {
        val expected = psc(credentialType)
        return psc.size == expected.size && MessageDigest.isEqual(expected, psc)
    }

    /** The 16-byte seed. Internal on purpose: callers get `psc` and the check, never the seed. */
    internal fun derive(credentialType: String): ByteArray = root.deriveSecret(info(credentialType), SEED_BYTES)

    internal companion object {
        /** The derivation label, including its version. */
        const val LABEL = "org.siros.private_seed/v1"

        /** The rulebook's `private_seed` length. */
        const val SEED_BYTES = 16

        fun info(credentialType: String): ByteArray = (LABEL + credentialType).toByteArray(Charsets.UTF_8)
    }
}
