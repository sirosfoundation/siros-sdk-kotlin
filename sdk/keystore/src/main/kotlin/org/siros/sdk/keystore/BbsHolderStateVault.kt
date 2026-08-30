// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import java.util.Base64
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.siros.sdk.credentials.BbsHolderState

/**
 * Persists the holder state a blind BBS credential cannot be presented
 * without.
 *
 * # Why this exists at all
 *
 * A JWP carries the issuer's claims and the signature. It deliberately does
 * not carry the holder's blinding factor, its committed values, or which
 * device key the credential is bound to — publishing those would undo the
 * point of blind issuance. So they live beside the credential, and without
 * them the credential is not degraded but *unusable*: there is no way to
 * reconstruct a blinding factor after the fact.
 *
 * That is why this is written to the synchronised container rather than to
 * device-local storage. A credential issued on one device and restored on
 * another has to remain presentable.
 *
 * # Where it lives
 *
 * `S.extensions["org.siros.bbs"]`, keyed by credential id — privatedata-spec
 * §6.1. The key names one credential, never "bbs" or a subsystem, because
 * resolution is last-write-wins per entry: an aggregate entry would let two
 * devices storing different credentials' state overwrite each other.
 *
 * @param keystore the container this state is stored in. Must be unlocked.
 *   Typed as [ExtensionStore] rather than a concrete keystore because both
 *   container owners qualify and this has no reason to know which one it has.
 */
class BbsHolderStateVault(private val keystore: ExtensionStore) {

    /**
     * Store the state produced by accepting an issued credential.
     *
     * @param credentialId identifies the credential this state belongs to,
     *   and becomes the entry key. Must be the same value used to look the
     *   state up at presentation time.
     */
    suspend fun put(credentialId: String, state: BbsHolderState) {
        keystore.setExtensionEntry(NAMESPACE, credentialId, encode(state))
    }

    /**
     * Look up the state for a credential, or `null` if none is stored.
     *
     * A `null` here means the credential cannot be presented — never that it
     * can be presented without binding.
     */
    suspend fun get(credentialId: String): BbsHolderState? =
        keystore.extensionEntries(NAMESPACE)[credentialId]?.let(::decode)

    /**
     * Drop the state for a credential.
     *
     * privatedata-spec §6.1.2 requires that deleting the entity an entry
     * names deletes the entry, so this must be called when the credential
     * is deleted. Left behind, the entry is a long-lived secret belonging to
     * a credential that no longer exists.
     */
    suspend fun remove(credentialId: String) {
        keystore.removeExtensionEntry(NAMESPACE, credentialId)
    }

    /** Every credential id this container holds BBS state for. */
    suspend fun credentialIds(): Set<String> = keystore.extensionEntries(NAMESPACE).keys

    // --- encoding -----------------------------------------------------------

    /**
     * The stored shape.
     *
     * Byte arrays are base64url because the entry value is a string: §6.1
     * makes an entry an opaque *string* so that a client which does not
     * implement the namespace can still carry it without knowing how to
     * encode whatever is inside.
     */
    @Serializable
    private data class Stored(
        val issuerPublicKey: String,
        val secretProverBlind: String,
        val committedMessages: List<String>,
        val keybindPublicKeys: List<String>,
    )

    private fun encode(state: BbsHolderState): String = json.encodeToString(
        Stored.serializer(),
        Stored(
            issuerPublicKey = b64(state.issuerPublicKey),
            secretProverBlind = b64(state.secretProverBlind),
            committedMessages = state.committedMessages.map(::b64),
            keybindPublicKeys = state.keybindPublicKeys.map(::b64),
        ),
    )

    private fun decode(raw: String): BbsHolderState? = runCatching {
        val stored = json.decodeFromString(Stored.serializer(), raw)
        BbsHolderState(
            issuerPublicKey = unb64(stored.issuerPublicKey),
            secretProverBlind = unb64(stored.secretProverBlind),
            committedMessages = stored.committedMessages.map(::unb64),
            keybindPublicKeys = stored.keybindPublicKeys.map(::unb64),
        )
    }.getOrNull()

    private fun b64(data: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(data)

    private fun unb64(value: String): ByteArray = Base64.getUrlDecoder().decode(value)

    companion object {
        /** privatedata-spec §6.1.6 registry entry. */
        const val NAMESPACE: String = "org.siros.bbs"

        private val json = Json { ignoreUnknownKeys = true }
    }
}
