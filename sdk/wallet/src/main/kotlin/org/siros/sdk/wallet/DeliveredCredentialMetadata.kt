// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import org.siros.sdk.credentials.SecretSeedCommitment
import org.siros.sdk.transport.CredentialResultMetadata

/** Why delivered credential metadata was refused. The text names no value. */
internal enum class DeliveredMetadataRefusal(val text: String) {
    /** A secret arrived in a response the engine did not report as JWE-decrypted. */
    NOT_ENCRYPTED("the secret was not delivered in an encrypted response"),

    /** An entry or the secret is not in the required form. */
    MALFORMED("the delivered metadata is malformed"),

    /** The same secret type was delivered more than once. */
    DUPLICATE("the secret was delivered more than once"),

    /** The credential carries no readable commitment to check the secret against. */
    NO_COMMITMENT("the credential carries no usable commitment for the delivered secret"),

    /** The secret does not open the credential's commitment. */
    MISMATCH("the delivered secret does not match the credential's commitment"),

    /** This keystore cannot hold the secret. */
    NO_STORAGE("this wallet cannot store the delivered secret"),
}

/** The outcome of checking one received credential's delivered metadata. */
internal sealed class DeliveredMetadataVerdict {
    /** The issuer delivered no metadata: nothing to store, behaviour unchanged. */
    data object None : DeliveredMetadataVerdict()

    /** Store [entries] (every entry exactly as received) with the credential. */
    class Accept(val entries: JsonArray) : DeliveredMetadataVerdict()

    /** The credential must not be stored. */
    class Refuse(val reason: DeliveredMetadataRefusal) : DeliveredMetadataVerdict()
}

/**
 * Receipt of the per-credential `credential_metadata` the issuer delivers beside a credential
 * (privatedata-spec §5A). A pure check, run BEFORE anything is stored: a refusal means the credential
 * (and, for a batch, the whole issuance) is not stored.
 *
 * Only the entry type [secretSeedType] is interpreted: it must arrive in a JWE-encrypted response, be 16
 * bytes as 32 lowercase hex characters, and open the `ssc` of the credential just received
 * (`SHA256(secret_seed) == ssc`). Every other entry is stored uninterpreted.
 */
internal object DeliveredCredentialMetadata {
    fun check(
        format: String,
        credential: String,
        delivered: CredentialResultMetadata,
        secretSeedType: String,
        canStoreSecret: Boolean,
    ): DeliveredMetadataVerdict {
        val entries = delivered.credentialMetadata
        if (entries.isNullOrEmpty()) return DeliveredMetadataVerdict.None
        // An entry the container could not store (blank type) refuses rather than being dropped.
        if (entries.any { it.type.isEmpty() }) return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.MALFORMED)
        val all = JsonArray(
            entries.map { e ->
                buildJsonObject {
                    put("type", JsonPrimitive(e.type))
                    put("value", e.value)
                }
            },
        )
        val seeds = entries.filter { it.type == secretSeedType }
        if (seeds.isEmpty()) return DeliveredMetadataVerdict.Accept(all)
        if (seeds.size > 1) return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.DUPLICATE)
        // Plain JSON never carries a secret: the engine sets the flag only for a JWE-decrypted response.
        if (!delivered.credentialMetadataEncryptedResponse) return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.NOT_ENCRYPTED)
        if (!canStoreSecret) return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.NO_STORAGE)
        val hex = (seeds[0].value as? JsonPrimitive)?.takeIf { it.isString }?.content
            ?: return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.MALFORMED)
        val seed = SecretSeedCommitment.seedFromHex(hex)
            ?: return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.MALFORMED)
        try {
            val ssc = when {
                format.equals("mso_mdoc", ignoreCase = true) -> SecretSeedCommitment.sscOfMdoc(credential)
                format.contains("sd-jwt", ignoreCase = true) -> SecretSeedCommitment.sscOfSdJwt(credential)
                else -> null
            } ?: return DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.NO_COMMITMENT)
            val ok = SecretSeedCommitment.opens(seed, ssc)
            ssc.fill(0)
            return if (ok) DeliveredMetadataVerdict.Accept(all) else DeliveredMetadataVerdict.Refuse(DeliveredMetadataRefusal.MISMATCH)
        } finally {
            seed.fill(0)
        }
    }
}
