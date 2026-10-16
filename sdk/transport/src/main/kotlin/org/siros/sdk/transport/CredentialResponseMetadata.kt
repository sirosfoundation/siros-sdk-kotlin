package org.siros.sdk.transport

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * One entry of a per-credential `credential_metadata` array that an issuer
 * delivers beside `credential` in an OID4VCI credential response, as the
 * wallet engine relays it on a `CredentialResult`.
 *
 * This is NOT the display-oriented `CredentialMetadata` of the credential
 * store (issuer-published claim and logo metadata): it is a delivered,
 * possibly secret, per-credential value. [value] is kept as the raw JSON
 * element so it can be stored exactly as received; a consumer interprets
 * only the entry types it knows and leaves every other entry untouched.
 *
 * The array is only trustworthy when [CredentialResultMetadata.credentialMetadataEncryptedResponse]
 * is set on the same result: the engine sets that only when the issuer's
 * response was JWE-decrypted, and a secret must not be accepted from a plain
 * JSON response.
 */
@Serializable(with = CredentialResponseMetadataEntrySerializer::class)
data class CredentialResponseMetadataEntry(
    val type: String,
    val value: JsonElement,
    /**
     * Every member of the received entry other than `type` and `value`,
     * verbatim. Kept so the entry can be stored exactly as received
     * (privatedata-spec section 6), including members this SDK does not know.
     */
    val additionalMembers: JsonObject = JsonObject(emptyMap()),
) {
    /** The entry as received: `type`, `value` and every additional member, values verbatim. */
    val raw: JsonObject
        get() = JsonObject(additionalMembers + mapOf("type" to JsonPrimitive(type), "value" to value))
}

/**
 * Decodes an entry from the raw JSON object so unknown members survive
 * (`ignoreUnknownKeys` would otherwise drop them). Requires a string `type`
 * and a present `value`; anything else is a [SerializationException], as
 * before. Member values stay [JsonElement]s whose literals are untouched, so
 * integers stay integers and floats keep their spelling.
 */
internal object CredentialResponseMetadataEntrySerializer : KSerializer<CredentialResponseMetadataEntry> {
    override val descriptor: SerialDescriptor = JsonObject.serializer().descriptor

    override fun deserialize(decoder: Decoder): CredentialResponseMetadataEntry {
        val obj = (decoder as? JsonDecoder ?: throw SerializationException("credential metadata entries decode from JSON only"))
            .decodeJsonElement() as? JsonObject
            ?: throw SerializationException("credential metadata entry is not a JSON object")
        val type = (obj["type"] as? JsonPrimitive)?.takeIf { it.isString }?.content
            ?: throw SerializationException("credential metadata entry has no string type")
        val value = obj["value"] ?: throw SerializationException("credential metadata entry has no value")
        return CredentialResponseMetadataEntry(type, value, JsonObject(obj - "type" - "value"))
    }

    override fun serialize(encoder: Encoder, value: CredentialResponseMetadataEntry) {
        (encoder as? JsonEncoder ?: throw SerializationException("credential metadata entries encode to JSON only"))
            .encodeJsonElement(value.raw)
    }
}

/**
 * The delivered-metadata members shared by both transports' `CredentialResult`
 * DTOs, so wallet code reads them the same way whichever transport carried
 * the result.
 */
interface CredentialResultMetadata {
    /** `credential_metadata`; null when the issuer delivered none. */
    val credentialMetadata: List<CredentialResponseMetadataEntry>?

    /**
     * `credential_metadata_encrypted_response`: true only when metadata is
     * present AND the issuer's response was JWE-decrypted by the engine.
     * Absent means false; metadata with this false came over plain JSON.
     */
    val credentialMetadataEncryptedResponse: Boolean
}
