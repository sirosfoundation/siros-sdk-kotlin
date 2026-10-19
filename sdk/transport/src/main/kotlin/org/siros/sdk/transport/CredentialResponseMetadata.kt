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
    /**
     * True when the wire entry was not a well-formed `{type: non-empty string, value: ...}` object (or
     * the whole `credential_metadata` was not an array). Such a placeholder carries no data: a consumer
     * MUST refuse the issuance rather than store or interpret it. Decoding it as a flag, not an
     * exception, keeps the rest of the frame (notably each credential's `notification_id`) readable so
     * the refusal can be reported to the issuer.
     */
    val malformed: Boolean = false,
) {
    /** The entry as received: `type`, `value` and every additional member, values verbatim. */
    val raw: JsonObject
        get() = JsonObject(additionalMembers + mapOf("type" to JsonPrimitive(type), "value" to value))
}

internal fun malformedCredentialMetadataEntry() =
    CredentialResponseMetadataEntry(type = "", value = kotlinx.serialization.json.JsonNull, malformed = true)

/** Reads one wire entry; anything other than an object with a non-empty string `type` and a `value` is the [malformed] placeholder. */
internal fun decodeCredentialMetadataEntry(element: JsonElement): CredentialResponseMetadataEntry {
    val obj = element as? JsonObject ?: return malformedCredentialMetadataEntry()
    val type = (obj["type"] as? JsonPrimitive)?.takeIf { it.isString }?.content?.takeIf { it.isNotEmpty() }
        ?: return malformedCredentialMetadataEntry()
    val value = obj["value"] ?: return malformedCredentialMetadataEntry()
    return CredentialResponseMetadataEntry(type, value, JsonObject(obj - "type" - "value"))
}

/**
 * Decodes the `credential_metadata` array without ever throwing for its content: a value that is not
 * an array becomes one malformed placeholder, and each bad entry becomes a malformed placeholder, so
 * the frame still decodes and the wallet's refusal path (not a swallowed serializer exception) ends
 * the issuance.
 */
internal object CredentialMetadataListSerializer : KSerializer<List<CredentialResponseMetadataEntry>> {
    override val descriptor: SerialDescriptor = kotlinx.serialization.json.JsonArray.serializer().descriptor

    override fun deserialize(decoder: Decoder): List<CredentialResponseMetadataEntry> {
        val element = (decoder as? JsonDecoder ?: throw SerializationException("credential metadata decodes from JSON only"))
            .decodeJsonElement()
        return when (element) {
            is kotlinx.serialization.json.JsonArray -> element.map(::decodeCredentialMetadataEntry)
            else -> listOf(malformedCredentialMetadataEntry())
        }
    }

    override fun serialize(encoder: Encoder, value: List<CredentialResponseMetadataEntry>) {
        (encoder as? JsonEncoder ?: throw SerializationException("credential metadata encodes to JSON only"))
            .encodeJsonElement(kotlinx.serialization.json.JsonArray(value.map { it.raw }))
    }
}

/**
 * Decodes `credential_metadata_encrypted_response` without ever throwing: only a JSON boolean `true`
 * is true; absent, `false` or any other shape (a string, number, object) is false, which is the safe
 * direction (a secret then is refused as not encrypted) and keeps the frame decodable.
 */
internal object EncryptedResponseFlagSerializer : KSerializer<Boolean> {
    override val descriptor: SerialDescriptor = kotlinx.serialization.descriptors.PrimitiveSerialDescriptor(
        "org.siros.sdk.transport.EncryptedResponseFlag",
        kotlinx.serialization.descriptors.PrimitiveKind.BOOLEAN,
    )

    override fun deserialize(decoder: Decoder): Boolean {
        val element = (decoder as? JsonDecoder ?: throw SerializationException("flag decodes from JSON only"))
            .decodeJsonElement()
        return element is JsonPrimitive && !element.isString && element.content == "true"
    }

    override fun serialize(encoder: Encoder, value: Boolean) = encoder.encodeBoolean(value)
}

/**
 * Decodes an entry from the raw JSON object so unknown members survive
 * (`ignoreUnknownKeys` would otherwise drop them). A bad entry is not an
 * exception here either (see [decodeCredentialMetadataEntry]). Member values stay [JsonElement]s whose literals are untouched, so
 * integers stay integers and floats keep their spelling.
 */
internal object CredentialResponseMetadataEntrySerializer : KSerializer<CredentialResponseMetadataEntry> {
    override val descriptor: SerialDescriptor = JsonObject.serializer().descriptor

    override fun deserialize(decoder: Decoder): CredentialResponseMetadataEntry =
        decodeCredentialMetadataEntry(
            (decoder as? JsonDecoder ?: throw SerializationException("credential metadata entries decode from JSON only"))
                .decodeJsonElement(),
        )

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
