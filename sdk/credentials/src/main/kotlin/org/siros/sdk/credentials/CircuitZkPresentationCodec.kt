// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import com.upokecenter.cbor.CBOREncodeOptions
import com.upokecenter.cbor.CBORException
import com.upokecenter.cbor.CBORObject
import com.upokecenter.cbor.CBORType
import java.io.ByteArrayInputStream
import java.time.Instant
import java.time.OffsetDateTime
import java.time.format.DateTimeParseException
import java.util.Base64

/**
 * Encoder and strict decoder for [CircuitZkPresentation], per the rulebook's
 * "Presentation encoding" CDDL:
 *
 * ```
 * CircuitZkPresentation = {
 *   "circuit_id" => tstr, "proof" => bstr, "issuer_key_set" => IssuerKeySet,
 *   ? "proof_time" => tdate, "results" => { + tstr => ResultValue } }
 * ResultValue = bstr .size 32 / true
 * ```
 *
 * In a `vp_token` a presentation is the base64url encoding, without padding,
 * of this CBOR ([encodeBase64Url]). Stateless and pure.
 *
 * Encoding order is fixed: `circuit_id`, `proof`, `issuer_key_set`,
 * `proof_time` (when present, CBOR tag 0), `results` (keys sorted by their
 * UTF-8 bytes), then [CircuitZkPresentation.unknownEntries] in their order.
 */
object CircuitZkPresentationCodec {
    private const val K_CIRCUIT_ID = "circuit_id"
    private const val K_PROOF = "proof"
    private const val K_ISSUER_KEY_SET = "issuer_key_set"
    private const val K_PROOF_TIME = "proof_time"
    private const val K_RESULTS = "results"
    private const val TAG_DATE_TIME = 0

    /** The top-level keys the CDDL defines. */
    internal val KNOWN_KEYS = setOf(K_CIRCUIT_ID, K_PROOF, K_ISSUER_KEY_SET, K_PROOF_TIME, K_RESULTS)

    // Duplicate map keys are rejected (the default); key order is kept so unknown entries round-trip.
    private val DECODE_OPTIONS = CBOREncodeOptions("keepkeyorder=true")

    /** The CBOR encoding of [presentation]. */
    fun encode(presentation: CircuitZkPresentation): ByteArray {
        val map = CBORObject.NewOrderedMap()
        map[K_CIRCUIT_ID] = CBORObject.FromObject(presentation.circuitId)
        map[K_PROOF] = CBORObject.FromObject(presentation.proof)
        map[K_ISSUER_KEY_SET] = when (val set = presentation.issuerKeySet) {
            is IssuerKeySet.DerCertificates -> CBORObject.NewArray().also { a ->
                set.certificates.forEach { a.Add(CBORObject.FromObject(it)) }
            }
            is IssuerKeySet.Other -> decodeOne(set.rawCborItem)
        }
        presentation.proofTime?.let {
            map[K_PROOF_TIME] = CBORObject.FromObjectAndTag(it.toString(), TAG_DATE_TIME)
        }
        val results = CBORObject.NewOrderedMap()
        presentation.results.entries
            .sortedWith { a, b -> compareUtf8(a.key, b.key) }
            .forEach { (handle, value) ->
                results[handle] = when (value) {
                    is ResultValue.Pseudonym -> CBORObject.FromObject(value.bytes)
                    ResultValue.Predicate -> CBORObject.True
                }
            }
        map[K_RESULTS] = results
        for ((key, raw) in presentation.unknownEntries) map[key] = decodeOne(raw)
        return map.EncodeToBytes()
    }

    /** [encode], then base64url without padding: the `vp_token` form. */
    fun encodeBase64Url(presentation: CircuitZkPresentation): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(encode(presentation))

    /**
     * Decodes [bytes], failing closed on anything the CDDL does not allow.
     *
     * @param strict Reject unknown top-level keys instead of preserving them.
     * @param issuerKeySetDecoder Optional hook for `issuer_key_set` representations other than `[+ bstr]`.
     *   Without it, an `issuer_key_set` that is not a list is [CircuitZkPresentationReason.UNSUPPORTED_ISSUER_KEY_SET].
     * @throws CircuitZkPresentationError on any violation.
     */
    fun decode(
        bytes: ByteArray,
        strict: Boolean = false,
        issuerKeySetDecoder: IssuerKeySetDecoder? = null,
    ): CircuitZkPresentation {
        val root = decodeOne(bytes, rejectTrailing = true)
        if (root.isTagged || root.type != CBORType.Map) fail(CircuitZkPresentationReason.NOT_A_MAP, "A presentation is a CBOR map")

        var circuitId: String? = null
        var proof: ByteArray? = null
        var keySetItem: CBORObject? = null
        var proofTimeItem: CBORObject? = null
        var resultsItem: CBORObject? = null
        val unknown = LinkedHashMap<String, ByteArray>()
        for (key in root.keys) {
            val name = textKey(key, "top-level")
            val value = root[key]
            when (name) {
                K_CIRCUIT_ID -> circuitId = text(value, K_CIRCUIT_ID)
                K_PROOF -> proof = bytes(value, K_PROOF)
                K_ISSUER_KEY_SET -> keySetItem = value
                K_PROOF_TIME -> proofTimeItem = value
                K_RESULTS -> resultsItem = value
                else -> {
                    if (strict) fail(CircuitZkPresentationReason.UNKNOWN_KEY, "Unknown top-level key '$name'")
                    unknown[name] = value.EncodeToBytes()
                }
            }
        }
        val id = circuitId ?: missing(K_CIRCUIT_ID)
        val keySet = decodeIssuerKeySet(id, keySetItem ?: missing(K_ISSUER_KEY_SET), issuerKeySetDecoder)
        return CircuitZkPresentation(
            circuitId = id,
            proof = proof ?: missing(K_PROOF),
            issuerKeySet = keySet,
            proofTime = proofTimeItem?.let(::proofTime),
            results = decodeResults(resultsItem ?: missing(K_RESULTS)),
            unknownEntries = unknown,
        )
    }

    /**
     * [decode] of the `vp_token` form: base64url without padding.
     *
     * @throws CircuitZkPresentationError [CircuitZkPresentationReason.BAD_BASE64URL] on padding, a
     *   non-base64url character or a non-canonical encoding, otherwise as [decode].
     */
    fun decodeBase64Url(
        encoded: String,
        strict: Boolean = false,
        issuerKeySetDecoder: IssuerKeySetDecoder? = null,
    ): CircuitZkPresentation {
        if (!encoded.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }) {
            fail(CircuitZkPresentationReason.BAD_BASE64URL, "Not unpadded base64url")
        }
        val raw = try {
            Base64.getUrlDecoder().decode(encoded)
        } catch (e: IllegalArgumentException) {
            throw CircuitZkPresentationError(CircuitZkPresentationReason.BAD_BASE64URL, "Not unpadded base64url")
        }
        // Rejects non-zero trailing bits, which the JDK decoder tolerates.
        if (Base64.getUrlEncoder().withoutPadding().encodeToString(raw) != encoded) {
            fail(CircuitZkPresentationReason.BAD_BASE64URL, "Non-canonical base64url")
        }
        return decode(raw, strict, issuerKeySetDecoder)
    }

    private fun decodeIssuerKeySet(circuitId: String, item: CBORObject, hook: IssuerKeySetDecoder?): IssuerKeySet {
        if (hook != null) {
            val hooked = try {
                hook.decode(circuitId, item.EncodeToBytes())
            } catch (e: CircuitZkPresentationError) {
                throw e
            } catch (e: Exception) {
                fail(CircuitZkPresentationReason.UNSUPPORTED_ISSUER_KEY_SET, "issuer_key_set decoder failed: ${e.javaClass.simpleName}")
            }
            if (hooked != null) return hooked
        }
        if (item.isTagged || item.type != CBORType.Array) {
            fail(CircuitZkPresentationReason.UNSUPPORTED_ISSUER_KEY_SET, "issuer_key_set is not a list and no decoder accepted it")
        }
        if (item.size() == 0) fail(CircuitZkPresentationReason.EMPTY_ISSUER_KEY_SET, "issuer_key_set is empty")
        val certs = (0 until item.size()).map { i ->
            val element = item[i]
            if (element.isTagged || element.type != CBORType.ByteString) {
                fail(CircuitZkPresentationReason.BAD_ISSUER_KEY_ELEMENT, "issuer_key_set element $i is not a byte string")
            }
            element.GetByteString()
        }
        return IssuerKeySet.DerCertificates(certs)
    }

    private fun decodeResults(item: CBORObject): Map<String, ResultValue> {
        if (item.isTagged || item.type != CBORType.Map) fail(CircuitZkPresentationReason.NOT_A_MAP, "results is not a map")
        if (item.size() == 0) fail(CircuitZkPresentationReason.EMPTY_RESULTS, "results is empty")
        val out = LinkedHashMap<String, ResultValue>()
        for (key in item.keys) {
            val handle = textKey(key, "results")
            val value = item[key]
            out[handle] = when {
                value.isTagged -> fail(CircuitZkPresentationReason.WRONG_TYPE, "result '$handle' is tagged")
                value.type == CBORType.ByteString -> ResultValue.Pseudonym(value.GetByteString())
                value.isTrue -> ResultValue.Predicate
                value.type == CBORType.Boolean || value.isNull || value.isUndefined || value.type == CBORType.SimpleValue ->
                    fail(CircuitZkPresentationReason.BAD_PREDICATE, "result '$handle' is a simple value other than true")
                else -> fail(CircuitZkPresentationReason.WRONG_TYPE, "result '$handle' is neither a byte string nor true")
            }
        }
        return out
    }

    private fun proofTime(item: CBORObject): Instant {
        if (item.tagCount != 1 || !item.HasMostOuterTag(TAG_DATE_TIME)) {
            fail(CircuitZkPresentationReason.BAD_PROOF_TIME, "proof_time is not a tag-0 date-time")
        }
        val untagged = item.UntagOne()
        if (untagged.isTagged || untagged.type != CBORType.TextString) {
            fail(CircuitZkPresentationReason.BAD_PROOF_TIME, "proof_time is not a text string")
        }
        return try {
            OffsetDateTime.parse(untagged.AsString()).toInstant()
        } catch (e: DateTimeParseException) {
            throw CircuitZkPresentationError(CircuitZkPresentationReason.BAD_PROOF_TIME, "proof_time is not an RFC 3339 date-time")
        }
    }

    private fun textKey(key: CBORObject, where: String): String {
        if (key.isTagged || key.type != CBORType.TextString) {
            fail(CircuitZkPresentationReason.WRONG_TYPE, "A $where map key is not a text string")
        }
        return key.AsString()
    }

    private fun text(item: CBORObject, name: String): String {
        if (item.isTagged || item.type != CBORType.TextString) fail(CircuitZkPresentationReason.WRONG_TYPE, "$name is not a text string")
        return item.AsString()
    }

    private fun bytes(item: CBORObject, name: String): ByteArray {
        if (item.isTagged || item.type != CBORType.ByteString) fail(CircuitZkPresentationReason.WRONG_TYPE, "$name is not a byte string")
        return item.GetByteString()
    }

    private fun decodeOne(bytes: ByteArray, rejectTrailing: Boolean = true): CBORObject {
        val input = ByteArrayInputStream(bytes)
        val item = try {
            CBORObject.Read(input, DECODE_OPTIONS)
        } catch (e: CBORException) {
            throw CircuitZkPresentationError(CircuitZkPresentationReason.MALFORMED_CBOR, "Not well-formed CBOR")
        }
        if (rejectTrailing && input.available() > 0) {
            fail(CircuitZkPresentationReason.TRAILING_BYTES, "${input.available()} bytes follow the CBOR item")
        }
        return item
    }

    private fun missing(key: String): Nothing = fail(CircuitZkPresentationReason.MISSING_KEY, "Missing required key '$key'")

    private fun fail(reason: CircuitZkPresentationReason, message: String): Nothing =
        throw CircuitZkPresentationError(reason, message)

    private fun compareUtf8(a: String, b: String): Int {
        val x = a.toByteArray(Charsets.UTF_8)
        val y = b.toByteArray(Charsets.UTF_8)
        for (i in 0 until minOf(x.size, y.size)) {
            val d = (x[i].toInt() and 0xff) - (y[i].toInt() and 0xff)
            if (d != 0) return d
        }
        return x.size - y.size
    }
}
