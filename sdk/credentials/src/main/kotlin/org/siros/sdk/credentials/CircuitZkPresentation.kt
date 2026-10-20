// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import java.time.Instant

/**
 * Why encoding, decoding or checking a [CircuitZkPresentation] failed.
 *
 * Every decode rule has its own reason so a caller (and the shared vectors)
 * can tell them apart. None of them says anything about whether a proof is
 * valid: this codec never looks inside `proof`.
 */
enum class CircuitZkPresentationReason {
    /** The base64url form has padding, a non-base64url character, or is not canonical. */
    BAD_BASE64URL,

    /** The bytes are not one well-formed CBOR item (including duplicate map keys). */
    MALFORMED_CBOR,

    /** Bytes remain after the CBOR item. */
    TRAILING_BYTES,

    /** The top-level item is not a map, or `results` is not a map. */
    NOT_A_MAP,

    /** A required key (`circuit_id`, `proof`, `issuer_key_set`, `results`) is absent. */
    MISSING_KEY,

    /** A value has the wrong CBOR type, or a map key is not a text string. */
    WRONG_TYPE,

    /** `issuer_key_set` is an empty list. */
    EMPTY_ISSUER_KEY_SET,

    /** An `issuer_key_set` list element is not a byte string. */
    BAD_ISSUER_KEY_ELEMENT,

    /** `issuer_key_set` is not a list and no decoder hook accepted it. */
    UNSUPPORTED_ISSUER_KEY_SET,

    /** `results` is an empty map. */
    EMPTY_RESULTS,

    /** A pseudonym result is not exactly 32 bytes. */
    BAD_PSEUDONYM_LENGTH,

    /** A non-bytes result is not the simple value `true`. */
    BAD_PREDICATE,

    /** `proof_time` is not a tag-0 text string holding an RFC 3339 date-time. */
    BAD_PROOF_TIME,

    /** Strict mode only: a top-level key the CDDL does not define. */
    UNKNOWN_KEY,

    /** [CircuitZkPresentation.requireResultHandles]: the `results` keys differ from the expected handles. */
    RESULT_HANDLES_MISMATCH,
}

/** Raised on any violation of the `CircuitZkPresentation` rules. The message never contains proof bytes. */
class CircuitZkPresentationError(
    val reason: CircuitZkPresentationReason,
    message: String,
) : SirosException(message, errorCode = "circuit_zk_${reason.name.lowercase()}")

/** One value of `results`: a pseudonym or a predicate outcome. */
sealed interface ResultValue {
    /** `PseudonymValue = bstr .size 32`. */
    class Pseudonym(bytes: ByteArray) : ResultValue {
        /** A copy of the 32 pseudonym bytes. */
        val bytes: ByteArray = bytes.copyOf()

        init {
            if (bytes.size != SIZE) {
                throw CircuitZkPresentationError(
                    CircuitZkPresentationReason.BAD_PSEUDONYM_LENGTH,
                    "A pseudonym is $SIZE bytes, got ${bytes.size}",
                )
            }
        }

        override fun equals(other: Any?) = other is Pseudonym && bytes.contentEquals(other.bytes)

        override fun hashCode() = bytes.contentHashCode()

        override fun toString() = "Pseudonym(${bytes.size} bytes)"

        companion object {
            /** The pseudonym size, in bytes. */
            const val SIZE = 32
        }
    }

    /** `PredicateValue = true`: a predicate that holds. There is no `false`. */
    object Predicate : ResultValue {
        override fun toString() = "Predicate(true)"
    }
}

/**
 * The `issuer_key_set` of a presentation. Its representation is defined by
 * the registry entry of the circuit, so this is a sealed set of variants.
 */
sealed interface IssuerKeySet {
    /** The default representation: `[+ bstr]`, DER-encoded Document Signer certificates. */
    class DerCertificates(certificates: List<ByteArray>) : IssuerKeySet {
        /** The certificates, as copies; never empty. */
        val certificates: List<ByteArray> = certificates.map { it.copyOf() }

        init {
            if (certificates.isEmpty()) {
                throw CircuitZkPresentationError(
                    CircuitZkPresentationReason.EMPTY_ISSUER_KEY_SET,
                    "issuer_key_set has no certificates",
                )
            }
        }

        override fun equals(other: Any?) =
            other is DerCertificates &&
                certificates.size == other.certificates.size &&
                certificates.indices.all { certificates[it].contentEquals(other.certificates[it]) }

        override fun hashCode() = certificates.fold(1) { acc, c -> 31 * acc + c.contentHashCode() }

        override fun toString() = "DerCertificates(${certificates.size})"
    }

    /**
     * A representation this codec does not interpret, produced by an
     * [IssuerKeySetDecoder]. [rawCborItem] is exactly one CBOR data item,
     * which the encoder writes back verbatim.
     */
    class Other(rawCborItem: ByteArray) : IssuerKeySet {
        /** A copy of the encoded CBOR item. */
        val rawCborItem: ByteArray = rawCborItem.copyOf()

        override fun equals(other: Any?) = other is Other && rawCborItem.contentEquals(other.rawCborItem)

        override fun hashCode() = rawCborItem.contentHashCode()

        override fun toString() = "Other(${rawCborItem.size} bytes)"
    }
}

/**
 * Plug-in point for circuits whose `issuer_key_set` is not a list of DER
 * certificates.
 *
 * [CircuitZkPresentationCodec.decode] calls it with the presentation's
 * `circuit_id` and the encoded `issuer_key_set` item. Return the decoded
 * set, or `null` to leave the item to the default `[+ bstr]` rule. Throw
 * [CircuitZkPresentationError] to reject it; any other exception is also
 * turned into a rejection.
 */
fun interface IssuerKeySetDecoder {
    /** See the interface. */
    fun decode(circuitId: String, rawCborItem: ByteArray): IssuerKeySet?
}

/**
 * SUPERSEDED on the wire: a `circuit_zk` response is now the JSON shape of [CircuitZkResponsePresentation]
 * (`vp_token[queryId]` an array of `{circuit_id, proof_system, proof, x5chain, results}` objects; there is no
 * `proof_time` member). This CBOR form is no longer produced by the wallet; it remains for hosts and vectors that
 * still read it.
 *
 * A `circuit_zk` presentation, per the rulebook's `CircuitZkPresentation`
 * CDDL. Generic: nothing here names a credential type, a circuit or a verifier.
 *
 * @property circuitId An opaque string. The caller checks it against the
 *   circuit catalog; the codec never does.
 * @property proof The proof, as defined by the proof system. Never interpreted here.
 * @property issuerKeySet The issuer keys the proof was made against.
 * @property proofTime The time the circuit used for validity checks, if it did.
 * @property results The result per `return` handle; never empty.
 * @property unknownEntries Top-level entries the CDDL does not define, kept
 *   as `key -> encoded CBOR value` so a decode followed by an encode loses nothing.
 */
class CircuitZkPresentation(
    val circuitId: String,
    proof: ByteArray,
    val issuerKeySet: IssuerKeySet,
    val proofTime: Instant?,
    results: Map<String, ResultValue>,
    unknownEntries: Map<String, ByteArray> = emptyMap(),
) {
    val proof: ByteArray = proof.copyOf()
    val results: Map<String, ResultValue> = LinkedHashMap(results)
    val unknownEntries: Map<String, ByteArray> = unknownEntries.mapValuesTo(LinkedHashMap()) { it.value.copyOf() }

    init {
        if (results.isEmpty()) {
            throw CircuitZkPresentationError(CircuitZkPresentationReason.EMPTY_RESULTS, "results is empty")
        }
        for (key in unknownEntries.keys) {
            if (key in CircuitZkPresentationCodec.KNOWN_KEYS) {
                throw CircuitZkPresentationError(
                    CircuitZkPresentationReason.UNKNOWN_KEY,
                    "'$key' is a defined key, not an unknown entry",
                )
            }
        }
    }

    /**
     * Opt-in check of the rule that the `results` keys are exactly the
     * request's `return` handles: throws [CircuitZkPresentationReason.RESULT_HANDLES_MISMATCH]
     * on any missing or additional key. Never applied by the decoder, which
     * cannot know the handles.
     */
    fun requireResultHandles(expected: Set<String>) {
        val missing = expected - results.keys
        val extra = results.keys - expected
        if (missing.isNotEmpty() || extra.isNotEmpty()) {
            throw CircuitZkPresentationError(
                CircuitZkPresentationReason.RESULT_HANDLES_MISMATCH,
                "results handles differ from the request's: missing ${missing.sorted()}, additional ${extra.sorted()}",
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (other !is CircuitZkPresentation) return false
        return circuitId == other.circuitId &&
            proof.contentEquals(other.proof) &&
            issuerKeySet == other.issuerKeySet &&
            proofTime == other.proofTime &&
            results == other.results &&
            unknownEntries.keys == other.unknownEntries.keys &&
            unknownEntries.all { (k, v) -> v.contentEquals(other.unknownEntries.getValue(k)) }
    }

    override fun hashCode(): Int = 31 * circuitId.hashCode() + proof.contentHashCode()

    override fun toString() = "CircuitZkPresentation(circuitId=$circuitId, results=${results.keys})"
}
