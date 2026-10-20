// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import java.util.Base64
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

/**
 * One presentation of a `circuit_zk` credential query, in the wire shape of siros-dc-matcher's
 * `docs/circuit_zk_response.md`: `vp_token[queryId]` is an ARRAY of these objects,
 * `{circuit_id, proof_system, proof, x5chain, results}`. Exactly those five members, no other.
 *
 * @property circuitId A `circuit_id` the request offered (`circuit_id_values`).
 * @property proofSystem A `proof_system` the request offered (`circuit_proof_system_values`).
 * @property proof The proof bytes; written base64url without padding.
 * @property x5chain The issuer certificate chain, DER, leaf (Document Signer) first, from the credential's own
 *   `issuerAuth` `x5chain`: at most [MAX_CERTS] certificates of at most [MAX_CERT_BYTES] bytes. Written as standard
 *   base64 with padding. The verifier validates it through its trust evaluation and takes the issuer key from the leaf.
 * @property results One result per `return` handle of the request, none skipped.
 */
class CircuitZkResponsePresentation(
    val circuitId: String,
    val proofSystem: String,
    proof: ByteArray,
    x5chain: List<ByteArray>,
    results: Map<String, ResultValue>,
) {
    val proof: ByteArray = proof.copyOf()
    val x5chain: List<ByteArray> = x5chain.map { it.copyOf() }
    val results: Map<String, ResultValue> = LinkedHashMap(results)

    init {
        require(circuitId.isNotEmpty() && proofSystem.isNotEmpty()) { "circuit_id and proof_system are non-empty" }
        require(proof.isNotEmpty()) { "an empty proof" }
        require(x5chain.size in 1..MAX_CERTS) { "x5chain has ${x5chain.size} certificates (1..$MAX_CERTS)" }
        require(x5chain.all { it.size in 1..MAX_CERT_BYTES }) { "an x5chain certificate is empty or over $MAX_CERT_BYTES bytes" }
        require(results.isNotEmpty()) { "no results" }
    }

    /** The JSON object of this presentation. */
    fun toJson(): JsonObject = buildJsonObject {
        put("circuit_id", JsonPrimitive(circuitId))
        put("proof_system", JsonPrimitive(proofSystem))
        put("proof", JsonPrimitive(B64URL.encodeToString(proof)))
        put("x5chain", JsonArray(x5chain.map { JsonPrimitive(Base64.getEncoder().encodeToString(it)) }))
        put(
            "results",
            JsonObject(
                results.entries.associate { (handle, value) ->
                    handle to when (value) {
                        is ResultValue.Pseudonym -> buildJsonObject { put("pseudonym", JsonPrimitive(B64URL.encodeToString(value.bytes))) }
                        ResultValue.Predicate -> buildJsonObject { put("satisfied", JsonPrimitive(true)) }
                    }
                },
            ),
        )
    }

    override fun toString() = "CircuitZkResponsePresentation(circuitId=$circuitId, results=${results.keys})"

    companion object {
        /** Most certificates an `x5chain` may carry. */
        const val MAX_CERTS = 8

        /** Largest certificate of an `x5chain`, in DER bytes. */
        const val MAX_CERT_BYTES = 4096

        private val B64URL = Base64.getUrlEncoder().withoutPadding()
    }
}

/**
 * The stable refusal codes of the `circuit_zk` response conformance vectors
 * (`spec/circuit-zk-response-vectors`, from siros-dc-matcher `tests/vectors/circuit_zk_response`).
 */
enum class CircuitZkResponseError(val code: String) {
    RESPONSE_NOT_PARSEABLE("response_not_parseable"),
    DUPLICATE_MEMBER("duplicate_member"),
    QUERY_ID_MISSING("query_id_missing"),
    PRESENTATIONS_NOT_ARRAY("presentations_not_array"),
    PRESENTATIONS_EMPTY("presentations_empty"),
    PRESENTATIONS_MULTIPLE_NOT_ALLOWED("presentations_multiple_not_allowed"),
    PRESENTATION_NOT_OBJECT("presentation_not_object"),
    PRESENTATION_ERROR_MEMBER("presentation_error_member"),
    PRESENTATION_UNKNOWN_MEMBER("presentation_unknown_member"),
    PRESENTATION_MEMBER_MISSING("presentation_member_missing"),
    PRESENTATION_MEMBER_WRONG_TYPE("presentation_member_wrong_type"),
    CIRCUIT_ID_NOT_OFFERED("circuit_id_not_offered"),
    PROOF_SYSTEM_NOT_OFFERED("proof_system_not_offered"),
    X5CHAIN_NOT_ARRAY("x5chain_not_array"),
    X5CHAIN_EMPTY("x5chain_empty"),
    X5CHAIN_TOO_MANY("x5chain_too_many"),
    X5CHAIN_ELEMENT_NOT_STRING("x5chain_element_not_string"),
    X5CHAIN_ELEMENT_NOT_BASE64("x5chain_element_not_base64"),
    X5CHAIN_ELEMENT_EMPTY("x5chain_element_empty"),
    X5CHAIN_ELEMENT_TOO_LARGE("x5chain_element_too_large"),
    PROOF_EMPTY("proof_empty"),
    PROOF_NOT_BASE64URL("proof_not_base64url"),
    DUPLICATE_HANDLE("duplicate_handle"),
    RESULT_HANDLE_MISSING("result_handle_missing"),
    RESULT_HANDLE_UNEXPECTED("result_handle_unexpected"),
    RESULT_NOT_OBJECT("result_not_object"),
    RESULT_FUNCTION_UNKNOWN("result_function_unknown"),
    RESULT_UNKNOWN_MEMBER("result_unknown_member"),
    RESULT_MEMBER_MISSING("result_member_missing"),
    RESULT_MEMBER_WRONG_TYPE("result_member_wrong_type"),
    RESULT_NOT_SATISFIED("result_not_satisfied"),
    PSEUDONYM_NOT_BASE64URL("pseudonym_not_base64url"),
    PSEUDONYM_WRONG_LENGTH("pseudonym_wrong_length"),
}

/**
 * Checks the `circuit_zk` entry of a `vp_token` against the request it answers: shape and binding to the request, not the
 * proof (a mirror of siros-dc-matcher's `circuit_zk_response::validate_response`; the first rule broken, in the spec's order,
 * is the one reported). The wallet runs it on the response it built, so it never sends one a verifier must refuse. Strict
 * everywhere: a JSON `null` is a type error, a repeated member is refused, no item type is skipped (a request item whose
 * function has no result shape refuses the response).
 *
 * @param predicateFunctionIds Ids of the predicate functions whose result is `{"satisfied": true}` (default: `age_check`).
 */
object CircuitZkResponseValidator {
    private val MEMBERS = listOf("circuit_id", "proof_system", "proof", "x5chain", "results")
    private const val PSEUDONYM_BYTES = 32

    /** The first rule [vpTokenText] breaks against [plan] (the query is `plan.raw`), or null when it is valid. */
    fun validate(
        plan: CircuitZkPlan,
        vpTokenText: String,
        predicateFunctionIds: Set<String> = setOf(CircuitZkRuleSet.AGE_CHECK),
    ): CircuitZkResponseError? {
        val token = StrictJson.parse(vpTokenText) as? StrictJson.Obj ?: return CircuitZkResponseError.RESPONSE_NOT_PARSEABLE
        val members = unique(token) ?: return CircuitZkResponseError.DUPLICATE_MEMBER
        val queryId = (plan.raw["id"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return CircuitZkResponseError.QUERY_ID_MISSING
        val entry = members.firstOrNull { it.first == queryId }?.second ?: return CircuitZkResponseError.QUERY_ID_MISSING
        val presentations = (entry as? StrictJson.Arr)?.items ?: return CircuitZkResponseError.PRESENTATIONS_NOT_ARRAY
        if (presentations.isEmpty()) return CircuitZkResponseError.PRESENTATIONS_EMPTY
        // DCQL: `multiple` omitted means false, i.e. at most one presentation.
        if (presentations.size > 1 && (plan.raw["multiple"] as? JsonPrimitive)?.takeIf { !it.isString }?.content != "true") {
            return CircuitZkResponseError.PRESENTATIONS_MULTIPLE_NOT_ALLOWED
        }
        for (p in presentations) checkPresentation(plan, p, predicateFunctionIds)?.let { return it }
        return null
    }

    /** The members of [obj], or null when a name repeats. */
    private fun unique(obj: StrictJson.Obj): List<Pair<String, StrictJson>>? =
        obj.members.takeIf { m -> m.map { it.first }.toSet().size == m.size }

    private fun checkPresentation(plan: CircuitZkPlan, p: StrictJson, predicates: Set<String>): CircuitZkResponseError? {
        val obj = p as? StrictJson.Obj ?: return CircuitZkResponseError.PRESENTATION_NOT_OBJECT
        val members = unique(obj) ?: return CircuitZkResponseError.DUPLICATE_MEMBER
        if (members.any { it.first == "error" || it.first == "error_description" }) return CircuitZkResponseError.PRESENTATION_ERROR_MEMBER
        if (members.any { it.first !in MEMBERS }) return CircuitZkResponseError.PRESENTATION_UNKNOWN_MEMBER
        fun get(name: String) = members.firstOrNull { it.first == name }?.second
        for (m in MEMBERS) if (get(m) == null) return CircuitZkResponseError.PRESENTATION_MEMBER_MISSING
        fun string(name: String) = (get(name) as? StrictJson.Str)?.value
        val circuitId = string("circuit_id") ?: return CircuitZkResponseError.PRESENTATION_MEMBER_WRONG_TYPE
        val proofSystem = string("proof_system") ?: return CircuitZkResponseError.PRESENTATION_MEMBER_WRONG_TYPE
        val proof = string("proof") ?: return CircuitZkResponseError.PRESENTATION_MEMBER_WRONG_TYPE
        val x5chain = (get("x5chain") as? StrictJson.Arr)?.items ?: return CircuitZkResponseError.X5CHAIN_NOT_ARRAY
        val results = get("results") as? StrictJson.Obj ?: return CircuitZkResponseError.PRESENTATION_MEMBER_WRONG_TYPE

        // Fail closed: a request that stated no list offered nothing to match.
        if (plan.circuitFilter?.circuitIds?.contains(circuitId) != true) return CircuitZkResponseError.CIRCUIT_ID_NOT_OFFERED
        if (plan.circuitFilter?.proofSystems?.contains(proofSystem) != true) return CircuitZkResponseError.PROOF_SYSTEM_NOT_OFFERED
        if (proof.isEmpty()) return CircuitZkResponseError.PROOF_EMPTY
        if (!isUnpaddedBase64Url(proof)) return CircuitZkResponseError.PROOF_NOT_BASE64URL
        checkX5chain(x5chain)?.let { return it }
        return checkResults(plan, results, predicates)
    }

    private fun checkX5chain(chain: List<StrictJson>): CircuitZkResponseError? {
        if (chain.isEmpty()) return CircuitZkResponseError.X5CHAIN_EMPTY
        if (chain.size > CircuitZkResponsePresentation.MAX_CERTS) return CircuitZkResponseError.X5CHAIN_TOO_MANY
        for (element in chain) {
            val text = (element as? StrictJson.Str)?.value ?: return CircuitZkResponseError.X5CHAIN_ELEMENT_NOT_STRING
            if (text.isEmpty()) return CircuitZkResponseError.X5CHAIN_ELEMENT_EMPTY
            val length = paddedBase64DecodedLength(text) ?: return CircuitZkResponseError.X5CHAIN_ELEMENT_NOT_BASE64
            if (length > CircuitZkResponsePresentation.MAX_CERT_BYTES) return CircuitZkResponseError.X5CHAIN_ELEMENT_TOO_LARGE
        }
        return null
    }

    private fun checkResults(plan: CircuitZkPlan, results: StrictJson.Obj, predicates: Set<String>): CircuitZkResponseError? {
        val entries = results.members
        if (entries.map { it.first }.toSet().size != entries.size) return CircuitZkResponseError.DUPLICATE_HANDLE
        val wanted = plan.functions.map { it.handle }.toSet()
        if (entries.any { it.first !in wanted }) return CircuitZkResponseError.RESULT_HANDLE_UNEXPECTED
        // Every handle is present before any value is judged.
        if (plan.functions.any { f -> entries.none { it.first == f.handle } }) return CircuitZkResponseError.RESULT_HANDLE_MISSING
        for (function in plan.functions) {
            val value = entries.first { it.first == function.handle }.second
            val obj = value as? StrictJson.Obj ?: return CircuitZkResponseError.RESULT_NOT_OBJECT
            val members = unique(obj) ?: return CircuitZkResponseError.DUPLICATE_MEMBER
            when {
                function.id == CircuitZkRuleSet.PSEUDONYM -> checkPseudonym(members)?.let { return it }
                function.id in predicates -> checkSatisfied(members)?.let { return it }
                else -> return CircuitZkResponseError.RESULT_FUNCTION_UNKNOWN
            }
        }
        return null
    }

    /** The one member a result object may have, or the reason it cannot. */
    private fun sole(members: List<Pair<String, StrictJson>>, name: String): Pair<StrictJson?, CircuitZkResponseError?> {
        if (members.any { it.first != name }) return null to CircuitZkResponseError.RESULT_UNKNOWN_MEMBER
        val v = members.firstOrNull { it.first == name }?.second ?: return null to CircuitZkResponseError.RESULT_MEMBER_MISSING
        return v to null
    }

    private fun checkPseudonym(members: List<Pair<String, StrictJson>>): CircuitZkResponseError? {
        val (value, error) = sole(members, "pseudonym")
        if (error != null) return error
        val text = (value as? StrictJson.Str)?.value ?: return CircuitZkResponseError.RESULT_MEMBER_WRONG_TYPE
        if (!isUnpaddedBase64Url(text)) return CircuitZkResponseError.PSEUDONYM_NOT_BASE64URL
        val bytes = Base64.getUrlDecoder().decode(text).size
        return if (bytes != PSEUDONYM_BYTES) CircuitZkResponseError.PSEUDONYM_WRONG_LENGTH else null
    }

    private fun checkSatisfied(members: List<Pair<String, StrictJson>>): CircuitZkResponseError? {
        val (value, error) = sole(members, "satisfied")
        if (error != null) return error
        return when ((value as? StrictJson.Bool)?.value) {
            true -> null
            false -> CircuitZkResponseError.RESULT_NOT_SATISFIED
            null -> CircuitZkResponseError.RESULT_MEMBER_WRONG_TYPE
        }
    }

    /** Strict unpadded base64url (alphabet `A-Z a-z 0-9 - _`, canonical final character), not decoded. */
    internal fun isUnpaddedBase64Url(s: String): Boolean {
        if (s.length % 4 == 1 || !s.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }) return false
        val last = s.lastOrNull() ?: return true
        val v = when (last) {
            in 'A'..'Z' -> last - 'A'
            in 'a'..'z' -> last - 'a' + 26
            in '0'..'9' -> last - '0' + 52
            '-' -> 62
            else -> 63
        }
        return when (s.length % 4) {
            2 -> v and 0x0F == 0
            3 -> v and 0x03 == 0
            else -> true
        }
    }

    /** Decoded length of strict padded standard base64 (RFC 4648 section 4), or null when [s] is not exactly that. */
    internal fun paddedBase64DecodedLength(s: String): Int? {
        if (s.isEmpty() || s.length % 4 != 0) return null
        val pad = s.reversed().takeWhile { it == '=' }.length
        if (pad > 2) return null
        val body = s.substring(0, s.length - pad)
        fun value(c: Char): Int? = when (c) {
            in 'A'..'Z' -> c - 'A'
            in 'a'..'z' -> c - 'a' + 26
            in '0'..'9' -> c - '0' + 52
            '+' -> 62
            '/' -> 63
            else -> null
        }
        if (!body.all { value(it) != null }) return null
        val last = value(body.last())!!
        val canonical = when (pad) {
            1 -> last and 0x03 == 0
            2 -> last and 0x0F == 0
            else -> true
        }
        return if (canonical) s.length / 4 * 3 - pad else null
    }
}
