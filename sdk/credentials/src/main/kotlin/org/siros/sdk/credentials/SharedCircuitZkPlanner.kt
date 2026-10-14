// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import java.util.Base64
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import timber.log.Timber
import uniffi.siros_dc_matcher_ffi.FfiCapability
import uniffi.siros_dc_matcher_ffi.FfiCredential
import uniffi.siros_dc_matcher_ffi.MatchException
import uniffi.siros_dc_matcher_ffi.SirosBlobBuilder
import uniffi.siros_dc_matcher_ffi.matchDcqlWithContext

/**
 * The [CircuitZkPlanner] backed by the shared matcher: the same planner the OS
 * credential picker runs, so the wallet and the picker cannot read a
 * `circuit_zk` request differently.
 *
 * ## How it reaches the planner
 *
 * The matcher (0.8.0) does not export its planner over the FFI. It exports
 * matching, and a `circuit_zk` match carries the plan it was made under
 * (`FfiMatchedCredential.circuitZk`). So this builds a throwaway blob holding
 * one probe credential and one probe circuit chosen to satisfy the request's
 * own constraints, asks the matcher to match the query, and reads the plan back
 * out of the match. The matcher's answer is the plan's only source: this class
 * never parses a function or a parameter itself.
 *
 * The probe needs two things from the request, and only these are read here:
 * `meta.doctype_value` (the probe credential is of that type, or of a dummy
 * type when the request names none) and the first entries of the verifier's
 * circuit lists in `client_metadata` (the probe circuit is that system and
 * id). Both are seeds. If a seed is wrong the matcher finds no match and the
 * request is [CircuitZkPlanResult.InvalidRequest], which fails closed; no seed
 * can make a defective request plan.
 *
 * ## Known limits of probing
 *
 *  - A request whose circuit lists are present but empty is well-formed (the
 *    matcher plans it, and nothing can satisfy it), yet no probe circuit can
 *    satisfy it, so it is reported as invalid. Both end in a refusal.
 *  - `meta.vct_values: []` is treated the same way, for the same reason.
 *  - A query with no `id` is reported as invalid: the matcher's DCQL reader
 *    needs one, and every query that reaches a wallet has one.
 *
 * All of this goes away if the matcher exports `circuit_zk::plan` directly.
 */
class SharedCircuitZkPlanner : CircuitZkPlanner {

    override fun plan(credentialQuery: JsonObject, clientMetadata: JsonObject?): CircuitZkPlanResult {
        val planJson = try {
            planJson(credentialQuery, clientMetadata)
        } catch (e: LinkageError) {
            // A native library missing for this ABI is an Error, which the
            // caller's `catch (Exception)` would let through. Not "invalid".
            throw IllegalStateException("The shared matcher is not available", e)
        } ?: return CircuitZkPlanResult.InvalidRequest
        return try {
            CircuitZkPlanResult.Plan(toPlan(planJson))
        } catch (e: IllegalArgumentException) {
            Timber.w(e, "The matcher's plan is not in the shape this SDK reads")
            CircuitZkPlanResult.InvalidRequest
        }
    }

    internal companion object {
        private const val PROBE_DOCTYPE = "urn:siros:circuit-zk-probe"
        private const val PROBE_SYSTEM = "probe-system"
        private const val PROBE_CIRCUIT = "probe-circuit"
        private val json = Json

        /**
         * The matcher's plan for [query], as the JSON it serialises
         * (`functions`, `circuit_filter`, `meta_doctype`, `raw`), or null when
         * the matcher does not plan it. Throws when the native library is
         * unavailable.
         */
        fun planJson(query: JsonObject, clientMetadata: JsonObject?): JsonObject? {
            if (query["id"] !is JsonPrimitive) return null
            val meta = query["meta"] as? JsonObject
            val doctype = (meta?.get("doctype_value") as? JsonPrimitive)?.takeIf { it.isString }?.content
            val vct = ((meta?.get("vct_values") as? JsonArray)?.firstOrNull() as? JsonPrimitive)
                ?.takeIf { it.isString }?.content
            val seed = circuitSeed(clientMetadata)

            val blob = SirosBlobBuilder().use { builder ->
                builder.addCircuitZkSystem(
                    FfiCapability(seed.first, mapOf("circuit_id" to seed.second)),
                )
                builder.addCredential(
                    FfiCredential(
                        id = "probe",
                        format = "mso_mdoc",
                        doctype = doctype ?: PROBE_DOCTYPE,
                        vct = vct,
                        title = "probe",
                        subtitle = "",
                        iconId = null,
                        claims = emptyList(),
                    ),
                )
                builder.build()
            }
            val dcql = JsonObject(mapOf("credentials" to JsonArray(listOf(query)))).toString()
            val outcome = try {
                matchDcqlWithContext(blob, dcql, clientMetadata?.toString())
            } catch (e: MatchException) {
                return null
            }
            if (!outcome.satisfiable) return null
            val member = outcome.combinations.firstOrNull()?.members?.firstOrNull() ?: return null
            val selection = json.parseToJsonElement(member.circuitZk ?: return null) as? JsonObject ?: return null
            return selection["plan"] as? JsonObject
        }

        /**
         * A (proof system, circuit id) the verifier's lists admit: the first of
         * each list that was sent, anything for one that was not. The lists
         * may arrive plain or in the envelope the rulebook example uses
         * (`{fn_id, input: base64(json)}`); an unreadable one yields the
         * placeholders, which the matcher then declines or rejects itself.
         */
        fun circuitSeed(clientMetadata: JsonObject?): Pair<String, String> {
            val circuitZk = ((clientMetadata?.get("vp_formats_supported") as? JsonObject)?.get("circuit_zk")) as? JsonObject
            val lists = circuitZk?.let { entry ->
                if (entry.containsKey("input")) decodeEnvelope(entry["input"]) else entry
            }
            fun first(key: String, fallback: String) =
                (lists?.get(key) as? JsonArray)?.firstOrNull()?.let { (it as? JsonPrimitive)?.contentOrNull } ?: fallback
            return first("circuit_proof_system_values", PROBE_SYSTEM) to first("circuit_id_values", PROBE_CIRCUIT)
        }

        private fun decodeEnvelope(input: JsonElement?): JsonObject? {
            val text = (input as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
            val bytes = runCatching {
                // base64url or base64, padded or not.
                Base64.getUrlDecoder().decode(text.replace('+', '-').replace('/', '_').trimEnd('='))
            }.getOrNull() ?: return null
            return runCatching { json.parseToJsonElement(String(bytes, Charsets.UTF_8)) }.getOrNull() as? JsonObject
        }

        /**
         * The matcher's plan JSON as a [CircuitZkPlan]. Its two independent
         * circuit lists become the pairs [CircuitZkCircuitRef] holds: a list
         * that was not sent is a null on every pair, and a list sent empty
         * leaves no pair at all, which admits no circuit.
         *
         * @throws IllegalArgumentException if the JSON is not a plan.
         */
        fun toPlan(plan: JsonObject): CircuitZkPlan {
            val functions = (plan["functions"] as? JsonArray ?: throw IllegalArgumentException("no functions")).map { f ->
                val o = f as? JsonObject ?: throw IllegalArgumentException("function is not an object")
                CircuitZkFunction(
                    id = o.string("function_id"),
                    handle = o.string("handle"),
                    params = o["params"] as? JsonObject ?: JsonObject(emptyMap()),
                )
            }
            val filter = plan["circuit_filter"] as? JsonObject
            val systems = filter?.get("proof_systems")?.strings("proof_systems")
            val ids = filter?.get("circuit_ids")?.strings("circuit_ids")
            val refs = when {
                systems == null && ids == null -> null
                ids == null -> systems!!.map { CircuitZkCircuitRef(it, null) }
                systems == null -> ids.map { CircuitZkCircuitRef(null, it) }
                else -> systems.flatMap { s -> ids.map { i -> CircuitZkCircuitRef(s, i) } }
            }
            return CircuitZkPlan(
                functions = functions,
                circuitFilter = refs,
                raw = plan["raw"] as? JsonObject ?: throw IllegalArgumentException("no raw"),
            )
        }

        private fun JsonObject.string(key: String): String =
            (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content
                ?: throw IllegalArgumentException("$key is not a string")

        private fun JsonElement.strings(what: String): List<String> =
            (this as? JsonArray ?: throw IllegalArgumentException("$what is not an array")).map {
                (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content
                    ?: throw IllegalArgumentException("$what has a non-string")
            }
    }
}
