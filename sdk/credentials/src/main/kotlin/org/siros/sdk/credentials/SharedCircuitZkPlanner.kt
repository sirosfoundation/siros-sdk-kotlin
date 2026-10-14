// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import timber.log.Timber
import uniffi.siros_dc_matcher_ffi.CircuitZkPlanException
import uniffi.siros_dc_matcher_ffi.circuitZkPlan

/**
 * The [CircuitZkPlanner] backed by the shared matcher: the same planner the OS
 * credential picker runs, so the wallet and the picker cannot read a
 * `circuit_zk` request differently.
 *
 * The matcher (0.9.0) exports its planner over the FFI as `circuit_zk_plan`,
 * which returns the plan as JSON or fails with the planner's own stable code
 * for a structurally broken request. The plan is read from that JSON and this
 * class never parses a function or a parameter itself. A request the planner
 * rejects, and a plan in a shape this SDK does not read, are both
 * [CircuitZkPlanResult.InvalidRequest], which fails closed.
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
        private val json = Json

        /**
         * The matcher's plan for [query], as the JSON it serialises
         * (`functions`, `circuit_filter`, `meta_doctype`, `raw`), or null when
         * the planner rejects the request. Throws when the native library is
         * unavailable.
         */
        fun planJson(query: JsonObject, clientMetadata: JsonObject?): JsonObject? {
            val text = try {
                circuitZkPlan(query.toString(), clientMetadata?.toString())
            } catch (e: CircuitZkPlanException) {
                Timber.d("The matcher does not plan this request (${e.javaClass.simpleName})")
                return null
            }
            return json.parseToJsonElement(text) as? JsonObject
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
