package org.siros.sdk.sample

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.siros.sdk.credentials.CircuitZkCircuit
import org.siros.sdk.credentials.CircuitZkCircuitSource
import org.siros.sdk.credentials.CircuitZkFunction
import org.siros.sdk.credentials.CircuitZkPlan
import org.siros.sdk.credentials.CircuitZkPlanResult
import org.siros.sdk.credentials.CircuitZkPlanner
import org.siros.sdk.credentials.NonDisclosurePolicy

/**
 * DEMO `circuit_zk` plumbing for the sample app, only used when the Request
 * policy setting turns `circuit_zk` on. The SDK does not yet ship a planner
 * (the shared matcher's is a later change), so this one understands exactly
 * one query: `meta.doctype_value` of the nym_auth type, planned as a single
 * pseudonym bound to the verifier's `x509_san_dns`. Anything else is an invalid
 * request and matches nothing. It is a stand-in for testing the wallet's
 * handling, not a planner to copy.
 */
internal object SampleCircuitZk {
    /** The circuit table of the demo: one circuit serving nym_auth, from the fake proof system. */
    val circuits = CircuitZkCircuitSource {
        listOf(CircuitZkCircuit(system = "demo-fake", circuitId = "demo-fake-circuit-v1", docTypes = setOf(NonDisclosurePolicy.NYM_AUTH_DOCTYPE)))
    }

    val planner = CircuitZkPlanner { query, _ -> plan(query) }

    internal fun plan(query: JsonObject): CircuitZkPlanResult {
        val doctype = (query["meta"] as? JsonObject)?.get("doctype_value")?.jsonPrimitive?.contentOrNull
        if (doctype != NonDisclosurePolicy.NYM_AUTH_DOCTYPE) return CircuitZkPlanResult.InvalidRequest
        return CircuitZkPlanResult.Plan(
            CircuitZkPlan(
                functions = listOf(
                    CircuitZkFunction(
                        id = "pseudonym-v1-sha256",
                        handle = "nym",
                        params = buildJsonObject {
                            put("config", "known-offender-matching-psc")
                            put("verifier_id_type", "x509_san_dns")
                        },
                    ),
                ),
                raw = query,
            ),
        )
    }
}
