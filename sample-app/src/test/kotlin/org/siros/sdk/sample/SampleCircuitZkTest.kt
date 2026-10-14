package org.siros.sdk.sample

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.CircuitZkPlanResult
import org.siros.sdk.credentials.NonDisclosurePolicy

class SampleCircuitZkTest {
    private fun query(json: String) = Json.parseToJsonElement(json).jsonObject

    @Test
    fun plansTheNymAuthDemoQueryAsOnePseudonym() {
        val result = SampleCircuitZk.plan(query("""{"id":"q","format":"circuit_zk","meta":{"doctype_value":"${NonDisclosurePolicy.NYM_AUTH_DOCTYPE}"}}"""))
        val plan = (result as CircuitZkPlanResult.Plan).plan
        assertEquals(listOf("pseudonym-v1-sha256"), plan.functions.map { it.id })
    }

    @Test
    fun anythingElseIsAnInvalidRequest() {
        assertTrue(SampleCircuitZk.plan(query("""{"id":"q","format":"circuit_zk","meta":{"doctype_value":"other"}}""")) is CircuitZkPlanResult.InvalidRequest)
        assertTrue(SampleCircuitZk.plan(query("""{"id":"q","format":"circuit_zk"}""")) is CircuitZkPlanResult.InvalidRequest)
    }

    @Test
    fun theDemoCircuitServesOnlyTheNymAuthDocType() {
        assertEquals(setOf(NonDisclosurePolicy.NYM_AUTH_DOCTYPE), SampleCircuitZk.circuits.circuits().flatMap { it.docTypes }.toSet())
    }
}
