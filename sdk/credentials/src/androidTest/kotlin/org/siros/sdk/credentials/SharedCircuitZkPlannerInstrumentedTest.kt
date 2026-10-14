// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * [SharedCircuitZkPlanner] against the matcher's own conformance vectors
 * (`spec/circuit-zk-planner-vectors/`, copied verbatim; see its `SOURCE.md`),
 * on a device because the planner is reached through the native library.
 *
 * NOT run by `./gradlew test`: needs a device or emulator.
 */
@RunWith(AndroidJUnit4::class)
class SharedCircuitZkPlannerInstrumentedTest {
    private val dir = "circuit-zk-planner-vectors"

    private fun vectors(): List<Pair<String, JsonObject>> {
        val assets = InstrumentationRegistry.getInstrumentation().context.assets
        val files = assets.list(dir).orEmpty().filter { it.endsWith(".json") }.sorted()
        return files.map { name ->
            name to Json.parseToJsonElement(assets.open("$dir/$name").bufferedReader().readText()).jsonObject
        }
    }

    /** The vector's query and client metadata as the planner's typed boundary takes them; null where the vector is raw text. */
    private fun JsonObject.query() = this["query"] as? JsonObject
    private fun JsonObject.clientMetadata() = this["client_metadata"] as? JsonObject

    @Test
    fun the_vector_set_is_there() {
        val all = vectors()
        assertTrue("copied vectors not found in the test APK's assets: ${all.size}", all.count { it.first.startsWith("ok_") } >= 10)
        assertTrue(all.count { it.first.startsWith("err_") } >= 30)
    }

    @Test
    fun plans_every_ok_vector_identically_to_the_matcher() {
        for ((name, v) in vectors().filter { it.first.startsWith("ok_") }) {
            val query = v.query() ?: error("$name: an ok vector is an object query")
            val plan = SharedCircuitZkPlanner.planJson(query, v.clientMetadata())
            assertNotNull("$name was not planned", plan)
            val expected = (v["expect"] as JsonObject)["plan"] as JsonObject
            assertEquals("$name: plan", expected, JsonObject(plan!!.filterKeys { it != "raw" }))
            assertEquals("$name: raw is the query, unchanged", query, plan["raw"])
            // And the SDK's own plan reads the same functions.
            val sdk = (SharedCircuitZkPlanner().plan(query, v.clientMetadata()) as CircuitZkPlanResult.Plan).plan
            assertEquals(name, (expected["functions"] as kotlinx.serialization.json.JsonArray).size, sdk.functions.size)
            assertEquals(name, query, sdk.raw)
        }
    }

    @Test
    fun rejects_every_err_vector() {
        var typed = 0
        for ((name, v) in vectors().filter { it.first.startsWith("err_") }) {
            val query = v.query() ?: continue // raw text or a non-object query cannot reach the typed boundary
            if (v.containsKey("client_metadata_text")) continue
            typed++
            assertNull("$name was planned", SharedCircuitZkPlanner.planJson(query, v.clientMetadata()))
            assertTrue("$name", SharedCircuitZkPlanner().plan(query, v.clientMetadata()) is CircuitZkPlanResult.InvalidRequest)
        }
        assertTrue("only $typed error vectors reached the planner", typed >= 30)
    }

    /** What a request's two circuit lists become in the SDK's plan, end to end. */
    @Test
    fun the_circuit_lists_map_onto_the_sdks_plan() {
        fun planned(vector: String): CircuitZkPlan {
            val v = vectors().first { it.first == vector }.second
            return (SharedCircuitZkPlanner().plan(v.query()!!, v.clientMetadata()) as CircuitZkPlanResult.Plan).plan
        }
        assertEquals(
            listOf(CircuitZkCircuitRef("longfellow-libzk-v1", "urn:circuits:longfellow:nym_auth:v1")),
            planned("ok_normative_plain.json").circuitFilter,
        )
        assertNull(planned("ok_client_metadata_without_circuit_zk.json").circuitFilter)
    }

    /** The planner is what [CredentialMatcher] uses when the wallet turns circuit_zk on. */
    @Test
    fun matching_uses_the_ffi_planner() {
        val nym = "eu.europa.ec.eudi.nym_auth.1"
        val creds = listOf(
            StoredCredential(id = 1L, format = "mso_mdoc", raw = "", metadata = CredentialMetadata(doctype = nym), batchId = 1L, instanceId = 0),
        )
        val support = CircuitZkSupport(
            planner = SharedCircuitZkPlanner(),
            circuits = CircuitZkCircuitSource {
                listOf(CircuitZkCircuit("longfellow-libzk-v1", "urn:circuits:longfellow:nym_auth:v1", setOf(nym)))
            },
        )
        val v = vectors().first { it.first == "ok_normative_plain.json" }.second
        val dcql = JsonObject(mapOf("credentials" to kotlinx.serialization.json.JsonArray(listOf(v.query()!!))))
        val result = CredentialMatcher.matchDcql(dcql, creds, circuitZk = support, clientMetadata = v.clientMetadata()).queryResults.single()
        assertEquals(listOf(1L), result.candidates.map { it.id })
        assertEquals(listOf("pseudonym-v1-sha256", "age_check"), result.circuitZkPlan!!.functions.map { it.id })

        // A verifier naming another circuit is not served, and a structurally invalid request is not planned.
        val other = JsonObject(
            mapOf(
                "vp_formats_supported" to JsonObject(
                    mapOf("circuit_zk" to JsonObject(mapOf("circuit_id_values" to kotlinx.serialization.json.JsonArray(listOf(kotlinx.serialization.json.JsonPrimitive("urn:other")))))),
                ),
            ),
        )
        val unserved = CredentialMatcher.matchDcql(dcql, creds, circuitZk = support, clientMetadata = other).queryResults.single()
        assertTrue(unserved.candidates.isEmpty())
        val invalid = vectors().first { it.first == "err_duplicate_handle.json" }.second
        val bad = JsonObject(mapOf("credentials" to kotlinx.serialization.json.JsonArray(listOf(invalid.query()!!))))
        val refused = CredentialMatcher.matchDcql(bad, creds, circuitZk = support).queryResults.single()
        assertNull(refused.circuitZkPlan)
        assertTrue(refused.candidates.isEmpty())
    }
}
