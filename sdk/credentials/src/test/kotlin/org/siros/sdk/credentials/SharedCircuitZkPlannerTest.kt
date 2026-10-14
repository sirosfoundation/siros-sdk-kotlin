package org.siros.sdk.credentials

import java.util.Base64
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The parts of [SharedCircuitZkPlanner] that run without the native matcher: reading its plan JSON into the SDK's
 * plan, and choosing the probe's circuit. What the matcher answers is checked on a device, against its own vectors
 * (`SharedCircuitZkPlannerInstrumentedTest`).
 */
class SharedCircuitZkPlannerTest {
    private fun obj(s: String): JsonObject = Json.parseToJsonElement(s).jsonObject

    private fun plan(filter: String?) = SharedCircuitZkPlanner.toPlan(
        obj(
            """{"functions":[{"function_id":"age_check","handle":"h","params":{"ge":"2008-10-10","source":{"path":["birth_date"]}}}],
               ${filter?.let { "\"circuit_filter\":$it," } ?: ""} "meta_doctype":"d","raw":{"id":"q"}}""",
        ),
    )

    @Test
    fun functionsKeepIdHandleAndParamsAsPlanned() {
        val f = plan("{}").functions.single()
        assertEquals("age_check", f.id)
        assertEquals("h", f.handle)
        assertEquals(obj("""{"ge":"2008-10-10","source":{"path":["birth_date"]}}"""), f.params)
        assertEquals(obj("""{"id":"q"}"""), plan("{}").raw)
    }

    @Test
    fun aListNotSentIsNoConstraintAndAListSentEmptyAdmitsNothing() {
        assertNull(plan("{}").circuitFilter)
        assertNull(plan(null).circuitFilter)
        assertEquals(emptyList<CircuitZkCircuitRef>(), plan("""{"circuit_ids":[]}""").circuitFilter)
        assertEquals(emptyList<CircuitZkCircuitRef>(), plan("""{"proof_systems":["s"],"circuit_ids":[]}""").circuitFilter)
    }

    @Test
    fun twoIndependentListsBecomeTheirPairs() {
        assertEquals(listOf(CircuitZkCircuitRef("s1", null), CircuitZkCircuitRef("s2", null)), plan("""{"proof_systems":["s1","s2"]}""").circuitFilter)
        assertEquals(listOf(CircuitZkCircuitRef(null, "c1")), plan("""{"circuit_ids":["c1"]}""").circuitFilter)
        assertEquals(
            listOf(CircuitZkCircuitRef("s1", "c1"), CircuitZkCircuitRef("s1", "c2"), CircuitZkCircuitRef("s2", "c1"), CircuitZkCircuitRef("s2", "c2")),
            plan("""{"proof_systems":["s1","s2"],"circuit_ids":["c1","c2"]}""").circuitFilter,
        )
    }

    /** The pairs admit exactly what the matcher admits: system in the first list AND id in the second. */
    @Test
    fun thePairsAdmitWhatTheMatcherAdmits() {
        fun circuit(system: String, id: String) = CircuitZkCircuit(system, id, setOf("d"))
        val p = plan("""{"proof_systems":["s1","s2"],"circuit_ids":["c1","c2"]}""")
        fun admits(c: CircuitZkCircuit) = p.circuitFilter!!.any { it.admits(c) }
        assertTrue(admits(circuit("s1", "c2")))
        assertTrue(admits(circuit("s2", "c1")))
        assertTrue(!admits(circuit("s3", "c1")))
        assertTrue(!admits(circuit("s1", "c3")))
    }

    @Test
    fun anUnreadablePlanIsRejected() {
        assertThrows(IllegalArgumentException::class.java) { SharedCircuitZkPlanner.toPlan(obj("""{"raw":{}}""")) }
        assertThrows(IllegalArgumentException::class.java) {
            SharedCircuitZkPlanner.toPlan(obj("""{"functions":[{"function_id":1,"handle":"h"}],"raw":{}}"""))
        }
        assertThrows(IllegalArgumentException::class.java) {
            SharedCircuitZkPlanner.toPlan(obj("""{"functions":[],"circuit_filter":{"circuit_ids":[1]},"raw":{}}"""))
        }
    }

    private fun cm(circuitZk: String) = obj("""{"vp_formats_supported":{"circuit_zk":$circuitZk}}""")

    @Test
    fun theProbeCircuitTakesTheFirstOfEachListSent() {
        assertEquals("s1" to "c1", SharedCircuitZkPlanner.circuitSeed(cm("""{"circuit_proof_system_values":["s1","s2"],"circuit_id_values":["c1","c2"]}""")))
        // A list not sent is satisfied by a placeholder.
        val onlyIds = SharedCircuitZkPlanner.circuitSeed(cm("""{"circuit_id_values":["c1"]}"""))
        assertEquals("c1", onlyIds.second)
        assertEquals(SharedCircuitZkPlanner.circuitSeed(null).first, onlyIds.first)
    }

    @Test
    fun theEnvelopeFormIsReadWhateverItsBase64() {
        val inner = """{"circuit_proof_system_values":["s1"],"circuit_id_values":["c>?"]}"""
        val bytes = inner.toByteArray()
        for (encoded in listOf(
            Base64.getEncoder().encodeToString(bytes),
            Base64.getUrlEncoder().encodeToString(bytes),
            Base64.getUrlEncoder().withoutPadding().encodeToString(bytes),
        )) {
            assertEquals(encoded, "s1" to "c>?", SharedCircuitZkPlanner.circuitSeed(cm("""{"fn_id":"x","input":"$encoded"}""")))
        }
        // Unreadable: placeholders, and the matcher decides.
        assertEquals(SharedCircuitZkPlanner.circuitSeed(null), SharedCircuitZkPlanner.circuitSeed(cm("""{"fn_id":"x","input":"!!!"}""")))
    }
}
