package org.siros.sdk.credentials

import java.io.File
import java.security.MessageDigest
import java.util.Base64
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [CircuitZkResponseValidator] against the shared response vectors of siros-dc-matcher (commit 932b07af, vendored verbatim in
 * `spec/circuit-zk-response-vectors`), and [CircuitZkResponsePresentation] against the validator.
 */
class CircuitZkResponseVectorsTest {
    private val dir = File("../../spec/circuit-zk-response-vectors").also { require(it.isDirectory) { "vector dir not found at ${it.absolutePath}" } }
    private val files = dir.listFiles { f -> f.extension == "json" }!!.sortedBy { it.name }

    private fun plan(query: JsonObject, clientMetadata: JsonObject?): CircuitZkPlan {
        val functions = query["req"]!!.jsonArray.map {
            val o = it.jsonObject
            CircuitZkFunction(o["id"]!!.jsonPrimitive.content, o["return"]!!.jsonPrimitive.content, (o["params"] as? JsonObject) ?: JsonObject(emptyMap()))
        }
        val offered = clientMetadata?.get("vp_formats_supported")?.jsonObject?.get("circuit_zk")?.jsonObject
        fun list(k: String) = offered?.get(k)?.jsonArray?.map { it.jsonPrimitive.content }
        return CircuitZkPlan(functions, CircuitZkCircuitFilter(list("circuit_proof_system_values"), list("circuit_id_values")), query)
    }

    private fun text(v: JsonObject, value: String, text: String): String? = v[value]?.toString() ?: v[text]?.jsonPrimitive?.content

    @Test
    fun theVendoredVectorSetIsTheOneConformedTo() {
        // The set digest: SHA-256 over "<sha256 of file>  <name>\n" for the json files in name order.
        val lines = files.joinToString("") { f -> "${hex(MessageDigest.getInstance("SHA-256").digest(f.readBytes()))}  ${f.name}\n" }
        assertEquals(79, files.size)
        assertEquals("5c7fd1d3cfc77288737cbb9d198b7a56ce4edb89360de1c49e12d1c752a53e52", hex(MessageDigest.getInstance("SHA-256").digest(lines.toByteArray())))
    }

    @Test
    fun everyVectorGivesItsStatedVerdict() {
        val failures = mutableListOf<String>()
        var ok = 0
        var err = 0
        for (f in files) {
            val v = Json.parseToJsonElement(f.readText()).jsonObject
            val query = v["query"]?.jsonObject ?: Json.parseToJsonElement(v["query_text"]!!.jsonPrimitive.content).jsonObject
            val cm = (v["client_metadata"] as? JsonObject) ?: v["client_metadata_text"]?.let { Json.parseToJsonElement(it.jsonPrimitive.content) as? JsonObject }
            val token = text(v, "vp_token", "vp_token_text")!!
            val got = CircuitZkResponseValidator.validate(plan(query, cm), token)
            val expect = v["expect"]!!.jsonObject
            if (f.name.startsWith("ok_") != (expect["valid"] != null)) failures += "${f.name}: name and expect disagree"
            if (expect["valid"] != null) {
                ok++
                if (got != null) failures += "${f.name}: expected ok, got ${got.code}"
            } else {
                err++
                val want = expect["error"]!!.jsonPrimitive.content
                if (got?.code != want) failures += "${f.name}: expected $want, got ${got?.code}"
            }
        }
        assertTrue("ok=$ok err=$err", ok >= 5 && err >= 25)
        assertTrue("\n" + failures.joinToString("\n"), failures.isEmpty())
    }

    @Test
    fun everyRefusalCodeHasAVector() {
        val codes = files.mapNotNull { Json.parseToJsonElement(it.readText()).jsonObject["expect"]!!.jsonObject["error"]?.jsonPrimitive?.content }.toSet()
        val missing = CircuitZkResponseError.values().map { it.code } - codes
        assertTrue("no vector for $missing", missing.isEmpty())
    }

    // ── What the SDK builds is what the validator accepts ────────────────────────────────────────────────

    private val query = Json.parseToJsonElement(
        """{"id":"q","format":"circuit_zk","req":[{"id":"pseudonym-v1-sha256","return":"p","params":{"config":"known-offender-matching-ssc"}},{"id":"age_check","return":"a","params":{"ge":"2008-10-10","le":"2013-10-09"}}]}""",
    ).jsonObject
    private val offered = Json.parseToJsonElement(
        """{"vp_formats_supported":{"circuit_zk":{"circuit_proof_system_values":["sys"],"circuit_id_values":["urn:c"]}}}""",
    ).jsonObject

    private fun presentation(results: Map<String, ResultValue>? = null, chain: List<ByteArray> = listOf(ByteArray(10) { it.toByte() })) = CircuitZkResponsePresentation(
        circuitId = "urn:c", proofSystem = "sys", proof = ByteArray(40) { (it * 3).toByte() }, x5chain = chain,
        results = results ?: linkedMapOf("p" to ResultValue.Pseudonym(ByteArray(32) { it.toByte() }), "a" to ResultValue.Predicate),
    )

    private fun vpToken(vararg p: CircuitZkResponsePresentation) = JsonObject(mapOf("q" to JsonArray(p.map { it.toJson() }))).toString()

    @Test
    fun aBuiltPresentationValidates_andCarriesTheLeafFirstChainAsPaddedStandardBase64() {
        val p = presentation(chain = listOf(ByteArray(1) { 0xfb.toByte() }, ByteArray(2) { 0xff.toByte() }))
        assertNull(CircuitZkResponseValidator.validate(plan(query, offered), vpToken(p)))
        val chain = p.toJson()["x5chain"]!!.jsonArray.map { it.jsonPrimitive.content }
        assertEquals(listOf(Base64.getEncoder().encodeToString(byteArrayOf(0xfb.toByte())), "//8="), chain)
        assertEquals(setOf("circuit_id", "proof_system", "proof", "x5chain", "results"), p.toJson().keys)
    }

    @Test
    fun aSecondPresentationNeedsMultiple() {
        val two = vpToken(presentation(), presentation())
        assertEquals(CircuitZkResponseError.PRESENTATIONS_MULTIPLE_NOT_ALLOWED, CircuitZkResponseValidator.validate(plan(query, offered), two))
        val multiple = JsonObject(query + ("multiple" to JsonPrimitive(true)))
        assertNull(CircuitZkResponseValidator.validate(plan(multiple, offered), two))
    }

    @Test
    fun aResponseToARequestThatOfferedNothingIsRefused() {
        assertEquals(CircuitZkResponseError.CIRCUIT_ID_NOT_OFFERED, CircuitZkResponseValidator.validate(plan(query, null), vpToken(presentation())))
    }

    @Test
    fun noItemTypeIsSkipped_anUnknownFunctionOrAMissingHandleRefusesTheResponse() {
        val unknown = JsonObject(query + ("req" to JsonArray(query["req"]!!.jsonArray + Json.parseToJsonElement("""{"id":"mystery","return":"m"}"""))))
        val withExtra = presentation(linkedMapOf("p" to ResultValue.Pseudonym(ByteArray(32)), "a" to ResultValue.Predicate, "m" to ResultValue.Predicate))
        assertEquals(CircuitZkResponseError.RESULT_FUNCTION_UNKNOWN, CircuitZkResponseValidator.validate(plan(unknown, offered), vpToken(withExtra)))
        val skipped = presentation(linkedMapOf("p" to ResultValue.Pseudonym(ByteArray(32))))
        assertEquals(CircuitZkResponseError.RESULT_HANDLE_MISSING, CircuitZkResponseValidator.validate(plan(query, offered), vpToken(skipped)))
    }

    @Test(expected = IllegalArgumentException::class)
    fun aPresentationWithoutAnX5chainCannotBeBuilt() {
        presentation(chain = emptyList())
    }

    @Test(expected = IllegalArgumentException::class)
    fun aNinthCertificateCannotBeBuilt() {
        presentation(chain = List(9) { ByteArray(4) })
    }

    @Test(expected = IllegalArgumentException::class)
    fun anOversizedCertificateCannotBeBuilt() {
        presentation(chain = listOf(ByteArray(4097)))
    }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
}
