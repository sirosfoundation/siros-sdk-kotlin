package org.siros.sdk.credentials

import java.io.File
import java.time.Instant
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Checks [CircuitZkPresentationCodec] against `spec/circuit-zk-presentation-vectors.json`, shared with the
 * Swift SDK. Expected bytes come from `tools/gen_circuit_zk_presentation_vectors.py`; see
 * `spec/circuit-zk-presentation-vectors.md`.
 */
class CircuitZkPresentationTest {
    private val file: JsonObject by lazy {
        // Gradle runs unit tests with the module directory as the working directory.
        val f = File("../../spec/circuit-zk-presentation-vectors.json")
        require(f.isFile) { "vector file not found at ${f.absolutePath}" }
        Json.parseToJsonElement(f.readText()).jsonObject
    }

    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    private fun JsonObject.str(key: String): String? = this[key]?.jsonPrimitive?.content

    /** The test hook documented in the vector README. */
    private val hook = IssuerKeySetDecoder { circuitId, raw ->
        if (circuitId == "urn:test:custom-keys") IssuerKeySet.Other(raw) else null
    }

    private fun presentation(j: JsonObject): CircuitZkPresentation {
        val ks = j["issuer_key_set"]!!.jsonObject
        val keySet = ks["der_certificates_hex"]?.let { a -> IssuerKeySet.DerCertificates(a.jsonArray.map { hex(it.jsonPrimitive.content) }) }
            ?: IssuerKeySet.Other(hex(ks.str("other_cbor_hex")!!))
        val results = j["results"]!!.jsonObject.mapValues { (_, v) ->
            val o = v.jsonObject
            if (o["predicate"] != null) ResultValue.Predicate else ResultValue.Pseudonym(hex(o.str("pseudonym_hex")!!))
        }
        return CircuitZkPresentation(
            circuitId = j.str("circuit_id")!!,
            proof = hex(j.str("proof_hex")!!),
            issuerKeySet = keySet,
            proofTime = j.str("proof_time")?.let(Instant::parse),
            results = results,
            unknownEntries = j["unknown_entries_cbor_hex"]?.jsonObject?.mapValues { hex(it.value.jsonPrimitive.content) } ?: emptyMap(),
        )
    }

    private fun check(v: JsonObject, decodeHook: IssuerKeySetDecoder?) {
        val name = v.str("name")
        val p = presentation(v["presentation"]!!.jsonObject)
        val cbor = hex(v.str("cbor_hex")!!)
        assertEquals(name, v.str("cbor_hex"), CircuitZkPresentationCodec.encode(p).joinToString("") { "%02x".format(it) })
        assertEquals(name, v.str("base64url"), CircuitZkPresentationCodec.encodeBase64Url(p))
        assertEquals(name, p, CircuitZkPresentationCodec.decode(cbor, issuerKeySetDecoder = decodeHook))
        assertEquals(name, p, CircuitZkPresentationCodec.decodeBase64Url(v.str("base64url")!!, issuerKeySetDecoder = decodeHook))
    }

    @Test
    fun `every vector encodes to its bytes and decodes back`() {
        val vectors = file["vectors"]!!.jsonArray
        assertTrue(vectors.size >= 10)
        for (e in vectors) check(e.jsonObject, null)
    }

    @Test
    fun `hook vectors round trip with the hook`() {
        for (e in file["hook_vectors"]!!.jsonArray) check(e.jsonObject, hook)
    }

    @Test
    fun `every rejection fails with its reason`() {
        val rejections = file["rejections"]!!.jsonArray
        val seen = mutableSetOf<String>()
        for (e in rejections) {
            val v = e.jsonObject
            val expected = v.str("error")!!
            seen += expected
            val strict = v["strict"]!!.jsonPrimitive.boolean
            val h = if (v["issuer_key_set_hook"]!!.jsonPrimitive.boolean) hook else null
            try {
                if (v["cbor_hex"] != null) {
                    CircuitZkPresentationCodec.decode(hex(v.str("cbor_hex")!!), strict, h)
                } else {
                    CircuitZkPresentationCodec.decodeBase64Url(v.str("base64url")!!, strict, h)
                }
                fail("${v.str("name")}: expected $expected")
            } catch (err: CircuitZkPresentationError) {
                assertEquals(v.str("name"), expected, err.reason.name)
            }
        }
        // Every reason except the opt-in handle check has a rejection vector.
        val decodeReasons = CircuitZkPresentationReason.values().map { it.name }.toSet() - "RESULT_HANDLES_MISMATCH"
        assertEquals(decodeReasons, seen)
    }

    @Test
    fun `unknown top-level keys are preserved`() {
        val v = file["vectors"]!!.jsonArray.map { it.jsonObject }.first { it.str("name")!!.startsWith("unknown top-level key preserved") }
        val decoded = CircuitZkPresentationCodec.decode(hex(v.str("cbor_hex")!!))
        assertEquals(setOf("x_future"), decoded.unknownEntries.keys)
        assertEquals(v.str("cbor_hex"), CircuitZkPresentationCodec.encode(decoded).joinToString("") { "%02x".format(it) })
    }

    @Test
    fun `strict mode accepts a presentation without unknown keys`() {
        val v = file["vectors"]!!.jsonArray.first().jsonObject
        CircuitZkPresentationCodec.decode(hex(v.str("cbor_hex")!!), strict = true)
    }

    @Test
    fun `requireResultHandles is opt-in and exact`() {
        val vectors = file["vectors"]!!.jsonArray.map { it.jsonObject }.associateBy { it.str("name") }
        for (c in file["handle_checks"]!!.jsonArray.map { it.jsonObject }) {
            val p = CircuitZkPresentationCodec.decode(hex(vectors.getValue(c.str("presentation"))["cbor_hex"]!!.jsonPrimitive.content))
            val expected = c["expected_handles"]!!.jsonArray.map { it.jsonPrimitive.content }.toSet()
            if (c["ok"]!!.jsonPrimitive.boolean) {
                p.requireResultHandles(expected)
            } else {
                try {
                    p.requireResultHandles(expected)
                    fail(c.str("name"))
                } catch (e: CircuitZkPresentationError) {
                    assertEquals(CircuitZkPresentationReason.RESULT_HANDLES_MISMATCH, e.reason)
                }
            }
        }
    }

    @Test
    fun `a throwing hook is a rejection, not a crash`() {
        val v = file["hook_vectors"]!!.jsonArray.first().jsonObject
        try {
            CircuitZkPresentationCodec.decode(hex(v.str("cbor_hex")!!), issuerKeySetDecoder = { _, _ -> error("boom") })
            fail()
        } catch (e: CircuitZkPresentationError) {
            assertEquals(CircuitZkPresentationReason.UNSUPPORTED_ISSUER_KEY_SET, e.reason)
        }
    }

    @Test
    fun `constructors enforce the CDDL sizes`() {
        for ((make, reason) in listOf<Pair<() -> Any, CircuitZkPresentationReason>>(
            { ResultValue.Pseudonym(ByteArray(31)) } to CircuitZkPresentationReason.BAD_PSEUDONYM_LENGTH,
            { IssuerKeySet.DerCertificates(emptyList()) } to CircuitZkPresentationReason.EMPTY_ISSUER_KEY_SET,
            { CircuitZkPresentation("c", ByteArray(0), IssuerKeySet.Other(byteArrayOf(0)), null, emptyMap()) } to CircuitZkPresentationReason.EMPTY_RESULTS,
        )) {
            try {
                make()
                fail()
            } catch (e: CircuitZkPresentationError) {
                assertEquals(reason, e.reason)
            }
        }
    }

    @Test
    fun `proof_time is optional and absent decodes to null`() {
        val v = file["vectors"]!!.jsonArray.first().jsonObject
        assertNull(CircuitZkPresentationCodec.decode(hex(v.str("cbor_hex")!!)).proofTime)
    }
}
