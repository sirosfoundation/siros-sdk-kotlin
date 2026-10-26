// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.openid4vp

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Test
import org.siros.sdk.credentials.CircuitZkCircuitFilter
import org.siros.sdk.credentials.CircuitZkFunction
import org.siros.sdk.credentials.CircuitZkPlan
import org.siros.sdk.credentials.CircuitZkPlanResult
import org.siros.sdk.credentials.CircuitZkPlanner
import org.siros.sdk.credentials.CircuitZkResponsePresentation
import org.siros.sdk.credentials.ResultValue
import org.siros.sdk.credentials.ZkWitnessSigner
import org.siros.sdk.keystore.BbsCdBinding
import org.siros.sdk.keystore.BbsCdMetrics
import org.siros.sdk.keystore.BbsCdPresenter
import org.siros.sdk.keystore.BbsCdProveRequest
import org.siros.sdk.keystore.BbsCdProveResponse
import org.siros.sdk.keystore.NymAuthNativeBbsCdBinding

/** The bbs_cd responder over a fake planner and binding (the matcher and nymauth-native do not load on the JVM). */
class BbsCdResponderTest {

    private val nym = ByteArray(48) { 3 }

    private class Binding(private val presentation: ByteArray, private val nym: ByteArray) : BbsCdBinding {
        override val systemId = NymAuthNativeBbsCdBinding.SYSTEM_ID
        override val proofSystem = NymAuthNativeBbsCdBinding.PROOF_SYSTEM
        override val implementation = "fake"
        val calls = mutableListOf<BbsCdProveRequest>()
        override fun prove(request: BbsCdProveRequest): BbsCdProveResponse {
            calls += request
            return BbsCdProveResponse(presentation, systemId, "nym", nym, listOf("age"), BbsCdMetrics(1.0, 2.0, 0.1, null, 10, presentation.size.toLong(), 1))
        }
    }

    private val presentation = CircuitZkResponsePresentation(
        NymAuthNativeBbsCdBinding.SYSTEM_ID, ByteArray(50) { 9 }, listOf(ByteArray(96) { 2 }), null,
        mapOf("nym" to ResultValue.Pseudonym(nym), "age" to ResultValue.Predicate),
    ).encode()

    private fun query(id: String, sourceFormat: String) = buildJsonObject {
        put("id", id)
        put("format", "zkp_req")
        put("meta", buildJsonObject {
            put("source_format", sourceFormat)
            if (sourceFormat == "bbs_cd") put("schema_id_value", "eu.europa.ec.eudi.nym_auth.bbs.1") else put("doctype_value", "eu.europa.ec.eudi.nym_auth.1")
        })
        put("_req", buildJsonArray {
            add(buildJsonObject { put("fn_id", "pseudonym"); put("return", "nym"); put("params", nymParams(sourceFormat)) })
            add(buildJsonObject { put("fn_id", "age_check"); put("return", "age"); put("params", age) })
        })
    }

    private fun nymParams(sourceFormat: String) = buildJsonObject {
        put("config", "known-offender-matching-ssc"); put("ver", 1)
        put("prf", if (sourceFormat == "bbs_cd") "hashdh-bls12381g1" else "sha-256")
    }

    private val age = buildJsonObject { put("ge", "2008-10-20"); put("le", "2013-10-19") }

    /** The matcher's reading of a query, as far as this test needs it. */
    private val planner = CircuitZkPlanner { q, _ ->
        val req = q["_req"]!!.jsonArray.map { it.jsonObject }
        CircuitZkPlanResult.Plan(
            CircuitZkPlan(
                functions = req.map { CircuitZkFunction(it["fn_id"]!!.jsonPrimitive.content, it["return"]!!.jsonPrimitive.content, it["params"]!!.jsonObject) },
                circuitFilter = CircuitZkCircuitFilter(listOf(NymAuthNativeBbsCdBinding.PROOF_SYSTEM), listOf(NymAuthNativeBbsCdBinding.SYSTEM_ID)),
                raw = q,
            ),
        )
    }

    private val payload = buildJsonObject {
        put("client_id", "x509_san_dns:community.example")
        put("nonce", "0123456789abcdef0123456789abcdef")
    }

    private val request = AuthorizationRequest(
        clientId = "x509_san_dns:community.example",
        requestUri = "https://verifier.example/request/1",
        responseUri = "https://verifier.example/response/1",
        nonce = "0123456789abcdef0123456789abcdef",
        state = "s",
        dcqlQuery = buildJsonObject {
            put("credentials", buildJsonArray { add(query("nym_attestation", "mso_mdoc")); add(query("nym_attestation_bbs", "bbs_cd")) })
        },
        clientMetadata = JsonObject(emptyMap()),
        responseEncryptionJwk = JsonObject(emptyMap()),
        responseEncryptionAlg = "ECDH-ES",
        responseEncryptionEnc = "A128GCM",
        responseEncryptionJwkThumbprint = "thumbprint-of-the-key",
        certificateChain = emptyList(),
        payload = payload,
    )

    private val signer = ZkWitnessSigner { _, _ -> ByteArray(64) }

    @Test
    fun `presents a bbs_cd query bound to the request object and its handover`() = runBlocking {
        val binding = Binding(presentation, nym)
        val responder = BbsCdResponder(BbsCdPresenter(binding), planner)
        val plan = responder.plan(request, "nym_attestation_bbs")
        val p = responder.present(request, "nym_attestation_bbs", plan, """{"format":"bbs_cd"}""", byteArrayOf(4, 5), signer, parallel = true)

        val call = binding.calls.single()
        assertSame(payload, call.requestObject)
        assertEquals("nym_attestation_bbs", call.credentialQueryId)
        assertEquals("x509_san_dns:community.example", call.handover.clientId)
        assertEquals("0123456789abcdef0123456789abcdef", call.handover.nonce)
        assertEquals("https://verifier.example/response/1", call.handover.responseUri)
        assertEquals("thumbprint-of-the-key", call.handover.jwkThumbprint)
        assertEquals("""{"format":"bbs_cd"}""", call.credential)
        assertArrayEquals(byteArrayOf(4, 5), call.devicePublicKey)
        assertSame(signer, call.signer)
        assertEquals(true, call.parallel)

        val token = p.vpToken["nym_attestation_bbs"]!!.jsonArray.single() as JsonPrimitive
        assertEquals(p.result.json, token)
        assertEquals(setOf("nym_attestation_bbs"), p.vpToken.keys)
        assertEquals(ResultValue.Pseudonym(nym), p.result.results["nym"])
    }

    @Test
    fun `an mdoc query or an unknown one is not a bbs_cd query`() {
        val responder = BbsCdResponder(BbsCdPresenter(Binding(presentation, nym)), planner)
        assertThrows(OpenId4VpException.Unsupported::class.java) { responder.plan(request, "nym_attestation") }
        assertThrows(OpenId4VpException.Unsupported::class.java) { responder.plan(request, "nope") }
        val refusing = BbsCdResponder(BbsCdPresenter(Binding(presentation, nym)), CircuitZkPlanner { _, _ -> CircuitZkPlanResult.InvalidRequest })
        assertThrows(OpenId4VpException.Unsupported::class.java) { refusing.plan(request, "nym_attestation_bbs") }
    }

    @Test
    fun `wallet metadata offers the bbs_cd scheme after the circuits`() {
        val circuit = org.siros.sdk.credentials.CircuitZkCircuit(
            "longfellow-nymauth", "nymauth-longfellow-mdoc-v1", setOf("eu.europa.ec.eudi.nym_auth.1"),
            aliases = setOf("urn:circuits:longfellow:nym_auth:v1"), proofSystem = "longfellow-libzk-v1",
        )
        val zk = WalletMetadata.circuitZk(listOf(circuit), listOf(NymAuthNativeBbsCdBinding))["vp_formats_supported"]!!.jsonObject["zkp_req"]!!.jsonObject
        assertEquals(
            listOf("nymauth-longfellow-mdoc-v1", "urn:circuits:longfellow:nym_auth:v1", "urn:mms:bbs-cd:nym_auth:v1"),
            zk["system_id_values"]!!.jsonArray.map { it.jsonPrimitive.content },
        )
        assertEquals(listOf("longfellow-libzk-v1", "bbs-cd-plugins-v0.1"), zk["proof_system_values"]!!.jsonArray.map { it.jsonPrimitive.content })
        // A BBS-only wallet offers the scheme alone.
        val bbsOnly = WalletMetadata.circuitZk(emptyList(), listOf(NymAuthNativeBbsCdBinding))["vp_formats_supported"]!!.jsonObject["zkp_req"]!!.jsonObject
        assertEquals(listOf("urn:mms:bbs-cd:nym_auth:v1"), bbsOnly["system_id_values"]!!.jsonArray.map { it.jsonPrimitive.content })
    }
}
