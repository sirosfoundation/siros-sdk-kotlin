// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import java.util.Base64
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.CircuitZkCircuitFilter
import org.siros.sdk.credentials.CircuitZkFunction
import org.siros.sdk.credentials.CircuitZkPlan
import org.siros.sdk.credentials.CircuitZkResponsePresentation
import org.siros.sdk.credentials.ResultValue
import org.siros.sdk.credentials.ZkWitnessSigner

/** The bbs_cd presenter over a fake binding (the native library does not load on the JVM; see the instrumented test). */
class BbsCdPresenterTest {

    private val nym = ByteArray(48) { (it + 1).toByte() }

    private class FakeBinding(var answer: (BbsCdProveRequest) -> BbsCdProveResponse) : BbsCdBinding {
        override val systemId = NymAuthNativeBbsCdBinding.SYSTEM_ID
        override val proofSystem = NymAuthNativeBbsCdBinding.PROOF_SYSTEM
        override val implementation = "fake"
        val calls = mutableListOf<BbsCdProveRequest>()
        override fun prove(request: BbsCdProveRequest): BbsCdProveResponse {
            calls += request
            return answer(request)
        }
    }

    private fun presentation(systemId: String = NymAuthNativeBbsCdBinding.SYSTEM_ID, handles: Map<String, ResultValue> = mapOf("nym" to ResultValue.Pseudonym(nym), "age" to ResultValue.Predicate)) =
        CircuitZkResponsePresentation(systemId, ByteArray(100) { 7 }, listOf(ByteArray(96) { 1 }), null, handles).encode()

    private fun response(bytes: ByteArray = presentation(), systemId: String = NymAuthNativeBbsCdBinding.SYSTEM_ID) =
        BbsCdProveResponse(bytes, systemId, "nym", nym, listOf("age"), BbsCdMetrics(160.0, 170.0, 0.4, 2.3, 100, bytes.size.toLong(), 1))

    private fun query(sourceFormat: String = "bbs_cd", prf: String = "hashdh-bls12381g1") = buildJsonObject {
        put("id", "nym_attestation_bbs")
        put("format", "zkp_req")
        put(
            "meta",
            buildJsonObject {
                put("source_format", sourceFormat)
                if (sourceFormat == "bbs_cd") put("schema_id_value", "eu.europa.ec.eudi.nym_auth.bbs.1") else put("doctype_value", "eu.europa.ec.eudi.nym_auth.1")
            },
        )
        put(
            "_req",
            buildJsonArray {
                add(buildJsonObject { put("fn_id", "pseudonym"); put("return", "nym"); put("params", params(prf)) })
                add(buildJsonObject { put("fn_id", "age_check"); put("return", "age"); put("params", age) })
            },
        )
    }

    private fun params(prf: String) = buildJsonObject { put("config", "known-offender-matching-ssc"); put("ver", 1); put("prf", prf) }
    private val age = buildJsonObject { put("ge", "2008-10-20"); put("le", "2013-10-19") }

    private fun plan(
        sourceFormat: String = "bbs_cd",
        prf: String = "hashdh-bls12381g1",
        filter: CircuitZkCircuitFilter? = CircuitZkCircuitFilter(listOf(NymAuthNativeBbsCdBinding.PROOF_SYSTEM), listOf(NymAuthNativeBbsCdBinding.SYSTEM_ID)),
    ) = CircuitZkPlan(
        functions = listOf(CircuitZkFunction("pseudonym", "nym", params(prf)), CircuitZkFunction("age_check", "age", age)),
        circuitFilter = filter,
        raw = query(sourceFormat, prf),
    )

    private val requestObject = buildJsonObject { put("client_id", "x509_san_dns:community.example") }
    private val handover = BbsCdHandover("x509_san_dns:community.example", "0123456789abcdef", "https://community.example/r", "thumb")
    private val signer = ZkWitnessSigner { _, _ -> ByteArray(64) }

    private fun request(p: CircuitZkPlan = plan()) = BbsCdPresenter.Request(p, requestObject, handover, """{"format":"bbs_cd"}""", byteArrayOf(4, 1, 2), parallel = true)

    private fun present(binding: FakeBinding, p: CircuitZkPlan = plan()) = runBlocking { BbsCdPresenter(binding).present(request(p), signer) }

    private fun denied(binding: FakeBinding, p: CircuitZkPlan = plan()): CircuitZkError.AccessDenied =
        assertThrows(CircuitZkError.AccessDenied::class.java) { present(binding, p) }

    @Test
    fun `presents through the binding and returns the vp_token element and its results`() {
        val binding = FakeBinding { response() }
        val r = present(binding)
        assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString(presentation()), r.json.content)
        assertEquals(NymAuthNativeBbsCdBinding.SYSTEM_ID, r.systemId)
        assertEquals(ResultValue.Pseudonym(nym), r.results["nym"])
        assertSame(ResultValue.Predicate, r.results["age"])
        assertEquals("fake", r.implementation)
        assertEquals(160.0, r.metrics!!.proveMs, 0.0)
        val call = binding.calls.single()
        assertEquals("nym_attestation_bbs", call.credentialQueryId)
        assertSame(requestObject, call.requestObject)
        assertSame(handover, call.handover)
        assertSame(signer, call.signer)
        assertArrayEquals(byteArrayOf(4, 1, 2), call.devicePublicKey)
        assertTrue(call.parallel)
    }

    @Test
    fun `refuses an mdoc plan and a plan that breaks a rulebook rule, without proving`() {
        val binding = FakeBinding { response() }
        assertEquals(CircuitZkStep.VALIDATE, denied(binding, plan(sourceFormat = "mso_mdoc", prf = "sha-256")).step)
        // bbs_cd's pseudonym is hashdh-bls12381g1 only.
        assertEquals(CircuitZkStep.VALIDATE, denied(binding, plan(prf = "sha-256")).step)
        assertTrue(binding.calls.isEmpty())
    }

    @Test
    fun `refuses a request that does not offer the scheme, without proving`() {
        val binding = FakeBinding { response() }
        for (filter in listOf(
            null,
            CircuitZkCircuitFilter(null, null),
            CircuitZkCircuitFilter(null, listOf("urn:circuits:longfellow:nym_auth:v1")),
            CircuitZkCircuitFilter(listOf("longfellow-libzk-v1"), listOf(NymAuthNativeBbsCdBinding.SYSTEM_ID)),
        )) {
            assertEquals(filter.toString(), CircuitZkStep.CIRCUIT, denied(binding, plan(filter = filter)).step)
        }
        assertTrue(binding.calls.isEmpty())
        // No proof-system list constrains nothing.
        present(binding, plan(filter = CircuitZkCircuitFilter(null, listOf(NymAuthNativeBbsCdBinding.SYSTEM_ID))))
        assertEquals(1, binding.calls.size)
    }

    @Test
    fun `a refusal of the binding is access_denied with its reason`() {
        val cases = mapOf(
            NymAuthNativeException(NymAuthNativeErrorKind.REFUSED, NymAuthRefusal.UNSATISFIED) to CircuitZkRefusalReason.UNSATISFIED,
            NymAuthNativeException(NymAuthNativeErrorKind.REFUSED, NymAuthRefusal.DEVICE_SIGNATURE) to CircuitZkRefusalReason.DEVICE_SIGNATURE,
            NymAuthNativeException(NymAuthNativeErrorKind.REFUSED, NymAuthRefusal.CREDENTIAL) to CircuitZkRefusalReason.CREDENTIAL,
            NymAuthNativeException(NymAuthNativeErrorKind.INVALID_INPUT) to CircuitZkRefusalReason.INVALID_INPUT,
            NymAuthNativeException(NymAuthNativeErrorKind.INTERNAL) to CircuitZkRefusalReason.INTERNAL,
        )
        for ((e, reason) in cases) {
            val d = denied(FakeBinding { throw e })
            assertEquals(CircuitZkStep.PROVE, d.step)
            assertEquals(reason, d.reason)
        }
    }

    @Test
    fun `the signer's own exception passes through unchanged`() {
        class UserCancelled : Exception("cancelled")
        val e = UserCancelled()
        val thrown = assertThrows(UserCancelled::class.java) { present(FakeBinding { throw e }) }
        // The same exception, or kotlinx.coroutines' stack-trace-recovery copy of it (same class, the original as its cause),
        // which it makes when an exception crosses dispatchers with assertions on (as in tests).
        assertTrue(thrown === e || thrown.cause === e)
    }

    @Test
    fun `a presentation that fails the SDK's own response checks is not returned`() {
        // Another scheme's system_id.
        assertEquals(CircuitZkStep.BUILD, denied(FakeBinding { response(presentation(systemId = "urn:circuits:longfellow:nym_auth:v1")) }).step)
        // A result handle the request did not ask for, and one missing.
        assertEquals(
            CircuitZkStep.BUILD,
            denied(FakeBinding { response(presentation(handles = mapOf("nym" to ResultValue.Pseudonym(nym), "other" to ResultValue.Predicate))) }).step,
        )
        // A 32-byte pseudonym for hashdh-bls12381g1.
        assertEquals(
            CircuitZkStep.BUILD,
            denied(FakeBinding { response(presentation(handles = mapOf("nym" to ResultValue.Pseudonym(ByteArray(32)), "age" to ResultValue.Predicate))) }).step,
        )
        // Not CBOR at all.
        assertEquals(CircuitZkStep.BUILD, denied(FakeBinding { response(byteArrayOf(1, 2, 3)) }).step)
    }

    @Test
    fun `the default binding is nymauth-native's`() {
        assertEquals("nymauth-native", BbsCdPresenter().implementation)
        assertEquals("urn:mms:bbs-cd:nym_auth:v1", NymAuthNativeBbsCdBinding.systemId)
        assertEquals("bbs-cd-plugins-v0.1", NymAuthNativeBbsCdBinding.proofSystem)
    }
}
