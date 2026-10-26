// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import androidx.test.ext.junit.runners.AndroidJUnit4
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import java.util.Base64
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.siros.sdk.credentials.CircuitZkPlanResult
import org.siros.sdk.credentials.ResultValue
import org.siros.sdk.credentials.SharedCircuitZkPlanner
import org.siros.sdk.credentials.ZkWitnessSigner

/**
 * The SDK's bbs_cd path on the phone: the shared matcher plans a community-demo-shaped `zkp_req` request for the teen's BBS
 * credential (community-demo's demo material), [BbsCdPresenter] checks it and nymauth-native proves, the device key signing
 * through a [ZkWitnessSigner] (here the teen's software key; StrongBox in a wallet). The pseudonym must be the one
 * community-demo derives for the teen (`b9a82517…`); an unmet age range signs nothing; the signer's own exception comes back.
 */
@RunWith(AndroidJUnit4::class)
class BbsCdPresentationTest {

    private val json = Json { ignoreUnknownKeys = true }
    private val wallet: JsonObject = json.parseToJsonElement(
        String(javaClass.classLoader!!.getResourceAsStream("nymauth/teen-bbs.json")!!.use { it.readBytes() }),
    ).jsonObject
    private val holder = wallet["holders"]!!.jsonArray[0].jsonObject
    private val b64u = Base64.getUrlDecoder()

    private val signs = AtomicInteger()

    /** The teen's software device key, signing ES256 as a key store would (raw r || s). */
    private val teenKey = ZkWitnessSigner { alg, data ->
        require(alg == -7L)
        signs.incrementAndGet()
        val d = BigInteger(1, b64u.decode(holder["device_key"]!!.jsonObject["d"]!!.jsonPrimitive.content))
        val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
        val key = KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(d, params))
        val der = Signature.getInstance("SHA256withECDSA").run { initSign(key); update(data); sign() }
        var i = 2
        fun int(): ByteArray {
            val len = der[i + 1].toInt() and 0xff
            val v = BigInteger(1, der.copyOfRange(i + 2, i + 2 + len)).toByteArray()
            i += 2 + len
            return if (v.size >= 32) v.copyOfRange(v.size - 32, v.size) else ByteArray(32 - v.size) + v
        }
        int() + int()
    }

    /** The device public key, uncompressed SEC1, from the JWK. */
    private val devicePublicKey: ByteArray get() {
        val k = holder["device_key"]!!.jsonObject
        return byteArrayOf(4) + b64u.decode(k["x"]!!.jsonPrimitive.content) + b64u.decode(k["y"]!!.jsonPrimitive.content)
    }

    private fun requestObject(age: String) = json.parseToJsonElement(
        """
        {"client_id":"x509_san_dns:community.example","nonce":"0123456789abcdef0123456789abcdef",
         "response_uri":"https://community.example/api/vp/response/s1","response_mode":"direct_post.jwt",
         "dcql_query":{"credentials":[{"id":"nym_attestation_bbs","format":"zkp_req",
           "meta":{"source_format":"bbs_cd","schema_id_value":"eu.europa.ec.eudi.nym_auth.bbs.1"},
           "_req":[{"fn_id":"pseudonym","return":"nym","params":{"config":"known-offender-matching-ssc","ver":1,"prf":"hashdh-bls12381g1"}},
                   {"fn_id":"age_check","return":"age","params":$age}]}]},
         "client_metadata":{"vp_formats_supported":{"zkp_req":{"proof_system_values":["bbs-cd-plugins-v0.1"],"system_id_values":["urn:mms:bbs-cd:nym_auth:v1"]}}}}
        """.trimIndent(),
    ).jsonObject

    private val handover = BbsCdHandover(
        "x509_san_dns:community.example",
        "0123456789abcdef0123456789abcdef",
        "https://community.example/api/vp/response/s1",
        "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
    )

    private fun request(age: String): BbsCdPresenter.Request {
        val ro = requestObject(age)
        val query = ro["dcql_query"]!!.jsonObject["credentials"]!!.jsonArray[0].jsonObject
        val planned = SharedCircuitZkPlanner().plan(query, ro["client_metadata"]!!.jsonObject)
        val plan = (planned as? CircuitZkPlanResult.Plan)?.plan ?: error("the matcher did not plan the request: $planned")
        return BbsCdPresenter.Request(plan, ro, handover, holder["credential"].toString(), devicePublicKey)
    }

    @Test
    fun theTeenPresentsThroughTheSignerWithCommunityDemosPseudonym() = runBlocking {
        val presenter = BbsCdPresenter()
        val t0 = System.nanoTime()
        val r = presenter.present(request("""{"ge":"2008-10-20","le":"2013-10-19"}"""), teenKey)
        val ms = (System.nanoTime() - t0) / 1_000_000
        assertEquals(1, signs.get())
        assertEquals("urn:mms:bbs-cd:nym_auth:v1", r.systemId)
        assertEquals("nymauth-native", r.implementation)
        val nym = (r.results["nym"] as ResultValue.Pseudonym).bytes.joinToString("") { "%02x".format(it) }
        assertEquals(TEEN_BBS_PSEUDONYM, nym)
        assertSame(ResultValue.Predicate, r.results["age"])
        val m = r.metrics!!
        println("BBS-CD teen: present $ms ms, prove ${m.proveMs} ms (device ${m.deviceSignMs} ms), presentation ${m.presentationBytes} B, heap ${m.heapMb} MB")
    }

    @Test
    fun anUnmetAgeRangeSignsNothing() {
        val e = assertThrows(CircuitZkError.AccessDenied::class.java) {
            runBlocking { BbsCdPresenter().present(request("""{"le":"2000-01-01"}"""), teenKey) }
        }
        assertEquals(CircuitZkRefusalReason.UNSATISFIED, e.reason)
        assertEquals(0, signs.get())
    }

    @Test
    fun theSignersOwnExceptionComesBack() {
        class UserCancelled : Exception("cancelled")
        val cancelled = UserCancelled()
        val thrown = assertThrows(UserCancelled::class.java) {
            runBlocking { BbsCdPresenter().present(request("""{"ge":"2008-10-20","le":"2013-10-19"}"""), ZkWitnessSigner { _, _ -> throw cancelled }) }
        }
        assertSame(cancelled, thrown)
        // A signature by another key is refused as a device-signature failure.
        val other = ZkWitnessSigner { _, _ -> ByteArray(64) { 1 } }
        val e = assertThrows(CircuitZkError.AccessDenied::class.java) {
            runBlocking { BbsCdPresenter().present(request("""{"ge":"2008-10-20","le":"2013-10-19"}"""), other) }
        }
        assertTrue(e.reason == CircuitZkRefusalReason.DEVICE_SIGNATURE)
    }

    private companion object {
        /** community-demo's teen BBS pseudonym for `x509_san_dns:community.example` (hashdh-bls12381g1). */
        const val TEEN_BBS_PSEUDONYM =
            "b9a8251758541f1ebcfef8e0cc304303c0afdbed39a2ef68a44f6605505592f62af672818286d6a74ba36d1b420c5d69"
    }
}
