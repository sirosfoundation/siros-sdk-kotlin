// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.openid4vp

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.math.BigInteger
import java.net.URI
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import java.time.Clock
import java.util.Base64
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.siros.sdk.credentials.CircuitZkCircuit
import org.siros.sdk.credentials.CircuitZkCircuitSource
import org.siros.sdk.credentials.CircuitZkFunction
import org.siros.sdk.credentials.RulebookCircuitZkValidator
import org.siros.sdk.credentials.ZkArtifact
import org.siros.sdk.credentials.ZkCircuitClient
import org.siros.sdk.credentials.ZkCircuitDescriptor
import org.siros.sdk.credentials.ZkUncompressed
import org.siros.sdk.credentials.ZkWitnessSigner
import org.siros.sdk.keystore.CatalogCircuitZkProver
import org.siros.sdk.keystore.CircuitZkFunctionWitness
import org.siros.sdk.keystore.CircuitZkPresenter
import org.siros.sdk.keystore.CircuitZkWitnessKind
import org.siros.sdk.keystore.CircuitZkWitnessProvider
import org.siros.sdk.keystore.NymAuthCircuitZkAdapter
import org.siros.sdk.keystore.UniffiNymAuthNativeProver
import org.siros.sdk.keystore.ZkProverResidency

/**
 * The whole backend-free flow against a running community-demo, on the phone: the site starts a session (as its `/dev`
 * view does, 13–17 and the pseudonym), the client fetches and verifies the signed request, the SDK proves with the teen's
 * demo mdoc (Longfellow, the SDK's default implementation), the client posts the encrypted response, and the site says
 * the presentation was verified. A second session is declined, and the site records the denial.
 *
 * Runs only when a verifier is named, and needs Longfellow accepted in its `/tech`:
 * `-Pandroid.testInstrumentationRunnerArguments.verifierOrigin=https://zkp-demo-verifier.fly.dev`.
 */
@RunWith(AndroidJUnit4::class)
class CommunityDemoFlowTest {

    private val origin: String? = InstrumentationRegistry.getArguments().getString("verifierOrigin")?.trimEnd('/')

    private val json = Json { ignoreUnknownKeys = true }
    private fun res(name: String): ByteArray = javaClass.classLoader!!.getResourceAsStream("nymauth/$name")!!.use { it.readBytes() }
    private val teen: JsonObject by lazy { json.parseToJsonElement(String(res("teen-request.json"))).jsonObject }
    private fun s(o: JsonObject, k: String) = o[k]!!.jsonPrimitive.content
    private val b64u = Base64.getUrlDecoder()

    /** The site's session belongs to this "browser": its cookie. */
    private val site = OkHttpClient.Builder()
        .cookieJar(object : CookieJar {
            private val cookies = mutableListOf<Cookie>()
            override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
                this.cookies.removeAll { c -> cookies.any { it.name == c.name } }
                this.cookies += cookies
            }
            override fun loadForRequest(url: HttpUrl) = cookies.toList()
        })
        .readTimeout(60, TimeUnit.SECONDS)
        .build()

    private fun siteCall(path: String, body: JsonObject? = null): JsonObject {
        val builder = Request.Builder().url("$origin$path")
        if (body != null) builder.post(body.toString().toRequestBody("application/json".toMediaType()))
        site.newCall(builder.build()).execute().use { r ->
            val text = r.body?.string().orEmpty()
            assumeTrue("the site answered $path with ${r.code}: $text (is Longfellow accepted in /tech?)", r.isSuccessful)
            return json.parseToJsonElement(text).jsonObject
        }
    }

    private fun newSession(): Pair<String, String> {
        val created = siteCall("/api/vp/session", buildJsonObject { put("purpose", "dev"); put("age", "range13to17"); put("origin", origin) })
        return s(created, "id") to s(created, "authorizationUrl")
    }

    private val circuit = CircuitZkCircuit(
        system = NymAuthCircuitZkAdapter.LONGFELLOW_SYSTEM,
        circuitId = CIRCUIT_ID,
        docTypes = setOf(DOC_TYPE),
        functions = setOf("pseudonym", "age_check"),
        aliases = setOf(SYSTEM_ID),
        systemVersion = "61a8a73",
        proofSystem = PROOF_SYSTEM,
    )

    private val presenter by lazy {
        val zst = res("longfellow-mdoc-circuits.zst")
        val descriptor = ZkCircuitDescriptor(
            id = CIRCUIT_ID,
            aliases = listOf(SYSTEM_ID),
            system = NymAuthCircuitZkAdapter.LONGFELLOW_SYSTEM,
            systemVersion = "61a8a73",
            docTypes = listOf(DOC_TYPE),
            published = true,
            status = "active",
            params = buildJsonObject {
                put("format", "mdoc")
                put("configuration", "known-offender-matching-ssc")
                put("hash_circuit_id", "5f8c75ae5c3893ef6ab6a079628cb385ba85e95a85437d58570c455289d75729")
                put("sig_circuit_id", "00513797c75b2eab1a9db75004977c15317d4e40c0db1d00674523431baa75cb")
                put("block_enc_hash", "6983")
                put("block_enc_sig", "4679")
            },
            artifact = ZkArtifact(
                url = "/v1/artifacts/sha256/$ZST_SHA256",
                hash = "sha256:$ZST_SHA256",
                size = zst.size.toLong(),
                compression = "zstd",
                uncompressed = ZkUncompressed(hash = "sha256:92dd42fdf99673249eec33c7d07850bd9da66fbdab01ef26391e04c8341c1b7f", size = 1_062_842),
            ),
            proofSystem = PROOF_SYSTEM,
        )
        // The circuit is bundled: the catalog client serves it from the test's resources.
        val catalog = ZkCircuitClient(
            sources = listOf("https://catalog.test"),
            httpGet = { url -> if (url.endsWith("/v1/circuits/$CIRCUIT_ID.json")) Json.encodeToString(ZkCircuitDescriptor.serializer(), descriptor) else null },
            httpGetBytes = { zst },
        )
        val circuits = CircuitZkCircuitSource { listOf(circuit) }
        CircuitZkPresenter(
            prover = CatalogCircuitZkProver(catalog, UniffiNymAuthNativeProver(), ZkProverResidency(), Clock.systemUTC()),
            circuits = circuits,
            validator = RulebookCircuitZkValidator(circuits = circuits),
            witnessProvider = object : CircuitZkWitnessProvider {
                override fun witness(function: CircuitZkFunction, needs: Set<CircuitZkWitnessKind>, credentialType: String, issuer: String?) =
                    CircuitZkFunctionWitness()

                override fun privateSeedMatches(credentialType: String, issuer: String?, psc: ByteArray) = false
            },
        )
    }

    /** The teen's software device key from community-demo's demo wallet (raw r||s). */
    private val signer = ZkWitnessSigner { alg, data ->
        require(alg == -7L)
        val d = BigInteger(1, b64u.decode(s(teen["device_key"]!!.jsonObject, "d")))
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

    private fun client() = OpenId4VpClient(AllowedHostsTrustPolicy(setOf(URI(origin!!).host)))

    @Test
    fun presentsToCommunityDemo_andTheSiteVerifies() = runBlocking {
        assumeTrue("no verifierOrigin given", origin != null)
        val (id, url) = newSession()
        val client = client()
        val request = client.fetchRequest(url, WalletMetadata.circuitZk(listOf(circuit)))
        val query = request.circuitZkQueries.firstOrNull { (it["meta"] as? JsonObject)?.get("source_format")?.jsonPrimitive?.content == "mso_mdoc" }
        assumeTrue("the site offers no mso_mdoc zkp_req query (is Longfellow accepted in /tech?)", query != null)
        val queryId = s(query!!, "id")

        val responder = CircuitZkResponder(presenter)
        val plan = responder.plan(request, queryId)
        val seed = ByteArray(16).also { s(teen, "secret_seed").chunked(2).forEachIndexed { k, h -> it[k] = h.toInt(16).toByte() } }
        val presentation = responder.present(
            request,
            queryId,
            plan,
            credentialBytes = b64u.decode(s(teen["credential"]!!.jsonObject, "issuer_signed")),
            secretSeed = seed,
            signer = signer,
        )
        seed.fill(0)
        client.sendPresentation(request, presentation.vpToken)

        val status = siteCall("/api/vp/session/$id")
        println("COMMUNITY-DEMO: ${request.clientId} answered, session ${s(status, "status")}, proof ${status["proof"]}")
        assertEquals(status.toString(), "verified", s(status, "status"))
    }

    @Test
    fun declinesACommunityDemoRequest_andTheSiteRecordsTheDenial() = runBlocking {
        assumeTrue("no verifierOrigin given", origin != null)
        val (id, url) = newSession()
        val client = client()
        val request = client.fetchRequest(url, WalletMetadata.circuitZk(listOf(circuit)))
        client.sendError(request, OpenId4VpClient.ERROR_ACCESS_DENIED)
        val status = siteCall("/api/vp/session/$id")
        assertEquals(status.toString(), "failed", s(status, "status"))
        assertEquals(status.toString(), "denied", s(status, "failure"))
    }

    private companion object {
        const val CIRCUIT_ID = "nymauth-longfellow-mdoc-v1"
        const val SYSTEM_ID = "urn:circuits:longfellow:nym_auth:v1"
        const val PROOF_SYSTEM = "longfellow-libzk-v1"
        const val DOC_TYPE = "eu.europa.ec.eudi.nym_auth.1"
        const val ZST_SHA256 = "6c4b96ed431ee547a3a2e5b62621943a9a0a44646267653bf2db0fcc269b5c3b"
    }
}
