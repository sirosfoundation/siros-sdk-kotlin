// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.github.luben.zstd.Zstd
import java.io.File
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import java.time.Clock
import java.util.Base64
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.AfterClass
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.siros.sdk.credentials.CircuitZkCircuit
import org.siros.sdk.credentials.CircuitZkCircuitSource
import org.siros.sdk.credentials.CircuitZkFunction
import org.siros.sdk.credentials.CircuitZkPlanResult
import org.siros.sdk.credentials.RulebookCircuitZkValidator
import org.siros.sdk.credentials.SharedCircuitZkPlanner
import org.siros.sdk.credentials.ZkArtifact
import org.siros.sdk.credentials.ZkCircuitClient
import org.siros.sdk.credentials.ZkCircuitDescriptor
import org.siros.sdk.credentials.ZkUncompressed
import org.siros.sdk.credentials.ZkWitnessSigner
import timber.log.Timber
import uniffi.nymauth_native.LongfellowPublicValues
import uniffi.nymauth_native.LongfellowVerifier
import uniffi.nymauth_native.NymAuthNativeException as NativeException

/**
 * Both Longfellow implementations through the SDK's whole circuit_zk path (matcher plan, rulebook validator, presenter,
 * catalog prover, nymauth adapter), on community-demo's teen demo mdoc and a request captured from community-demo:
 *
 * - the default, [GoogleLongfellowNymAuthBinding] (Google's longfellow-zk, as community-demo's verifier runs), and
 * - [ZkCredLongfellowNymAuthBinding] (ISRG), swapped in with `UniffiNymAuthNativeProver.withBindings`.
 *
 * Each proof is checked on the phone with nymauth-native's [LongfellowVerifier] (Google's verifier: the ISRG proof
 * must verify there too). Records cold (load + prove) and warm (resident) times and the proof sizes, and writes the
 * presentations to `nymauth-longfellow-implementations.json` in the test app's external files dir, for an optional
 * check against community-demo's own verifier (the test log prints the path; `adb pull` it).
 */
@RunWith(AndroidJUnit4::class)
class NymAuthLongfellowImplementationsTest {

    private val json = Json { ignoreUnknownKeys = true }
    private fun res(name: String): ByteArray = javaClass.classLoader!!.getResourceAsStream("nymauth/$name")!!.use { it.readBytes() }
    private val input: JsonObject = json.parseToJsonElement(String(res("teen-request.json"))).jsonObject
    private fun s(o: JsonObject, k: String) = o[k]!!.jsonPrimitive.content
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun unhex(h: String) = ByteArray(h.length / 2) { h.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
    private val b64u = Base64.getUrlDecoder()

    private val request = input["request"]!!.jsonObject
    private val handover = input["handover"]!!.jsonObject
    private val docType = s(input["credential"]!!.jsonObject, "doctype")
    private val verifierId = s(input, "verifier_id")
    private val circuitZst = res("longfellow-mdoc-circuits.zst")

    private val descriptor = ZkCircuitDescriptor(
        id = CIRCUIT_ID,
        aliases = listOf(SYSTEM_ID),
        system = NymAuthCircuitZkAdapter.LONGFELLOW_SYSTEM,
        systemVersion = "61a8a73",
        docTypes = listOf(docType),
        published = true,
        status = "active",
        params = buildJsonObject {
            put("format", "mdoc")
            put("configuration", "known-offender-matching-ssc")
            put("hash_circuit_id", HASH_ID)
            put("sig_circuit_id", SIG_ID)
            put("block_enc_hash", "6983")
            put("block_enc_sig", "4679")
        },
        artifact = ZkArtifact(
            url = "/v1/artifacts/sha256/$ZST_SHA256",
            hash = "sha256:$ZST_SHA256",
            size = 395_608,
            compression = "zstd",
            uncompressed = ZkUncompressed(hash = "sha256:$CIRCUITS_SHA256", size = 1_062_842),
        ),
        proofSystem = PROOF_SYSTEM,
    )

    private val client = ZkCircuitClient(
        sources = listOf("https://catalog.test"),
        httpGet = { url -> if (url.endsWith("/v1/circuits/$CIRCUIT_ID.json")) Json.encodeToString(ZkCircuitDescriptor.serializer(), descriptor) else null },
        httpGetBytes = { circuitZst },
    )

    private val circuit = CircuitZkCircuit(
        system = NymAuthCircuitZkAdapter.LONGFELLOW_SYSTEM,
        circuitId = CIRCUIT_ID,
        docTypes = setOf(docType),
        functions = setOf("pseudonym", "age_check"),
        aliases = setOf(SYSTEM_ID),
        systemVersion = "61a8a73",
        proofSystem = PROOF_SYSTEM,
    )

    /** The teen's software device key from community-demo's demo wallet, signing as a wallet would (raw r||s). */
    private val signer = ZkWitnessSigner { alg, data ->
        require(alg == -7L)
        val d = BigInteger(1, b64u.decode(s(input["device_key"]!!.jsonObject, "d")))
        val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
        val key = KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(d, params))
        derToRaw(Signature.getInstance("SHA256withECDSA").run { initSign(key); update(data); sign() })
    }

    private fun derToRaw(der: ByteArray): ByteArray {
        var i = 2
        fun int(): ByteArray {
            val len = der[i + 1].toInt() and 0xff
            val v = BigInteger(1, der.copyOfRange(i + 2, i + 2 + len)).toByteArray()
            i += 2 + len
            return when {
                v.size == 32 -> v
                v.size > 32 -> v.copyOfRange(v.size - 32, v.size)
                else -> ByteArray(32 - v.size) + v
            }
        }
        return int() + int()
    }

    /**
     * What the SDK handed the native prover and what came back: the verifier's public values and the proof. The
     * response is copied: the adapter zeroes the returned pseudonym once it has checked it.
     */
    private class Recording(private val inner: UniffiNymAuthNativeProver) : NymAuthNativeProver {
        var request: NymAuthProveRequest? = null
        var response: NymAuthProveResponse? = null
        override suspend fun prove(request: NymAuthProveRequest): NymAuthProveResponse =
            inner.prove(request).also {
                this.request = request
                this.response = NymAuthProveResponse(it.proof.copyOf(), it.pseudonym.copyOf())
            }
        fun release() = inner.release()
    }

    private class Run(val implementation: String, val coldMs: Long, val warmMs: Long, val proof: ByteArray, val pseudonym: ByteArray, val presentation: String)

    private fun presentTwice(prover: UniffiNymAuthNativeProver): Run {
        val implementation = prover.implementationFor(NymAuthCircuitZkAdapter.LONGFELLOW_SYSTEM)!!
        val native = Recording(prover)
        val circuits = CircuitZkCircuitSource { listOf(circuit) }
        val presenter = CircuitZkPresenter(
            prover = CatalogCircuitZkProver(client, native, ZkProverResidency(), Clock.systemUTC()),
            circuits = circuits,
            validator = RulebookCircuitZkValidator(circuits = circuits),
            witnessProvider = object : CircuitZkWitnessProvider {
                override fun witness(function: CircuitZkFunction, needs: Set<CircuitZkWitnessKind>, credentialType: String, issuer: String?) =
                    CircuitZkFunctionWitness()

                override fun privateSeedMatches(credentialType: String, issuer: String?, psc: ByteArray) = false
            },
        )
        val credentialQuery = request["dcql_query"]!!.jsonObject["credentials"]!!.jsonArray[0].jsonObject
        val planned = SharedCircuitZkPlanner().plan(credentialQuery, request["client_metadata"]!!.jsonObject)
        val plan = (planned as? CircuitZkPlanResult.Plan)?.plan ?: error("the matcher did not plan the request: $planned")
        val transcript = MdocDeviceResponseBuilder.buildCircuitZkRedirectSessionTranscript(
            clientId = s(handover, "client_id"),
            nonce = s(handover, "nonce"),
            responseUri = s(handover, "response_uri"),
            verifierJwkThumbprint = s(handover, "jwk_thumbprint"),
        )
        fun present(): Pair<Long, String> {
            val t0 = System.nanoTime()
            val result = runBlocking {
                presenter.present(
                    CircuitZkPresenter.Request(
                        credentialBytes = b64u.decode(s(input["credential"]!!.jsonObject, "issuer_signed")),
                        plan = plan,
                        verifierId = verifierId,
                        sessionTranscript = transcript,
                        secretSeed = unhex(s(input, "secret_seed")),
                    ),
                    signer,
                )
            }
            return (System.nanoTime() - t0) / 1_000_000 to result.json.content
        }
        try {
            val (cold, _) = present()
            val (warm, presentation) = present()
            Timber.i("nymauth Longfellow with $implementation: cold ${cold} ms, warm ${warm} ms, proof ${native.response!!.proof.size} B")
            return Run(implementation, cold, warm, native.response!!.proof, native.response!!.pseudonym, presentation).also {
                verifyWithGoogle(native.request!!, it)
            }
        } finally {
            native.release()
        }
    }

    /** nymauth-native's verifier (Google's longfellow-zk) on the values the SDK proved for. */
    private fun verifyWithGoogle(r: NymAuthProveRequest, run: Run) {
        val circuits = Zstd.decompress(circuitZst, 1_062_842)
        val params = GoogleLongfellowNymAuthBinding.params(r)
        LongfellowVerifier.load(circuits, params, "sha256:$ZST_SHA256").use { verifier ->
            val values = LongfellowPublicValues(
                issuerKeyX = r.issuerKeyX,
                issuerKeyY = r.issuerKeyY,
                time = r.time,
                earliest = r.earliest,
                cutoff = r.cutoff,
                challengeDigest = r.challengeDigest,
                verifierInput = r.verifierInput,
                transcriptSeed = r.transcriptSeed,
            )
            verifier.verify(values, run.proof, run.pseudonym)
            // The same proof under another pseudonym, or for another verifier, must not verify.
            for ((what, check) in listOf<Pair<String, () -> Unit>>(
                "pseudonym" to { verifier.verify(values, run.proof, run.pseudonym.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }) },
                "verifier_input" to { verifier.verify(values.copy(verifierInput = MessageDigest.getInstance("SHA-256").digest("other".toByteArray())), run.proof, run.pseudonym) },
            )) {
                try {
                    check()
                    fail("${run.implementation}: a proof verified with a changed $what")
                } catch (e: NativeException.ProofInvalid) {
                    // expected
                }
            }
        }
    }

    @Test
    fun googleByDefault_isrgSwappedIn_eachVerifiesWithGoogle() {
        Timber.plant(Timber.DebugTree())
        val google = presentTwice(UniffiNymAuthNativeProver())
        val isrg = presentTwice(UniffiNymAuthNativeProver.withBindings(ZkCredLongfellowNymAuthBinding))

        assertEquals("google-longfellow-zk", google.implementation)
        assertEquals("zk-cred-longfellow", isrg.implementation)
        // One holder, one verifier: one pseudonym, whichever implementation proves.
        assertEquals(TEEN_PSEUDONYM, hex(google.pseudonym))
        assertArrayEquals(google.pseudonym, isrg.pseudonym)
        assertTrue("Google's proof is the smaller one (${google.proof.size} vs ${isrg.proof.size})", google.proof.size < isrg.proof.size)

        results += listOf(google, isrg)
    }

    companion object {
        private const val CIRCUIT_ID = "nymauth-longfellow-mdoc-v1"
        private const val SYSTEM_ID = "urn:circuits:longfellow:nym_auth:v1"
        private const val PROOF_SYSTEM = "longfellow-libzk-v1"
        private const val HASH_ID = "5f8c75ae5c3893ef6ab6a079628cb385ba85e95a85437d58570c455289d75729"
        private const val SIG_ID = "00513797c75b2eab1a9db75004977c15317d4e40c0db1d00674523431baa75cb"
        private const val ZST_SHA256 = "6c4b96ed431ee547a3a2e5b62621943a9a0a44646267653bf2db0fcc269b5c3b"
        private const val CIRCUITS_SHA256 = "92dd42fdf99673249eec33c7d07850bd9da66fbdab01ef26391e04c8341c1b7f"
        private const val TEEN_PSEUDONYM = "61266c285395e6fa97f3fa2d93ee428de03d99e9e0e62a3fcc38664faaaa4c30"

        private val results = mutableListOf<Run>()

        @JvmStatic
        @AfterClass
        fun writeResults() {
            if (results.isEmpty()) return
            val out = buildJsonObject {
                put("device", "${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL} (API ${android.os.Build.VERSION.SDK_INT})")
                put("runs", buildJsonArray {
                    results.forEach { r ->
                        add(buildJsonObject {
                            put("implementation", r.implementation)
                            put("cold_ms", r.coldMs)
                            put("warm_ms", r.warmMs)
                            put("proof_bytes", r.proof.size)
                            put("presentation", r.presentation)
                        })
                    }
                })
            }
            val dir = InstrumentationRegistry.getInstrumentation().targetContext.getExternalFilesDir(null)!!
            val file = File(dir, "nymauth-longfellow-implementations.json")
            file.writeText(out.toString())
            results.forEach { println("NYMAUTH ${it.implementation}: cold ${it.coldMs} ms, warm ${it.warmMs} ms, proof ${it.proof.size} B") }
            println("NYMAUTH results: ${file.absolutePath}")
        }
    }
}
