package org.siros.sdk.keystore

import com.upokecenter.cbor.CBORObject
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.siros.sdk.credentials.CircuitZkCircuit
import org.siros.sdk.credentials.CircuitZkCircuitSource
import org.siros.sdk.credentials.CircuitZkFunction
import org.siros.sdk.credentials.CircuitZkPlan
import org.siros.sdk.credentials.CircuitZkPresentationCodec
import org.siros.sdk.credentials.CircuitZkRequestValidator
import org.siros.sdk.credentials.CircuitZkVerdict
import org.siros.sdk.credentials.IssuerKeySet
import org.siros.sdk.credentials.NymPseudonym
import org.siros.sdk.credentials.ResultValue
import org.siros.sdk.credentials.ZkWitnessSigner
import timber.log.Timber

/** [CircuitZkPresenter] with the fake prover, a fake signer and a fixed-root seed source. */
class CircuitZkPresenterTest {
    private val docType = "eu.europa.ec.eudi.nym_auth.1"
    private val root = ByteArray(32) { (it * 3).toByte() }
    private val seeds = PrivateSeed(object : RootSecret {
        override fun deriveSecret(info: ByteArray, length: Int) = hkdf(root, info, length)
    })

    /** An independent HKDF-SHA256 (RFC 5869), not the keystore's. */
    private fun hkdf(ikm: ByteArray, info: ByteArray, length: Int): ByteArray {
        val prk = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(ByteArray(32), "HmacSHA256")) }.doFinal(ikm)
        val t1 = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(prk, "HmacSHA256")) }.doFinal(info + byteArrayOf(1))
        return t1.copyOf(length)
    }

    private val seed16 get() = hkdf(root, "org.siros.private_seed/v1$docType".toByteArray(), 16)
    private val goodPsc get() = MessageDigest.getInstance("SHA-256").digest(seed16)
    private val cert = ByteArray(40) { (it + 7).toByte() }

    private fun cbor(o: Any) = CBORObject.FromObject(o)

    private fun item(id: Int, name: String, value: CBORObject): CBORObject {
        val m = CBORObject.NewMap()
        m[cbor("digestID")] = cbor(id.toLong())
        m[cbor("random")] = cbor(ByteArray(16))
        m[cbor("elementIdentifier")] = cbor(name)
        m[cbor("elementValue")] = value
        return CBORObject.FromObjectAndTag(m.EncodeToBytes(), 24)
    }

    private fun credential(
        docType: String = this.docType,
        birth: String? = "2000-06-15",
        psc: ByteArray? = goodPsc,
        withX5chain: Boolean = true,
        /** Namespace holding the claims; the credential's doctype by default. */
        claimsNamespace: String = docType,
        /** Elements of a namespace that precedes the claims namespace (a decoy). */
        decoyFirst: List<CBORObject> = emptyList(),
        /** Repeat birth_date inside the claims namespace. */
        duplicateBirth: Boolean = false,
        /** The `ssc` value; null leaves the element out. */
        ssc: CBORObject? = cbor(ByteArray(32) { 9 }),
        /** Repeat ssc inside the claims namespace, with this value. */
        duplicateSsc: CBORObject? = null,
    ): ByteArray {
        val items = CBORObject.NewArray()
        var id = 0
        if (birth != null) items.Add(item(id++, "birth_date", CBORObject.FromObjectAndTag(birth, 1004)))
        if (ssc != null) items.Add(item(id++, "ssc", ssc))
        if (duplicateSsc != null) items.Add(item(91, "ssc", duplicateSsc))
        if (psc != null) items.Add(item(id, "psc", cbor(psc)))
        if (duplicateBirth) items.Add(item(90, "birth_date", CBORObject.FromObjectAndTag("2000-06-15", 1004)))
        val ns = CBORObject.NewMap()
        if (decoyFirst.isNotEmpty()) ns[cbor("org.example.decoy")] = CBORObject.NewArray().also { a -> decoyFirst.forEach { a.Add(it) } }
        ns[cbor(claimsNamespace)] = items
        val mso = CBORObject.NewMap()
        mso[cbor("docType")] = cbor(docType)
        val unprotected = CBORObject.NewMap()
        if (withX5chain) unprotected[cbor(33)] = cbor(cert)
        val auth = CBORObject.NewArray()
        auth.Add(cbor(ByteArray(0)))
        auth.Add(unprotected)
        auth.Add(cbor(CBORObject.FromObjectAndTag(mso.EncodeToBytes(), 24).EncodeToBytes()))
        auth.Add(cbor(ByteArray(64)))
        val signed = CBORObject.NewMap()
        signed[cbor("nameSpaces")] = ns
        signed[cbor("issuerAuth")] = auth
        return signed.EncodeToBytes()
    }

    private fun params(json: String): JsonObject = Json.parseToJsonElement(json).jsonObject
    private fun pseudonymFn(config: String = "known-offender-matching-psc", handle: String = "n") =
        CircuitZkFunction("pseudonym-v1-sha256", handle, params("""{"config":"$config","verifier_id_type":"x509_san_dns"}"""))
    private fun ageFn(json: String = """{"ge":"1990-01-01"}""", handle: String = "a") = CircuitZkFunction("age_check", handle, params(json))
    private fun plan(vararg fns: CircuitZkFunction, doctype: String = docType) = CircuitZkPlan(
        functions = fns.toList(),
        raw = params("""{"id":"q","format":"circuit_zk","meta":{"doctype_value":"$doctype"}}"""),
    )

    private val circuit = CircuitZkCircuit("sys", "circuit-1", setOf(docType))
    private val signer = ZkWitnessSigner { _, _ -> error("the fake prover never asks for a signature") }

    private class CountingProver(val inner: CircuitZkProver, val override: (() -> CircuitZkProveOutput)? = null) : CircuitZkProver {
        var calls = 0
        override val isFake get() = inner.isFake
        override suspend fun prove(input: CircuitZkProveInput): CircuitZkProveOutput {
            calls++
            return override?.invoke() ?: inner.prove(input)
        }
    }

    private fun presenter(
        prover: CircuitZkProver = FakeCircuitZkProver.optIn(),
        circuits: List<CircuitZkCircuit> = listOf(circuit),
        validator: CircuitZkRequestValidator = CircuitZkRequestValidator.PERMISSIVE,
        userValue: ByteArray? = null,
    ) = CircuitZkPresenter(prover, { circuits }, validator, HolderWitnessProvider(seeds, userValue))

    private fun request(
        cred: ByteArray = credential(),
        p: CircuitZkPlan = plan(pseudonymFn(), ageFn()),
        verifierId: String? = "rp.example",
        secretSeed: ByteArray? = null,
        verifierContext: String? = null,
    ) = CircuitZkPresenter.Request(cred, p, verifierId, verifierContext, byteArrayOf(1, 2, 3), secretSeed)

    /** A delivered secret_seed (16 bytes) and the ssc it opens; independent of the presenter. */
    private val secretSeedA get() = ByteArray(16) { it.toByte() }
    private val secretSeedB get() = ByteArray(16) { (0xA0 + it).toByte() }
    private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)
    private fun sscCred(seed: ByteArray = secretSeedA, ssc: CBORObject? = cbor(sha256(seed))) = credential(ssc = ssc)
    private val sscPlan get() = plan(pseudonymFn("known-offender-matching-ssc"), ageFn())

    private fun present(pr: CircuitZkPresenter, r: CircuitZkPresenter.Request) = runBlocking { pr.present(r, signer) }

    private fun assertDenied(step: CircuitZkStep, block: () -> Unit) {
        try {
            block()
            fail("expected a refusal at $step")
        } catch (e: CircuitZkError.AccessDenied) {
            assertEquals(step, e.step)
            assertEquals("circuit_zk request refused", e.message)
        }
    }

    // -------- logs --------

    private val logs = mutableListOf<String>()
    private val tree = object : Timber.Tree() {
        override fun log(priority: Int, tag: String?, message: String, t: Throwable?) {
            logs += message + (t?.toString() ?: "")
        }
    }

    @Before fun plant() = Timber.plant(tree)

    @After fun uproot() = Timber.uproot(tree)

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    // -------- the happy path --------

    @Test
    fun `a presentation decodes and its pseudonym equals an independent recompute`() {
        val result = present(presenter(), request())
        val decoded = CircuitZkPresentationCodec.decodeBase64Url(result.base64Url)

        val expected = NymPseudonym.derive("known-offender-matching-psc", seed16, verifierId = "rp.example")
        assertEquals(ResultValue.Pseudonym(expected), decoded.results["n"])
        assertEquals(ResultValue.Predicate, decoded.results["a"])
        assertEquals("circuit-1", decoded.circuitId)
        assertEquals("circuit-1", result.circuitId)
        assertArrayEquals(FakeCircuitZkProver.DUMMY_PROOF, decoded.proof)
        assertEquals(IssuerKeySet.DerCertificates(listOf(cert)), decoded.issuerKeySet)
        assertNull(decoded.proofTime)
    }

    @Test
    fun `results keys are exactly the plan's handles`() {
        val p = plan(pseudonymFn(handle = "h-nym"), ageFn(handle = "h-age"))
        val decoded = CircuitZkPresentationCodec.decodeBase64Url(present(presenter(), request(p = p)).base64Url)
        assertEquals(setOf("h-nym", "h-age"), decoded.results.keys)
        decoded.requireResultHandles(setOf("h-nym", "h-age"))
    }

    @Test
    fun `an age_check alone needs no seed and no psc`() {
        val decoded = CircuitZkPresentationCodec.decodeBase64Url(
            present(presenter(), request(cred = credential(psc = null), p = plan(ageFn()))).base64Url,
        )
        assertEquals(setOf("a"), decoded.results.keys)
    }

    @Test
    fun `age bounds are inclusive`() {
        val b = credential(birth = "2000-06-15")
        for (json in listOf("""{"ge":"2000-06-15"}""", """{"le":"2000-06-15"}""", """{"ge":"2000-06-15","le":"2001-06-14"}""")) {
            present(presenter(), request(cred = b, p = plan(ageFn(json))))
        }
    }

    @Test
    fun `the circuit is the first that supports the plan`() {
        val circuits = listOf(
            CircuitZkCircuit("sys", "wrong-doctype", setOf("other")),
            CircuitZkCircuit("sys", "no-age", setOf(docType), functions = setOf("pseudonym-v1-sha256")),
            CircuitZkCircuit("sys", "right", setOf(docType), functions = setOf("pseudonym-v1-sha256", "age_check")),
        )
        assertEquals("right", present(presenter(circuits = circuits), request()).circuitId)
    }

    // -------- refusals --------

    @Test
    fun `a psc mismatch is refused and nothing is proved`() {
        val prover = CountingProver(FakeCircuitZkProver.optIn())
        assertDenied(CircuitZkStep.COMMITMENT) { present(presenter(prover), request(cred = credential(psc = ByteArray(32)))) }
        assertDenied(CircuitZkStep.COMMITMENT) { present(presenter(prover), request(cred = credential(psc = null))) }
        assertDenied(CircuitZkStep.COMMITMENT) { present(presenter(prover), request(cred = credential(psc = goodPsc.copyOf(31)))) }
        assertEquals(0, prover.calls)
    }

    @Test
    fun `a decoy namespace listed first is refused and nothing is proved`() {
        val prover = CountingProver(FakeCircuitZkProver.optIn())
        val decoyBirth = item(70, "birth_date", CBORObject.FromObjectAndTag("2015-01-01", 1004))
        assertDenied(CircuitZkStep.NAMESPACE) {
            present(presenter(prover), request(cred = credential(decoyFirst = listOf(decoyBirth)), p = plan(ageFn("""{"le":"2005-01-01"}"""))))
        }
        val decoyPsc = item(71, "psc", cbor(goodPsc))
        assertDenied(CircuitZkStep.NAMESPACE) {
            present(presenter(prover), request(cred = credential(psc = ByteArray(32), decoyFirst = listOf(decoyPsc))))
        }
        assertEquals(0, prover.calls)
    }

    @Test
    fun `a credential without the doctype namespace is refused`() {
        val prover = CountingProver(FakeCircuitZkProver.optIn())
        assertDenied(CircuitZkStep.NAMESPACE) { present(presenter(prover), request(cred = credential(claimsNamespace = "org.example.other"))) }
        assertDenied(CircuitZkStep.NAMESPACE) {
            present(presenter(prover), request(cred = credential(claimsNamespace = "org.example.other"), p = plan(ageFn())))
        }
        assertEquals(0, prover.calls)
    }

    @Test
    fun `a claim repeated inside the doctype namespace is refused`() {
        val prover = CountingProver(FakeCircuitZkProver.optIn())
        assertDenied(CircuitZkStep.PREDICATE) { present(presenter(prover), request(cred = credential(duplicateBirth = true), p = plan(ageFn()))) }
        assertEquals(0, prover.calls)
    }

    @Test
    fun `a false predicate yields no presentation`() {
        val prover = CountingProver(FakeCircuitZkProver.optIn())
        assertDenied(CircuitZkStep.PREDICATE) { present(presenter(prover), request(p = plan(pseudonymFn(), ageFn("""{"ge":"2010-01-01"}""")))) }
        assertDenied(CircuitZkStep.PREDICATE) { present(presenter(prover), request(p = plan(ageFn("""{"le":"1999-12-31"}""")))) }
        assertDenied(CircuitZkStep.PREDICATE) { present(presenter(prover), request(cred = credential(birth = null), p = plan(ageFn()))) }
        assertDenied(CircuitZkStep.PREDICATE) { present(presenter(prover), request(p = plan(ageFn("""{}""")))) }
        assertEquals(0, prover.calls)
    }

    @Test
    fun `a validator failure is refused`() {
        val prover = CountingProver(FakeCircuitZkProver.optIn())
        assertDenied(CircuitZkStep.VALIDATE) {
            present(presenter(prover, validator = { CircuitZkVerdict.AccessDenied("secret-rule") }), request())
        }
        assertEquals(0, prover.calls)
    }

    @Test
    fun `a wrong doctype is refused`() {
        assertDenied(CircuitZkStep.DOCTYPE) { present(presenter(), request(p = plan(pseudonymFn(), doctype = "other.doctype"))) }
        assertDenied(CircuitZkStep.DOCTYPE) { present(presenter(), request(cred = credential(docType = "other.doctype"))) }
        assertDenied(CircuitZkStep.DOCTYPE) {
            present(presenter(), request(p = CircuitZkPlan(listOf(ageFn()), raw = params("""{"meta":{}}"""))))
        }
    }

    @Test
    fun `no fitting circuit is refused`() {
        assertDenied(CircuitZkStep.CIRCUIT) { present(presenter(circuits = emptyList()), request()) }
        assertDenied(CircuitZkStep.CIRCUIT) { present(presenter(circuits = listOf(CircuitZkCircuit("s", "c", setOf("other")))), request()) }
        assertDenied(CircuitZkStep.CIRCUIT) {
            present(presenter(circuits = listOf(CircuitZkCircuit("s", "c", setOf(docType), functions = setOf("age_check")))), request())
        }
        assertDenied(CircuitZkStep.CIRCUIT) {
            val withFilter = request(p = plan(pseudonymFn(), ageFn()).copy(circuitFilter = org.siros.sdk.credentials.CircuitZkCircuitFilter(listOf("sys"), listOf("other"))))
            present(presenter(), withFilter)
        }
    }

    @Test
    fun `a witness the wallet cannot supply is refused, including every secret-seed config without a seed`() {
        val prover = CountingProver(FakeCircuitZkProver.optIn())
        for (config in listOf("known-offender-matching-ssc", "account-recovery-ssc", "user-managed-pseudonym-xsite-ssc", "made-up")) {
            assertDenied(CircuitZkStep.WITNESS) { present(presenter(prover), request(p = plan(pseudonymFn(config)))) }
        }
        assertEquals(0, prover.calls)
    }

    @Test
    fun `a prover that returns other handles, fails, or refuses is refused`() {
        val wrong = CountingProver(FakeCircuitZkProver.optIn(), override = { CircuitZkProveOutput(ByteArray(1), mapOf("zzz" to ResultValue.Predicate)) })
        assertDenied(CircuitZkStep.PROVE) { present(presenter(wrong), request(p = plan(ageFn()))) }
        val extra = CountingProver(FakeCircuitZkProver.optIn(), override = {
            CircuitZkProveOutput(ByteArray(1), mapOf("a" to ResultValue.Predicate, "extra" to ResultValue.Predicate))
        })
        assertDenied(CircuitZkStep.PROVE) { present(presenter(extra), request(p = plan(ageFn()))) }
        val boom = CountingProver(FakeCircuitZkProver.optIn(), override = { error("native crash with seed ${hex(seed16)}") })
        assertDenied(CircuitZkStep.PROVE) { present(presenter(boom), request(p = plan(ageFn()))) }
    }

    @Test
    fun `a cancelled prover is cancellation, not a refusal, while any other failure stays a silent refusal`() {
        val cancelled = CountingProver(FakeCircuitZkProver.optIn(), override = { throw kotlinx.coroutines.CancellationException("cancelled") })
        try {
            present(presenter(cancelled), request(p = plan(ageFn())))
            fail("cancellation must propagate")
        } catch (e: kotlinx.coroutines.CancellationException) {
            // expected
        }
        assertEquals(1, cancelled.calls)
        val boom = CountingProver(FakeCircuitZkProver.optIn(), override = { error("x") })
        assertDenied(CircuitZkStep.PROVE) { present(presenter(boom), request(p = plan(ageFn()))) }
    }

    @Test
    fun `a credential without an x5chain is refused`() {
        assertDenied(CircuitZkStep.BUILD) { present(presenter(), request(cred = credential(withX5chain = false))) }
    }

    @Test
    fun `malformed requests are InvalidRequest`() {
        fun invalid(block: () -> Unit) {
            try {
                block()
                fail()
            } catch (e: CircuitZkError.InvalidRequest) {
                assertEquals("circuit_zk request invalid", e.message)
            }
        }
        invalid { present(presenter(), request(cred = byteArrayOf(1, 2, 3))) }
        invalid { present(presenter(), request(p = plan())) }
        invalid { present(presenter(), request(p = plan(ageFn(handle = "x"), ageFn("""{"le":"2020-01-01"}""", handle = "x")))) }
        invalid { present(presenter(), request(p = plan(CircuitZkFunction("future_fn", "f", JsonObject(emptyMap()))))) }
    }

    // -------- secrecy --------

    @Test
    fun `no seed or psc bytes appear in logs, messages or the witness`() {
        val secrets = listOf(hex(seed16), hex(goodPsc))
        try {
            present(presenter(), request(cred = credential(psc = ByteArray(32))))
        } catch (e: CircuitZkError) {
            for (s in secrets) {
                assertFalse(e.toString().contains(s))
                assertFalse(e.message!!.contains(s))
            }
        }
        val boom = CountingProver(FakeCircuitZkProver.optIn(), override = { error("x") })
        runCatching { present(presenter(boom), request()) }
        present(presenter(), request())
        for (line in logs) for (s in secrets) assertFalse(line, line.contains(s))
        assertEquals("CircuitZkFunctionWitness(redacted)", CircuitZkFunctionWitness(seed16).toString())
    }

    // -------- secret_seed (issuer-delivered), checked against ssc --------

    private fun sscRequest(
        seed: ByteArray? = secretSeedA,
        cred: ByteArray = sscCred(),
        config: String = "known-offender-matching-ssc",
    ) = request(cred = cred, p = plan(pseudonymFn(config), ageFn()), secretSeed = seed)

    @Test
    fun `each secret-seed config presents with a seed that opens ssc and equals an independent recompute`() {
        val seed = secretSeedA
        val kom = CircuitZkPresentationCodec.decodeBase64Url(present(presenter(), sscRequest(seed)).base64Url)
        assertEquals(
            ResultValue.Pseudonym(NymPseudonym.derive("known-offender-matching-ssc", seed, verifierId = "rp.example")),
            kom.results["n"],
        )
        val recovery = CircuitZkPresentationCodec.decodeBase64Url(
            present(
                presenter(),
                request(sscCred(), plan(pseudonymFn("account-recovery-ssc"), ageFn()), secretSeed = seed, verifierContext = "ctx-1"),
            ).base64Url,
        )
        assertEquals(
            ResultValue.Pseudonym(NymPseudonym.derive("account-recovery-ssc", seed, verifierId = "rp.example", verifierContext = "ctx-1")),
            recovery.results["n"],
        )
        val userValue = byteArrayOf(5, 6, 7)
        val xsite = CircuitZkPresentationCodec.decodeBase64Url(
            present(
                presenter(userValue = userValue),
                request(sscCred(), plan(pseudonymFn("user-managed-pseudonym-xsite-ssc"), ageFn()), verifierId = null, secretSeed = seed),
            ).base64Url,
        )
        assertEquals(
            ResultValue.Pseudonym(NymPseudonym.derive("user-managed-pseudonym-xsite-ssc", seed, proverInput = userValue)),
            xsite.results["n"],
        )
    }

    @Test
    fun `a secret-seed config without a seed, or with a seed of the wrong length, is refused at the witness step`() {
        val prover = CountingProver(FakeCircuitZkProver.optIn())
        for (bad in listOf<ByteArray?>(null, ByteArray(0), ByteArray(15), ByteArray(17), ByteArray(32))) {
            assertDenied(CircuitZkStep.WITNESS) { present(presenter(prover), sscRequest(bad)) }
        }
        // The xsite config also needs the user value; a missing one is a witness refusal as well.
        assertDenied(CircuitZkStep.WITNESS) {
            present(presenter(prover), sscRequest(secretSeedA, config = "user-managed-pseudonym-xsite-ssc"))
        }
        assertEquals(0, prover.calls)
    }

    @Test
    fun `a seed that does not open ssc is refused and the prover is never called`() {
        val prover = CountingProver(FakeCircuitZkProver.optIn())
        // The seed of another credential, a flipped bit, and an ssc that is the seed itself.
        assertDenied(CircuitZkStep.SECRET_COMMITMENT) { present(presenter(prover), sscRequest(secretSeedB)) }
        val flipped = secretSeedA.also { it[3] = (it[3].toInt() xor 1).toByte() }
        assertDenied(CircuitZkStep.SECRET_COMMITMENT) { present(presenter(prover), sscRequest(flipped)) }
        assertDenied(CircuitZkStep.SECRET_COMMITMENT) {
            present(presenter(prover), sscRequest(cred = sscCred(ssc = cbor(ByteArray(32)))))
        }
        assertEquals(0, prover.calls)
    }

    @Test
    fun `an ssc that is absent, not a bstr, the wrong length or duplicated is refused and nothing is proved`() {
        val prover = CountingProver(FakeCircuitZkProver.optIn())
        val good = sha256(secretSeedA)
        val cases = mapOf(
            "absent" to credential(ssc = null),
            "text" to credential(ssc = cbor(hex(good))),
            "31 bytes" to credential(ssc = cbor(good.copyOf(31))),
            "33 bytes" to credential(ssc = cbor(good + byteArrayOf(0))),
            "empty" to credential(ssc = cbor(ByteArray(0))),
            "duplicate, both valid" to credential(ssc = cbor(good), duplicateSsc = cbor(good)),
            "duplicate, decoy second" to credential(ssc = cbor(good), duplicateSsc = cbor(ByteArray(32))),
        )
        for ((name, cred) in cases) {
            try {
                present(presenter(prover), sscRequest(cred = cred))
                fail("$name: expected a refusal")
            } catch (e: CircuitZkError.AccessDenied) {
                assertEquals(name, CircuitZkStep.SECRET_COMMITMENT, e.step)
            }
        }
        assertEquals(0, prover.calls)
    }

    @Test
    fun `an ssc in another namespace is never consulted`() {
        val prover = CountingProver(FakeCircuitZkProver.optIn())
        val decoySsc = item(72, "ssc", cbor(sha256(secretSeedA)))
        assertDenied(CircuitZkStep.NAMESPACE) {
            present(presenter(prover), sscRequest(cred = credential(ssc = cbor(ByteArray(32)), decoyFirst = listOf(decoySsc))))
        }
        assertEquals(0, prover.calls)
    }

    @Test
    fun `a supplied seed does not weaken a psc config and is not used by it`() {
        // A psc request still needs the right psc, whatever seed rides along.
        assertDenied(CircuitZkStep.COMMITMENT) {
            present(presenter(), request(cred = credential(psc = ByteArray(32)), secretSeed = secretSeedA))
        }
        val witnessSeen = mutableListOf<CircuitZkFunctionWitness>()
        val spy = object : CircuitZkProver {
            override suspend fun prove(input: CircuitZkProveInput): CircuitZkProveOutput {
                witnessSeen += input.witnesses.getValue("n")
                return FakeCircuitZkProver.optIn().prove(input)
            }
        }
        present(presenter(spy), request(secretSeed = secretSeedA))
        assertNull(witnessSeen.single().secretSeed)
    }

    @Test
    fun `the presenter zeroes its copy of the seed and leaves the caller's array alone`() {
        val callers = secretSeedA
        val seen = mutableListOf<ByteArray>()
        val spy = object : CircuitZkProver {
            override suspend fun prove(input: CircuitZkProveInput): CircuitZkProveOutput {
                val s = input.witnesses.getValue("n").secretSeed!!
                assertArrayEquals(secretSeedA, s) // live while proving
                seen += s
                return FakeCircuitZkProver.optIn().prove(input)
            }
        }
        present(presenter(spy), sscRequest(callers))
        assertEquals(1, seen.size)
        assertTrue(seen.single().all { it == 0.toByte() })
        assertArrayEquals(secretSeedA, callers)
        assertTrue(seen.single() !== callers)
        // The copy is zeroed on a failing prover as well.
        val seen2 = mutableListOf<ByteArray>()
        val boom = object : CircuitZkProver {
            override suspend fun prove(input: CircuitZkProveInput): CircuitZkProveOutput {
                seen2 += input.witnesses.getValue("n").secretSeed!!
                error("prover crash")
            }
        }
        assertDenied(CircuitZkStep.PROVE) { present(presenter(boom), sscRequest(secretSeedA)) }
        assertTrue(seen2.single().all { it == 0.toByte() })
    }

    @Test
    fun `the secret seed and its hex appear in no log, error, witness or token`() {
        val seed = secretSeedA
        val secrets = listOf(hex(seed), hex(seed).uppercase(), java.util.Base64.getEncoder().encodeToString(seed))
        val boom = CountingProver(FakeCircuitZkProver.optIn(), override = { error("x") })
        val results = mutableListOf<String>()
        for (r in listOf(sscRequest(secretSeedB), sscRequest(seed.copyOf(15)), sscRequest(seed, boom.let { sscCred(ssc = null) }))) {
            try {
                present(presenter(), r)
            } catch (e: CircuitZkError) {
                results += e.toString() + (e.message ?: "")
            }
        }
        try { present(presenter(boom), sscRequest(seed)) } catch (e: CircuitZkError) { results += e.toString() }
        val ok = present(presenter(), sscRequest(seed))
        results += ok.base64Url
        results += ok.results.toString()
        results += CircuitZkFunctionWitness(secretSeed = seed).toString()
        results += logs
        for (line in results) for (s in secrets) assertFalse(line, line.contains(s))
        // The seed is not even in the encoded presentation bytes.
        val raw = java.util.Base64.getUrlDecoder().decode(ok.base64Url)
        assertTrue(indexOf(raw, seed) < 0)
    }

    private fun indexOf(hay: ByteArray, needle: ByteArray): Int {
        outer@ for (i in 0..hay.size - needle.size) {
            for (j in needle.indices) if (hay[i + j] != needle[j]) continue@outer
            return i
        }
        return -1
    }

    @Test
    fun `witness needs name the seed kind of each config and the default provider never supplies a secret seed`() {
        fun needs(config: String) = PseudonymFunctionHandler.witnessNeeds(pseudonymFn(config))
        assertEquals(setOf(CircuitZkWitnessKind.PRIVATE_SEED), needs("known-offender-matching-psc"))
        assertEquals(setOf(CircuitZkWitnessKind.SECRET_SEED), needs("known-offender-matching-ssc"))
        assertEquals(setOf(CircuitZkWitnessKind.SECRET_SEED), needs("account-recovery-ssc"))
        assertEquals(setOf(CircuitZkWitnessKind.SECRET_SEED, CircuitZkWitnessKind.USER_VALUE), needs("user-managed-pseudonym-xsite-ssc"))
        assertEquals(setOf(CircuitZkWitnessKind.NOT_HELD_BY_WALLET), needs("made-up"))
        val provider = HolderWitnessProvider(seeds, byteArrayOf(1))
        assertNull(provider.witness(pseudonymFn("known-offender-matching-ssc"), setOf(CircuitZkWitnessKind.SECRET_SEED), docType))
        assertNull(provider.witness(pseudonymFn("known-offender-matching-ssc"), setOf(CircuitZkWitnessKind.NOT_HELD_BY_WALLET), docType))
    }

    @Test
    fun `a witness has identity equality so two witnesses with one seed are not equal`() {
        val a = CircuitZkFunctionWitness(secretSeed = secretSeedA)
        val b = CircuitZkFunctionWitness(secretSeed = secretSeedA)
        assertFalse(a == b)
        assertTrue(a == a)
    }

    @Test
    fun `an error never names a rule or a reason`() {
        for (e in listOf<CircuitZkError>(CircuitZkError.AccessDenied(CircuitZkStep.PREDICATE), CircuitZkError.InvalidRequest())) {
            assertFalse(e.toString().contains("PREDICATE"))
            assertFalse(e.toString().contains("rule"))
        }
        try {
            present(presenter(validator = { CircuitZkVerdict.AccessDenied("secret-rule-77") }), request())
        } catch (e: CircuitZkError) {
            assertFalse(e.toString().contains("secret-rule-77"))
        }
        assertTrue(logs.none { it.contains("secret-rule-77") })
    }

    // -------- the fake --------

    @Test
    fun `the fake prover exists only by explicit opt-in and says it is fake`() {
        assertTrue(FakeCircuitZkProver::class.constructors.none { it.visibility == kotlin.reflect.KVisibility.PUBLIC })
        val fake = FakeCircuitZkProver.optIn()
        assertTrue(fake.isFake)
        assertTrue(presenter(fake).usesFakeProver)
        val real = object : CircuitZkProver {
            override suspend fun prove(input: CircuitZkProveInput): CircuitZkProveOutput = error("unused")
        }
        assertFalse(presenter(real).usesFakeProver)
    }

    @Test
    fun `the fake refuses a config whose seed is not in the witness even when called directly`() {
        fun prove(config: String, w: CircuitZkFunctionWitness) = runBlocking {
            FakeCircuitZkProver.optIn().prove(
                CircuitZkProveInput(circuit, plan(pseudonymFn(config)), credential(), byteArrayOf(), "v", null, mapOf("n" to w), signer),
            )
        }
        // An ssc config given only the private seed, a psc config given only the secret seed, and no seed at all.
        for ((config, w) in listOf(
            "known-offender-matching-ssc" to CircuitZkFunctionWitness(privateSeed = seed16),
            "known-offender-matching-psc" to CircuitZkFunctionWitness(secretSeed = secretSeedA),
            "known-offender-matching-ssc" to CircuitZkFunctionWitness(),
        )) {
            try {
                prove(config, w)
                fail("$config")
            } catch (e: CircuitZkError.AccessDenied) {
                assertEquals(CircuitZkStep.PROVE, e.step)
            }
        }
        // And it derives from the right seed.
        val ok = prove("known-offender-matching-ssc", CircuitZkFunctionWitness(secretSeed = secretSeedA))
        assertEquals(
            ResultValue.Pseudonym(NymPseudonym.derive("known-offender-matching-ssc", secretSeedA, verifierId = "v")),
            ok.results["n"],
        )
    }

    @Test
    fun `releaseProvers releases the shared residency`() {
        val residency = ZkProverResidency()
        CircuitZkPresenter(FakeCircuitZkProver.optIn(), { listOf(circuit) }, CircuitZkRequestValidator.PERMISSIVE,
            HolderWitnessProvider(seeds), residency = residency).releaseProvers()
        presenter().releaseProvers()
    }

    @Test
    fun `a new function is a new handler`() {
        val custom = object : CircuitZkFunctionHandler {
            override val functionId = "custom_fn"
            override fun witnessNeeds(function: CircuitZkFunction) = emptySet<CircuitZkWitnessKind>()
            override fun holds(function: CircuitZkFunction, credential: org.siros.sdk.credentials.mdoc.DocumentMdoc) = true
        }
        val prover = CountingProver(FakeCircuitZkProver.optIn(), override = { CircuitZkProveOutput(ByteArray(2), mapOf("c" to ResultValue.Predicate)) })
        val pr = CircuitZkPresenter(prover, { listOf(circuit) }, CircuitZkRequestValidator.PERMISSIVE, HolderWitnessProvider(seeds),
            handlers = listOf(custom))
        val out = present(pr, request(p = plan(CircuitZkFunction("custom_fn", "c", JsonObject(emptyMap())))))
        assertEquals(setOf("c"), out.results.keys)
    }
}
