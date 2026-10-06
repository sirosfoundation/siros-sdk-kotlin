package org.siros.sdk.wallet.transaction

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.TransactionDataError
import org.siros.sdk.credentials.TransactionDataReason
import org.siros.sdk.keystore.AuthenticationCategory
import org.siros.sdk.keystore.AuthenticationFactor
import org.siros.sdk.wallet.AuthenticationFactorsProvider
import org.siros.sdk.wallet.ConservativeAuthenticationFactorsProvider
import org.siros.sdk.wallet.TransactionConsentHandler
import org.siros.sdk.wallet.TransactionConsentRequest
import org.siros.sdk.wallet.TransactionLogEntry
import org.siros.sdk.wallet.TransactionLogStore
import org.siros.sdk.wallet.TransactionOutcome
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.FakeSource
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.PAYMENT_TYPES
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.metadata
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.raw

class TransactionDataCoordinatorTest {
    private class MemoryLog : TransactionLogStore {
        val items = mutableListOf<TransactionLogEntry>()
        override suspend fun append(entry: TransactionLogEntry) { items += entry }
        override suspend fun entries() = items.toList()
        override suspend fun clear() { items.clear() }
    }

    private val twoFactors = listOf(
        AuthenticationFactor(AuthenticationCategory.KNOWLEDGE, "other"),
        AuthenticationFactor(AuthenticationCategory.POSSESSION, "key_in_remote_wscd"),
    )

    private class Harness(
        val handler: TransactionConsentHandler?,
        val factors: AuthenticationFactorsProvider,
        val log: MemoryLog = MemoryLog(),
        source: TransactionMetadataSource = FakeSource(metadata(types = PAYMENT_TYPES)),
        timeoutMs: Long = 5_000,
    ) {
        val coordinator = TransactionDataCoordinator(
            validator = TransactionDataValidator(source),
            display = TransactionDisplayBuilder(source, "en"),
            consentHandler = { handler },
            factorsProvider = { factors },
            log = { log },
            nowMillis = { 1234L },
            consentTimeoutMillis = timeoutMs,
        )
    }

    private fun req(vararg raws: String, verifier: String? = "Shop") = TransactionDataRequest(
        entries = raws.map { TransactionDataEntry(it) },
        responseMode = "direct_post",
        credentials = mapOf("pay" to listOf(TransactionTestFixtures.credential())),
        verifier = verifier,
    )

    private fun run(h: Harness, r: TransactionDataRequest): Result<ScaPresentationPlan> =
        runCatching { runBlocking { h.coordinator.process(r) } }

    private fun reason(result: Result<*>) = (result.exceptionOrNull() as? TransactionDataError)?.reason

    @Test
    fun `consent, factors and a log entry yield the binding`() {
        var seen: TransactionConsentRequest? = null
        val h = Harness(TransactionConsentHandler { seen = it; true }, AuthenticationFactorsProvider { twoFactors })
        val raw = raw()

        val plan = run(h, req(raw)).getOrThrow()

        assertEquals(TransactionDataHashing.hash(raw, "sha-256"), plan.bindingFor("pay")!!.hashes.single())
        assertNull(plan.bindingFor("other"))
        assertNull(plan.bindingFor(null))
        assertEquals("Payee", seen!!.entries.single().fields.first().label)
        val entry = h.log.items.single()
        assertEquals(TransactionOutcome.CONSENTED, entry.outcome)
        assertEquals("tx-0001", entry.transactionId)
        assertEquals("urn:eudi:sca:payment:1", entry.transactionType)
        assertEquals("Payment Confirmation", entry.typeName)
        assertEquals(mapOf("payee" to "Shop AB"), entry.entities)
        assertEquals("Shop", entry.verifier)
        assertEquals("Pay Card", entry.credential)
        assertEquals(1234L, entry.timestampMillis)
        assertNull(entry.reason)
    }

    @Test
    fun `the log holds the TS12 5_3 items and not the payload`() {
        val h = Harness(TransactionConsentHandler { true }, AuthenticationFactorsProvider { twoFactors })

        run(h, req(raw(payload = """{"transaction_id":"tx-9","payee":{"name":"Shop AB","id":"SE-SECRET-ID","website":"https://s.example"},"pisp":{"legal_name":"PayCo AB","brand_name":"b","domain_name":"d"},"currency":"EUR","amount":777.77}""")))

        val text = h.log.items.single().toString()
        assertEquals(mapOf("payee" to "Shop AB", "pisp" to "PayCo AB"), h.log.items.single().entities)
        assertTrue(text, !text.contains("SE-SECRET-ID") && !text.contains("777.77") && !text.contains("s.example"))
    }

    @Test
    fun `entity names per built-in type`() {
        fun names(type: String, payload: String) =
            TransactionDataCoordinator.entityNames(type, kotlinx.serialization.json.Json.parseToJsonElement(payload) as kotlinx.serialization.json.JsonObject)
        assertEquals(mapOf("service" to "Bank"), names("urn:eudi:sca:login_risk_transaction:1", """{"transaction_id":"t","service":"Bank","action":"a"}"""))
        assertEquals(emptyMap<String, String>(), names("urn:eudi:sca:login_risk_transaction:1", """{"transaction_id":"t","action":"a"}"""))
        assertEquals(mapOf("aisp" to "AISP AB"), names("urn:eudi:sca:account_access:1", """{"transaction_id":"t","aisp":{"legal_name":"AISP AB","brand_name":"b","domain_name":"d"}}"""))
        assertEquals(
            mapOf("payee" to "P", "pisp" to "L"),
            names("urn:eudi:sca:emandate:1", """{"transaction_id":"t","payment_payload":{"payee":{"name":"P","id":"1"},"pisp":{"legal_name":"L"}}}"""),
        )
        assertEquals(emptyMap<String, String>(), names("https://custom/x", """{"payee":{"name":"P"}}"""))
    }

    @Test
    fun `a declined transaction signs nothing and is logged as declined`() {
        val h = Harness(TransactionConsentHandler { false }, AuthenticationFactorsProvider { twoFactors })

        val r = run(h, req(raw()))

        assertEquals(TransactionDataReason.DECLINED, reason(r))
        assertEquals("access_denied", (r.exceptionOrNull() as TransactionDataError).verifierError)
        assertEquals(TransactionOutcome.DECLINED, h.log.items.single().outcome)
        assertEquals("declined", h.log.items.single().reason)
    }

    @Test
    fun `a handler that throws or never answers is a decline, never consent`() {
        val throwing = Harness(TransactionConsentHandler { throw IllegalStateException("ui crashed") }, AuthenticationFactorsProvider { twoFactors })
        assertEquals(TransactionDataReason.DECLINED, reason(run(throwing, req(raw()))))

        val gate = CompletableDeferred<Boolean>()
        val silent = Harness(TransactionConsentHandler { gate.await() }, AuthenticationFactorsProvider { twoFactors }, timeoutMs = 50)
        assertEquals(TransactionDataReason.DECLINED, reason(run(silent, req(raw()))))
        assertEquals(TransactionOutcome.DECLINED, silent.log.items.single().outcome)
    }

    @Test
    fun `no handler registered refuses`() {
        val h = Harness(null, AuthenticationFactorsProvider { twoFactors })

        assertEquals(TransactionDataReason.NO_CONSENT_HANDLER, reason(run(h, req(raw()))))
        assertEquals(TransactionOutcome.REFUSED, h.log.items.single().outcome)
    }

    @Test
    fun `fewer than two categories refuses after consent, logged as refused`() {
        for (p in listOf(ConservativeAuthenticationFactorsProvider, AuthenticationFactorsProvider { twoFactors.take(1) })) {
            val h = Harness(TransactionConsentHandler { true }, p)

            val r = run(h, req(raw()))

            assertEquals(TransactionDataReason.INSUFFICIENT_AUTHENTICATION_FACTORS, reason(r))
            assertEquals(TransactionOutcome.REFUSED, h.log.items.single().outcome)
            assertEquals("insufficientAuthenticationFactors", h.log.items.single().reason)
        }
        val failing = Harness(TransactionConsentHandler { true }, AuthenticationFactorsProvider { throw IllegalStateException("x") })
        assertEquals(TransactionDataReason.INSUFFICIENT_AUTHENTICATION_FACTORS, reason(run(failing, req(raw()))))
    }

    @Test
    fun `a validation refusal never reaches the user and is logged with what could be read`() {
        var asked = false
        val h = Harness(TransactionConsentHandler { asked = true; true }, AuthenticationFactorsProvider { twoFactors })

        val r = run(h, req(raw(payload = """{"transaction_id":"tx-bad","currency":"EUR","amount":1}""")))

        assertEquals(TransactionDataReason.SCHEMA_VIOLATION, reason(r))
        assertTrue(!asked)
        val entry = h.log.items.single()
        assertEquals(TransactionOutcome.REFUSED, entry.outcome)
        assertEquals("tx-bad", entry.transactionId)
        assertEquals("schemaViolation", entry.reason)

        val garbage = Harness(TransactionConsentHandler { true }, AuthenticationFactorsProvider { twoFactors })
        run(garbage, req("###"))
        assertNull(garbage.log.items.single().transactionId)
        assertNull(garbage.log.items.single().transactionType)
    }

    @Test
    fun `a log store that fails does not change the decision`() {
        val failing = object : TransactionLogStore {
            override suspend fun append(entry: TransactionLogEntry) = throw java.io.IOException("disk full")
            override suspend fun entries() = emptyList<TransactionLogEntry>()
            override suspend fun clear() {}
        }
        val source = FakeSource(metadata(types = PAYMENT_TYPES))
        val c = TransactionDataCoordinator(
            TransactionDataValidator(source), TransactionDisplayBuilder(source, "en"),
            { TransactionConsentHandler { true } }, { AuthenticationFactorsProvider { twoFactors } }, { failing },
        )

        assertNotNull(runBlocking { c.process(req(raw())) })
    }

    @Test
    fun `refuse and recordUnreadable log a refusal`() {
        val h = Harness(null, AuthenticationFactorsProvider { twoFactors })
        val err = TransactionDataError(TransactionDataReason.DISABLED, "off")

        val r = runCatching { runBlocking { h.coordinator.refuse(req(raw()), err) } }
        runBlocking { h.coordinator.recordUnreadable("V", TransactionDataError(TransactionDataReason.INVALID_ENTRY, "no raw")) }

        assertEquals(TransactionDataReason.DISABLED, reason(r))
        assertEquals(listOf("disabled", "invalidEntry"), h.log.items.map { it.reason })
        assertEquals("tx-0001", h.log.items[0].transactionId)
        assertNull(h.log.items[1].transactionId)
        assertEquals("V", h.log.items[1].verifier)
    }
}
