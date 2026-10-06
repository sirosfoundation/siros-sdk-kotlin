package org.siros.sdk.wallet

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class TransactionLogTest {
    private var slot: String? = null
    private fun store(max: Int = 3) = JsonTransactionLogStore({ slot }, { slot = it }, max)

    private fun entry(id: String, outcome: TransactionOutcome = TransactionOutcome.CONSENTED) = TransactionLogEntry(
        transactionId = id, transactionType = "urn:eudi:sca:payment:1", typeName = "Payment Confirmation",
        entities = mapOf("payee" to "Shop"), verifier = "v", credential = "c", timestampMillis = 1, outcome = outcome, reason = null,
    )

    @Test
    fun `entries come back newest first and survive a restart`() = runBlocking {
        val s = store()
        s.append(entry("a"))
        s.append(entry("b", TransactionOutcome.DECLINED))

        val reloaded = store().entries()

        assertEquals(listOf("b", "a"), reloaded.map { it.transactionId })
        assertEquals(TransactionOutcome.DECLINED, reloaded.first().outcome)
        assertEquals(mapOf("payee" to "Shop"), reloaded.first().entities)
    }

    @Test
    fun `the oldest entries are dropped past the cap`() = runBlocking {
        val s = store(max = 3)
        listOf("a", "b", "c", "d").forEach { s.append(entry(it)) }

        assertEquals(listOf("d", "c", "b"), s.entries().map { it.transactionId })
    }

    @Test
    fun `clear empties the log, and a corrupt slot does not lose new entries`() = runBlocking {
        val s = store()
        s.append(entry("a"))
        s.clear()
        assertEquals(emptyList<TransactionLogEntry>(), s.entries())
        assertNull(slot)

        slot = "{not json"
        s.append(entry("z"))
        assertEquals(listOf("z"), s.entries().map { it.transactionId })
    }

    @Test
    fun `the outcome is written in the contract's words`() = runBlocking {
        store().append(entry("a", TransactionOutcome.REFUSED))
        assert(slot!!.contains("\"outcome\":\"refused\""))
        Unit
    }
}
