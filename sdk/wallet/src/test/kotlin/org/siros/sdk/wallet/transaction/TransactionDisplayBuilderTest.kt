package org.siros.sdk.wallet.transaction

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.TransactionDataError
import org.siros.sdk.credentials.TransactionDataReason
import org.siros.sdk.wallet.TransactionConsentRequest
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.FakeSource
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.PAYMENT
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.PAYMENT_TYPES
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.metadata
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.raw
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.request

class TransactionDisplayBuilderTest {
    private fun model(
        types: String? = PAYMENT_TYPES,
        locale: String = "en-GB",
        documents: Map<String, String> = emptyMap(),
        payload: String = TransactionTestFixtures.PAYMENT_PAYLOAD,
        signed: Boolean? = null,
    ): TransactionConsentRequest = runBlocking {
        val source = FakeSource(metadata(types = types), documents)
        val validated = TransactionDataValidator(source).validate(request(listOf(TransactionDataEntry(raw(payload = payload)))))
        TransactionDisplayBuilder(source, locale).build(validated, "Shop AB (verifier)", signed)
    }

    private fun refusal(block: () -> Unit): TransactionDataReason =
        runCatching(block).exceptionOrNull().let { e ->
            (e as? TransactionDataError)?.reason ?: throw AssertionError("expected a refusal, got $e")
        }

    @Test
    fun `fields carry labels and levels, ordered level 1 first, payload order within a level`() {
        val e = model().entries.single()

        assertEquals(
            listOf("Payee" to 1, "Amount" to 1, "Currency" to 2, "Payee ID" to 3, "Transaction ID" to 4),
            e.fields.map { it.label to it.level },
        )
        assertEquals("Shop AB", e.fields.first().value)
        assertEquals("49.99", e.fields.first { it.label == "Amount" }.value)
    }

    @Test
    fun `an unset visualisation defaults to 3`() {
        assertEquals(3, model().entries.single().fields.first { it.label == "Payee ID" }.level)
    }

    @Test
    fun `UI elements and request metadata come through`() {
        val m = model(signed = false)
        val e = m.entries.single()

        assertEquals("Confirm Payment", e.affirmativeLabel)
        assertEquals("Cancel Payment", e.denialLabel)
        assertEquals("Confirm your payment", e.title)
        assertEquals("Check the amount", e.securityHint)
        assertEquals("Payment Confirmation", e.typeName)
        assertEquals(false, m.requestSigned)
        assertEquals("Shop AB (verifier)", m.verifier)
        assertEquals("Pay Card", m.credentialName)
        assertEquals("en-GB", m.locale)
    }

    @Test
    fun `labels follow the locale, then the language, then English`() {
        assertEquals("Mottagare", model(locale = "sv-SE").entries.single().fields.first().label)
        assertEquals("Bekräfta betalning", model(locale = "sv").entries.single().affirmativeLabel)
        assertEquals("Payee", model(locale = "de-DE").entries.single().fields.first().label)
        assertEquals("Mottagare", model(locale = "sv_SE").entries.single().fields.first().label)
    }

    @Test
    fun `optional UI elements may be absent, the required one may not`() {
        val onlyRequired = PAYMENT_TYPES.replace(
            Regex(""""denial_action_label":\[[^\]]*\],\s*"transaction_title":\[[^\]]*\],\s*"security_hint":\[[^\]]*\]"""), "\"x\":[]",
        )
        val e = model(types = onlyRequired).entries.single()
        assertNull(e.denialLabel)
        assertNull(e.title)
        assertNull(e.securityHint)

        val noAffirmative = PAYMENT_TYPES.replace("\"affirmative_action_label\"", "\"other\"")
        assertEquals(TransactionDataReason.METADATA_UNAVAILABLE, refusal { model(types = noAffirmative) })
    }

    @Test
    fun `a parameter without a localised name stops the transaction, unless the issuer marked it omittable`() {
        val noAmountLabel = PAYMENT_TYPES.replace(
            """{"path":["payload","amount"],"visualisation":1,"display":[{"lang":"en","label":"Amount"}]}""",
            """{"path":["payload","amount"],"visualisation":1}""",
        )
        assertEquals(TransactionDataReason.METADATA_UNAVAILABLE, refusal { model(types = noAmountLabel) })

        val noClaimAtAll = PAYMENT_TYPES.replace(
            """{"path":["payload","currency"],"visualisation":2,"display":[{"lang":"en","label":"Currency"}]},""", "",
        )
        assertEquals(TransactionDataReason.METADATA_UNAVAILABLE, refusal { model(types = noClaimAtAll) })

        val omittable = PAYMENT_TYPES.replace(
            """{"path":["payload","transaction_id"],"visualisation":4,"display":[{"lang":"en","label":"Transaction ID"}]}""",
            """{"path":["payload","transaction_id"],"visualisation":4}""",
        )
        assertTrue(model(types = omittable).entries.single().fields.none { it.label == "Transaction ID" })
    }

    @Test
    fun `no metadata entry, or malformed claim metadata, refuses`() {
        // a built-in type validates without a metadata entry, but then nothing can be labelled
        assertEquals(TransactionDataReason.METADATA_UNAVAILABLE, refusal { model(types = "{}") })
        assertEquals(
            TransactionDataReason.METADATA_UNAVAILABLE,
            refusal { model(types = PAYMENT_TYPES.replace("\"visualisation\":2", "\"visualisation\":7")) },
        )
        assertEquals(
            TransactionDataReason.METADATA_UNAVAILABLE,
            refusal { model(types = """{"$PAYMENT":{"claims":5,"ui_labels":{}}}""") },
        )
    }

    @Test
    fun `claims_uri and ui_labels_uri are fetched, and may not be given alongside the inline form`() {
        val claims = """[{"path":["payload","transaction_id"],"visualisation":4},{"path":["payload","payee","name"],"display":[{"lang":"en","label":"Payee"}]},
            {"path":["payload","payee","id"],"visualisation":4},{"path":["payload","currency"],"display":[{"lang":"en","label":"Cur"}]},{"path":["payload","amount"],"display":[{"lang":"en","label":"Amt"}]}]"""
        val labels = """{"affirmative_action_label":[{"lang":"en","value":"OK"}]}"""
        val types = """{"$PAYMENT":{"claims_uri":"https://bank.example/c.json","ui_labels_uri":"https://bank.example/l.json"}}"""
        val docs = mapOf("https://bank.example/c.json" to claims, "https://bank.example/l.json" to labels)

        val e = model(types = types, documents = docs).entries.single()
        assertEquals("OK", e.affirmativeLabel)
        assertEquals(listOf("Payee", "Cur", "Amt"), e.fields.map { it.label })

        assertEquals(TransactionDataReason.METADATA_UNAVAILABLE, refusal { model(types = types) }) // not fetchable
        assertEquals(
            TransactionDataReason.METADATA_UNAVAILABLE,
            refusal { model(types = types, documents = docs + ("https://bank.example/l.json" to "<html>")) },
        )
        assertEquals(
            TransactionDataReason.METADATA_UNAVAILABLE,
            refusal { model(types = """{"$PAYMENT":{"claims":[],"claims_uri":"https://bank.example/c.json","ui_labels":{}}}""", documents = docs) },
        )
    }

    @Test
    fun `what is shown is derived from raw, so a hint cannot change it`() {
        // The pipeline decodes raw itself and refuses a disagreeing hint; the model is built from the decoded payload.
        val e = model(payload = """{"transaction_id":"t","payee":{"name":"Real Payee","id":"1"},"currency":"EUR","amount":5}""").entries.single()
        assertEquals("Real Payee", e.fields.first { it.label == "Payee" }.value)
    }
}
