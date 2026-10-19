// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import java.io.File
import java.util.Locale
import javax.xml.parsers.DocumentBuilderFactory
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.AgeForm
import org.siros.sdk.credentials.ConsentEntry
import org.siros.sdk.credentials.ConsentItem
import org.siros.sdk.credentials.ConsentVerifier
import org.siros.sdk.credentials.CredentialRef
import org.siros.sdk.credentials.PresentationConsentRequest
import org.siros.sdk.credentials.PseudonymScope

/** The SDK-owned consent wording: every locale, every key, and what the text may and may not say. */
class PresentationConsentTextTest {
    private val locales = mapOf("values" to Locale.ENGLISH, "values-sv" to Locale("sv"), "values-fi" to Locale("fi"), "values-el" to Locale("el"), "values-pt" to Locale("pt"))

    private fun strings(dir: String): Map<String, String> {
        val file = File("src/main/res/$dir/strings.xml")
        assertTrue("missing ${file.path}", file.exists())
        val nodes = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(file).getElementsByTagName("string")
        return (0 until nodes.length).associate { nodes.item(it).attributes.getNamedItem("name").nodeValue to nodes.item(it).textContent }
    }

    /** The consent string keys, named from the enum's resource: the key of [ConsentString] is its resource entry name. */
    private val keyOf = mapOf(
        ConsentString.TITLE to "siros_consent_title", ConsentString.SHARE to "siros_consent_share", ConsentString.CANCEL to "siros_consent_cancel",
        ConsentString.VERIFIER_PROVE to "siros_consent_verifier_prove", ConsentString.VERIFIER_SHARE to "siros_consent_verifier_share",
        ConsentString.AGE_BETWEEN to "siros_consent_age_between", ConsentString.AGE_AT_LEAST to "siros_consent_age_at_least",
        ConsentString.AGE_AT_MOST to "siros_consent_age_at_most", ConsentString.PSEUDONYM to "siros_consent_pseudonym",
        ConsentString.PSEUDONYM_ISSUER_CAN_LINK to "siros_consent_pseudonym_issuer", ConsentString.FOOTER to "siros_consent_footer",
        ConsentString.CLAIM to "siros_consent_claim", ConsentString.LEGACY_PSEUDONYM to "siros_consent_legacy_pseudonym",
    )

    private fun textFor(dir: String) = PresentationConsentText({ key, args ->
        String.format(locales.getValue(dir), strings(dir).getValue(keyOf.getValue(key)), *args)
    }, locales.getValue(dir))

    @Test
    fun everyConsentStringExistsInEveryLocale_withTheSamePlaceholders() {
        assertEquals("a ConsentString has no key in this test", ConsentString.values().toSet(), keyOf.keys)
        val english = strings("values").filterKeys { it.startsWith("siros_consent_") }
        assertEquals(keyOf.values.toSet(), english.keys)
        val placeholders = { t: String -> Regex("%\\d\\$[sd]").findAll(t).map { it.value }.sorted().toList() }
        for (dir in locales.keys) {
            val localised = strings(dir).filterKeys { it.startsWith("siros_consent_") }
            assertEquals("$dir is missing or has an extra consent string", english.keys, localised.keys)
            for ((k, t) in localised) {
                assertFalse("$dir/$k is empty", t.isBlank())
                assertEquals("$dir/$k placeholders differ from the default locale", placeholders(english.getValue(k)), placeholders(t))
                // The trust framework and the verifier_id_type are technical: never user text.
                assertFalse("$dir/$k names the framework", t.contains("framework", ignoreCase = true))
            }
        }
        // The two refusal messages of the consent are in every locale too.
        for (dir in locales.keys) {
            for (k in listOf("siros_dcapi_refused_consent_unavailable", "siros_dcapi_refused_user_declined")) assertTrue("$dir/$k", k in strings(dir))
        }
    }

    private val ssc = ConsentItem.Pseudonym("known-offender-matching-ssc", PseudonymScope.PER_VERIFIER, true, false, "rp.example", null)
    private val psc = ConsentItem.Pseudonym("known-offender-matching-psc", PseudonymScope.PER_VERIFIER, false, false, "rp.example", null)

    private fun request(vararg items: ConsentItem, verifierId: String? = "rp.example") = PresentationConsentRequest(
        verifier = ConsentVerifier("Example RP", trustFramework = "etsi-tl", trustIdentifier = "rp.example", verifierId = verifierId, verifierIdType = "x509_san_dns"),
        entries = listOf(ConsentEntry(CredentialRef("Nym", "Example Issuer"), items.toList())),
        requestSigned = true,
        locale = "en",
    )

    @Test
    fun theApprovedEnglishWording_isParameterisedPerItem() {
        val screen = textFor("values").render(
            request(ssc, ConsentItem.AgeRange("1990-01-01", "2008-10-19", AgeForm.Between("1990-01-01", "2008-10-19", 18, 36))),
        )
        assertEquals("Example RP is asking you to prove:", screen.header)
        assertEquals(
            listOf(
                "A pseudonym for Example RP is shared. You get the same pseudonym every time you visit this service, and a different one at every other service. " +
                    "The service that issued your credential can work out who this pseudonym belongs to.",
                "You were born between January 1, 1990 and October 19, 2008 (about 18–36 years old). Your exact birth date is not shared.",
            ),
            screen.entries.single().lines,
        )
        assertEquals("No other personal data is shared.", screen.footer)
        assertEquals("Nym", screen.entries.single().credentialName)
        assertEquals("Example Issuer", screen.entries.single().issuerName)
        assertEquals("You are at least 18 years old. Your exact birth date is not shared.", textFor("values").render(request(ConsentItem.AgeRange(null, "2008-10-19", AgeForm.AtLeast(18)))).entries.single().lines.single())
        assertEquals("You are at most 26 years old. Your exact birth date is not shared.", textFor("values").render(request(ConsentItem.AgeRange("2000-01-01", null, AgeForm.AtMost(26)))).entries.single().lines.single())
    }

    @Test
    fun theIssuerLinkabilitySentence_isThereExactlyWhenTheIssuerCanRemapThePseudonym() {
        for (dir in locales.keys) {
            val t = textFor(dir)
            val remappable = t.render(request(ssc)).entries.single().lines.single()
            val plain = t.render(request(psc)).entries.single().lines.single()
            assertTrue("$dir: the issuer sentence is extra text", remappable.length > plain.length)
            assertTrue("$dir: the plain pseudonym text is a prefix of the remappable one", remappable.startsWith(plain))
        }
    }

    @Test
    fun everyLocaleSaysTheVerifierLineWithTheNameAndNothingTechnical() {
        val expected = mapOf(
            "values" to "Example RP is asking you to prove:", "values-sv" to "Example RP ber dig bevisa:",
            "values-fi" to "Example RP pyytää sinua todistamaan:", "values-el" to "Η υπηρεσία Example RP σας ζητά να αποδείξετε:",
            "values-pt" to "Example RP pede-lhe que prove:",
        )
        for ((dir, line) in expected) {
            val screen = textFor(dir).render(request(ssc, ConsentItem.AgeRange(null, "2008-10-19", AgeForm.AtLeast(18))))
            assertEquals(dir, line, screen.header)
            // Nothing the dialog shows names the trust framework or the verifier_id_type.
            val all = listOf(screen.title, screen.header, screen.footer, screen.shareLabel, screen.cancelLabel) + screen.entries.flatMap { it.lines }
            for (t in all) {
                assertFalse("$dir: $t", t.contains("etsi-tl") || t.contains("x509_san_dns") || t.contains("semantic"))
            }
        }
    }

    @Test
    fun theVerifierIdIsADetailLine_verbatimAndShortenedOnlyForDisplay() {
        val did = "did:web:verifier.example.org:very:long:path:segment:identifying:this:verifier"
        val detail = textFor("values").render(request(ssc, verifierId = did)).verifierDetail!!
        assertEquals(did, detail.full)
        assertEquals(did.take(18) + "…" + did.takeLast(18), detail.shortened)
        assertEquals(null, textFor("values").render(request(ConsentItem.AgeRange(null, "2008-10-19", AgeForm.AtLeast(18)), verifierId = null)).verifierDetail)
    }

    @Test
    fun verifierIdShortening_followsTheSharedVectors() {
        val f = File("../../spec/circuit-zk-consent-vectors.json")
        val cases = Json.parseToJsonElement(f.readText()).jsonObject["verifier_id_shortening"]!!.jsonArray
        assertTrue(cases.size >= 5)
        for (c in cases) {
            val o = c.jsonObject
            assertEquals(o["display"]!!.jsonPrimitive.content, PresentationConsentText.shortenMiddle(o["id"]!!.jsonPrimitive.content))
        }
    }

    @Test
    fun aLegacyDisclosure_isADisclosureScreen_notThePickersNoPersonalDataText() {
        val screen = textFor("values").render(request(ConsentItem.Claim("family_name"), ConsentItem.LegacyPseudonym("ctx")))
        assertEquals("Example RP is asking you to share:", screen.header)
        assertEquals(listOf("The value of “family_name” from your credential is shared.", "A pseudonym is shared with Example RP."), screen.entries.single().lines)
        val picker = strings("values").getValue("siros_dcapi_zk_proof_detail")
        assertTrue(screen.entries.single().lines.none { it.contains("No personal data is shared") })
        assertFalse(picker == screen.footer)
    }

    @Test
    fun aPseudonymScopeTheWordingDoesNotCover_failsInsteadOfBeingOmitted() {
        val xsite = ConsentItem.Pseudonym("user-managed-pseudonym-xsite-ssc", PseudonymScope.CROSS_SITE, true, true, null, null)
        assertThrows(IllegalArgumentException::class.java) { textFor("values").render(request(xsite)) }
        val withContext = ConsentItem.Pseudonym("account-recovery-ssc", PseudonymScope.PER_VERIFIER_CONTEXT, true, false, "rp.example", "acct")
        assertThrows(IllegalArgumentException::class.java) { textFor("values").render(request(withContext)) }
    }
}
