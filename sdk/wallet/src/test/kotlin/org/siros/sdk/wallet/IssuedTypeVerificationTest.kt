package org.siros.sdk.wallet

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.Vctm
import org.siros.sdk.credentials.VctmDocument
import java.security.MessageDigest
import java.util.Base64
import kotlin.reflect.full.callSuspend
import kotlin.reflect.full.declaredMemberFunctions
import kotlin.reflect.jvm.isAccessible
import kotlinx.coroutines.test.runTest

/**
 * The wallet's two checks on a credential as it arrives.
 *
 * Everything earlier in the issuance path - the issuer's entitlement under ARF
 * section 6.6.2.3, which type metadata to apply, which WSCD to use - is decided
 * from what the issuer *advertised*. These are the only two things that look at
 * what actually turned up.
 */
class IssuedTypeVerificationTest {

    private val json = Json { ignoreUnknownKeys = true }

    private fun wallet(): SirosWallet {
        // allocateInstance leaves every field null, which is what the existing
        // cases below assume: no offer, so only resolved metadata is consulted.
        val unsafeClass = Class.forName("sun.misc.Unsafe")
        val f = unsafeClass.getDeclaredField("theUnsafe")
        f.isAccessible = true
        val allocate = unsafeClass.getMethod("allocateInstance", Class::class.java)
        return allocate.invoke(f.get(null), SirosWallet::class.java) as SirosWallet
    }

    private fun setField(target: Any, name: String, value: Any?) {
        val field = SirosWallet::class.java.getDeclaredField(name)
        field.isAccessible = true
        field.set(target, value)
    }

    private fun call(w: SirosWallet, name: String, vararg args: Any?): Any? {
        val m = SirosWallet::class.declaredMemberFunctions.first { it.name == name }
        m.isAccessible = true
        return try {
            m.call(w, *args)
        } catch (e: java.lang.reflect.InvocationTargetException) {
            throw e.cause ?: e
        }
    }

    /** The suspend counterpart of [call], for checks that may re-resolve. */
    private suspend fun callSuspending(w: SirosWallet, name: String, vararg args: Any?): Any? {
        val m = SirosWallet::class.declaredMemberFunctions.first { it.name == name }
        m.isAccessible = true
        return try {
            m.callSuspend(w, *args)
        } catch (e: java.lang.reflect.InvocationTargetException) {
            throw e.cause ?: e
        }
    }

    private fun sdJwt(vct: String?, integrity: String? = null): String {
        val claims = buildString {
            append("{")
            if (vct != null) append("\"vct\":\"$vct\"")
            if (integrity != null) {
                if (vct != null) append(",")
                append("\"vct#integrity\":\"$integrity\"")
            }
            append("}")
        }
        val b64 = { s: String -> Base64.getUrlEncoder().withoutPadding().encodeToString(s.toByteArray()) }
        return "${b64("{\"alg\":\"ES256\"}")}.${b64(claims)}.sig"
    }

    private fun payloadOf(raw: String): JsonObject =
        json.parseToJsonElement(String(Base64.getUrlDecoder().decode(raw.split(".")[1]))) as JsonObject

    // --- issued type ---

    @Test
    fun acceptsACredentialOfTheAuthorisedType() {
        val w = wallet()
        setField(w, "activeVctm", Vctm(vct = "urn:eudi:pid:1"))
        assertNull(call(w, "verifyIssuedType", "dc+sd-jwt", sdJwt("urn:eudi:pid:1")))
    }

    @Test
    fun refusesACredentialOfADifferentType() {
        // The whole point: an issuer entitled to one attestation type must not
        // be able to deliver another and have every earlier decision stand.
        val w = wallet()
        setField(w, "activeVctm", Vctm(vct = "urn:eudi:pid:1"))
        val reason = call(w, "verifyIssuedType", "dc+sd-jwt", sdJwt("urn:example:something-else")) as String?
        assertNotNull(reason)
        assertTrue("reason should name both types, was: $reason",
            reason!!.contains("urn:example:something-else") && reason.contains("urn:eudi:pid:1"))
    }

    @Test
    fun acceptsWhenNoTypeWasAuthorised() {
        // No metadata resolved means there is nothing to compare against. A
        // check that could not run must not become a refusal.
        val w = wallet()
        setField(w, "activeVctm", null)
        setField(w, "activeMddlSchema", null)
        assertNull(call(w, "verifyIssuedType", "dc+sd-jwt", sdJwt("urn:eudi:pid:1")))
    }

    @Test
    fun acceptsWhenTheCredentialDeclaresNoType() {
        val w = wallet()
        setField(w, "activeVctm", Vctm(vct = "urn:eudi:pid:1"))
        assertNull(call(w, "verifyIssuedType", "dc+sd-jwt", sdJwt(null)))
    }

    @Test
    fun mdocIsComparedAgainstTheDoctypeNotTheVct() {
        // The two namespaces are separate; comparing an mdoc against a vct
        // would refuse every mdoc ever issued.
        val w = wallet()
        setField(w, "activeVctm", Vctm(vct = "urn:eudi:pid:1"))
        setField(w, "activeMddlSchema", null)
        // No MDDL resolved, so nothing to compare - and crucially it does not
        // fall back to the SD-JWT vct.
        assertNull(call(w, "verifyIssuedType", "mso_mdoc", "not-a-jwt"))
    }

    @Test
    fun usesTheOffersTypeWhenMetadataResolutionFailed() {
        // The situation the check exists for and would otherwise miss: no
        // metadata resolved, so no Vctm - but the offer still declared a vct,
        // and that is what the entitlement check was run against.
        val w = wallet()
        setField(w, "activeVctm", null)
        setField(w, "activeMddlSchema", null)
        setField(
            w,
            "activeOffer",
            org.siros.sdk.credentials.CredentialOffer(
                credentialConfigurationId = "pid",
                credentialIssuerIdentifier = "https://issuer.example.com",
                credentialName = "PID",
                issuerName = "Issuer",
                vct = "urn:eudi:pid:1",
            ),
        )
        assertNotNull(call(w, "verifyIssuedType", "dc+sd-jwt", sdJwt("urn:example:other")))
        assertNull(call(w, "verifyIssuedType", "dc+sd-jwt", sdJwt("urn:eudi:pid:1")))
    }

    @Test
    fun mdocUsesTheOffersDoctype() {
        val w = wallet()
        setField(w, "activeVctm", null)
        setField(w, "activeMddlSchema", null)
        setField(
            w,
            "activeOffer",
            org.siros.sdk.credentials.CredentialOffer(
                credentialConfigurationId = "mdl",
                credentialIssuerIdentifier = "https://issuer.example.com",
                credentialName = "mDL",
                issuerName = "Issuer",
                doctype = "org.iso.18013.5.1.mDL",
            ),
        )
        // An unparseable mdoc still declares no type, so there is nothing to
        // disagree with - the offer's doctype alone must not cause a refusal.
        assertNull(call(w, "verifyIssuedType", "mso_mdoc", "not-a-real-mdoc"))
    }

    // --- vct#integrity ---

    private fun vctmDocument(vct: String): VctmDocument {
        val raw = """{"vct":"$vct"}"""
        return VctmDocument(raw = raw, vctm = Vctm(vct = vct))
    }

    private fun digestOf(raw: String): String =
        "sha256-" + Base64.getEncoder().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(raw.toByteArray()),
        )

    @Test
    fun acceptsTypeMetadataMatchingTheIssuersDigest() = runTest {
        val w = wallet()
        val doc = vctmDocument("urn:eudi:pid:1")
        setField(w, "activeVctmDocument", doc)
        val raw = sdJwt("urn:eudi:pid:1", digestOf(doc.raw))
        assertNull(refusalReason(callSuspending(w, "verifyVctIntegrity", "dc+sd-jwt", payloadOf(raw))))
    }

    @Test
    fun refusesTypeMetadataTheIssuerDidNotPin() = runTest {
        // A registry serving altered metadata for a type the issuer is
        // legitimately entitled to issue.
        val w = wallet()
        setField(w, "activeVctmDocument", vctmDocument("urn:eudi:pid:1"))
        val raw = sdJwt("urn:eudi:pid:1", digestOf("""{"vct":"urn:eudi:pid:1","claims":[]}"""))
        assertNotNull(refusalReason(callSuspending(w, "verifyVctIntegrity", "dc+sd-jwt", payloadOf(raw))))
    }

    @Test
    fun acceptsACredentialThatPinsNothing() = runTest {
        val w = wallet()
        setField(w, "activeVctmDocument", vctmDocument("urn:eudi:pid:1"))
        assertNull(refusalReason(callSuspending(w, "verifyVctIntegrity", "dc+sd-jwt", payloadOf(sdJwt("urn:eudi:pid:1")))))
    }

    @Test
    fun acceptsWhenNoMetadataWasResolvedToCheck() = runTest {
        // Nothing was applied, so nothing was tampered with.
        val w = wallet()
        setField(w, "activeVctmDocument", null)
        val raw = sdJwt("urn:eudi:pid:1", digestOf("""{"vct":"urn:eudi:pid:1"}"""))
        assertNull(refusalReason(callSuspending(w, "verifyVctIntegrity", "dc+sd-jwt", payloadOf(raw))))
    }

    @Test
    fun reResolvesRatherThanRefusingWhenTheResolvedDocumentIsStale() = runTest {
        // The state a device was actually found in: metadata cached before the
        // issuer changed it, so the digest disagrees. The document the issuer
        // pinned is still out there, so the credential must be accepted after
        // resolving again rather than refused.
        val current = """{"vct":"urn:eudi:pid:1","name":"PID"}"""
        val w = wallet()
        val staleDocument = vctmDocument("urn:eudi:pid:1")
        val stale = staleDocument.raw
        setField(w, "activeVctmDocument", staleDocument)
        setField(w, "config", WalletConfig(backendUrl = "https://backend.example"))
        setField(
            w,
            "activeOffer",
            org.siros.sdk.credentials.CredentialOffer(
                credentialConfigurationId = "pid_1_8",
                credentialIssuerIdentifier = "https://issuer.example",
                credentialName = "PID",
                issuerName = "Issuer",
                vct = "urn:eudi:pid:1",
            ),
        )
        setField(w, "vctmFetcher", org.siros.sdk.credentials.VctmFetcher(httpGet = { current }))

        val raw = sdJwt("urn:eudi:pid:1", digestOf(current))
        val outcome = callSuspending(w, "verifyVctIntegrity", "dc+sd-jwt", payloadOf(raw))

        assertNull(refusalReason(outcome))
        // And the re-resolved document is handed back, so the credential is
        // stored with it.
        assertEquals(current, (refreshedDocument(outcome) as VctmDocument).raw)
        // Deliberately NOT written into the wallet's shared issuance state: it
        // suspends on the network, and a cancelled or superseded flow may have
        // replaced that state meanwhile - see VctIntegrityCheck's doc comment.
        val field = SirosWallet::class.java.getDeclaredField("activeVctmDocument")
        field.isAccessible = true
        assertEquals(stale, (field.get(w) as VctmDocument).raw)
    }

    /** [SirosWallet.VctIntegrityCheck] is private; read its members by name. */
    private fun member(outcome: Any?, name: String): Any? {
        val f = outcome!!.javaClass.getDeclaredField(name)
        f.isAccessible = true
        return f.get(outcome)
    }

    private fun refusalReason(outcome: Any?): String? = member(outcome, "reason") as String?

    private fun refreshedDocument(outcome: Any?): Any? = member(outcome, "refreshed")

    @Test
    fun refusesWhenNoSourceHasTheDocumentTheIssuerPinned() = runTest {
        // Re-resolution is not a way around the check: when nothing serves the
        // pinned document, the credential is still refused.
        val w = wallet()
        setField(w, "activeVctmDocument", vctmDocument("urn:eudi:pid:1"))
        setField(w, "config", WalletConfig(backendUrl = "https://backend.example"))
        setField(
            w,
            "activeOffer",
            org.siros.sdk.credentials.CredentialOffer(
                credentialConfigurationId = "pid_1_8",
                credentialIssuerIdentifier = "https://issuer.example",
                credentialName = "PID",
                issuerName = "Issuer",
                vct = "urn:eudi:pid:1",
            ),
        )
        setField(w, "vctmFetcher", org.siros.sdk.credentials.VctmFetcher(httpGet = { """{"vct":"urn:eudi:pid:1","name":"something else"}""" }))

        val raw = sdJwt("urn:eudi:pid:1", digestOf("""{"vct":"urn:eudi:pid:1","name":"PID"}"""))
        assertNotNull(refusalReason(callSuspending(w, "verifyVctIntegrity", "dc+sd-jwt", payloadOf(raw))))
    }

    @Test
    fun mdocCarriesNoVctIntegrity() = runTest {
        val w = wallet()
        setField(w, "activeVctmDocument", vctmDocument("urn:eudi:pid:1"))
        val raw = sdJwt("urn:eudi:pid:1", digestOf("wrong"))
        assertNull(refusalReason(callSuspending(w, "verifyVctIntegrity", "mso_mdoc", payloadOf(raw))))
    }
}
