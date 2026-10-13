package org.siros.sdk.credentials

import com.upokecenter.cbor.CBORObject
import java.util.Base64
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** The policy table and the claim-level enforcement points in `credentials`: matching, display, blob claims. */
class NonDisclosureTest {
    private val nym = NonDisclosurePolicy.NYM_AUTH_DOCTYPE
    private val json = Json { ignoreUnknownKeys = true }

    @After
    fun resetPolicy() {
        CredentialDisclosureGuard.policy = NonDisclosurePolicy.DEFAULT
    }

    private fun item(id: Long, name: String, value: CBORObject): CBORObject {
        val m = CBORObject.NewMap()
        m[CBORObject.FromObject("digestID")] = CBORObject.FromObject(id)
        m[CBORObject.FromObject("random")] = CBORObject.FromObject(ByteArray(16))
        m[CBORObject.FromObject("elementIdentifier")] = CBORObject.FromObject(name)
        m[CBORObject.FromObject("elementValue")] = value
        return CBORObject.FromObjectAndTag(m.EncodeToBytes(), 24)
    }

    private fun mdocRaw(docType: String): String {
        val items = CBORObject.NewArray()
        items.Add(item(0, "birth_date", CBORObject.FromObjectAndTag("2000-06-15", 1004)))
        items.Add(item(1, "ssc", CBORObject.FromObject(ByteArray(32) { 1 })))
        items.Add(item(2, "psc", CBORObject.FromObject(ByteArray(32) { 2 })))
        items.Add(item(3, "given_name", CBORObject.FromObject("Jane")))
        val ns = CBORObject.NewMap()
        ns[CBORObject.FromObject(docType)] = items
        val mso = CBORObject.NewMap()
        mso[CBORObject.FromObject("docType")] = CBORObject.FromObject(docType)
        val auth = CBORObject.NewArray()
        auth.Add(CBORObject.FromObject(ByteArray(0)))
        auth.Add(CBORObject.NewMap())
        auth.Add(CBORObject.FromObject(CBORObject.FromObjectAndTag(mso.EncodeToBytes(), 24).EncodeToBytes()))
        auth.Add(CBORObject.FromObject(ByteArray(64)))
        val signed = CBORObject.NewMap()
        signed[CBORObject.FromObject("nameSpaces")] = ns
        signed[CBORObject.FromObject("issuerAuth")] = auth
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signed.EncodeToBytes())
    }

    private fun mdoc(docType: String, id: Long = 1) =
        StoredCredential(id = id, format = "mso_mdoc", raw = mdocRaw(docType), batchId = id, instanceId = 0)

    private fun sdJwt(vct: String, vararg claims: Pair<String, String>): StoredCredential {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val disclosures = claims.mapIndexed { i, (n, v) -> enc.encodeToString("""["salt$i","$n","$v"]""".toByteArray()) }
        val digests = disclosures.joinToString(",") { "\"" + enc.encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(it.toByteArray())) + "\"" }
        val payload = enc.encodeToString("""{"vct":"$vct","_sd":[$digests],"_sd_alg":"sha-256"}""".toByteArray())
        val raw = "${enc.encodeToString("""{"alg":"ES256"}""".toByteArray())}.$payload.c2ln~" + disclosures.joinToString("~") + "~"
        return StoredCredential(id = 5, format = "dc+sd-jwt", raw = raw, batchId = 5, instanceId = 0)
    }

    private fun query(format: String, doctypeOrVct: String, vararg paths: String): JsonObject {
        val meta = if (format == "mso_mdoc") """"doctype_value":"$doctypeOrVct"""" else """"vct_values":["$doctypeOrVct"]"""
        val claims = paths.joinToString(",") { p ->
            val segs = if (format == "mso_mdoc") listOf(doctypeOrVct, p) else listOf(p)
            """{"path":[${segs.joinToString(",") { "\"$it\"" }}]}"""
        }
        return json.parseToJsonElement(
            """{"credentials":[{"id":"q","format":"$format","meta":{$meta}${if (paths.isEmpty()) "" else ""","claims":[$claims]"""}}]}"""
        ).jsonObject
    }

    // ---- the policy table ----

    @Test
    fun `the default data protects ssc and psc of the nym_auth doctype and nothing else`() {
        val p = NonDisclosurePolicy.DEFAULT
        assertEquals(setOf(nym), p.types)
        assertTrue(p.isProtected(nym, listOf(nym, "ssc")))
        assertTrue(p.isProtected(nym, listOf(nym, "psc")))
        assertFalse(p.isProtected(nym, listOf(nym, "birth_date")))
        assertFalse(p.isProtected(nym, listOf(nym, "given_name")))
        assertFalse(p.isProtected("other.doctype", listOf("other.doctype", "ssc")))
        assertFalse(p.isProtected(null, listOf(nym, "ssc")))
        assertFalse(NonDisclosurePolicy.NONE.isProtected(nym, listOf(nym, "ssc")))
    }

    @Test
    fun `a protected path covers what is below it, and a request for an ancestor reaches it`() {
        val p = NonDisclosurePolicy(mapOf("t" to setOf(listOf("a", "b"))))
        assertTrue(p.isProtected("t", listOf("a", "b")))
        assertTrue(p.isProtected("t", listOf("a", "b", "c")))
        assertFalse(p.isProtected("t", listOf("a")))
        assertFalse(p.isProtected("t", listOf("a", "x")))
        assertTrue(p.requestsProtected("t", listOf(listOf("a", "b"))))
        assertTrue(p.requestsProtected("t", listOf(listOf("a", "b", "c"))))
        assertTrue(p.requestsProtected("t", listOf(listOf("a"))))
        assertTrue(p.requestsProtected("t", listOf(emptyList())))
        assertFalse(p.requestsProtected("t", listOf(listOf("a", "x"), listOf("z"))))
        assertFalse(p.requestsProtected("other", listOf(listOf("a", "b"))))
    }

    @Test
    fun `the table is data, so another type is another entry`() {
        CredentialDisclosureGuard.policy = NonDisclosurePolicy(mapOf("my.vct" to setOf(listOf("secret"))))
        assertTrue(CredentialDisclosureGuard.isProtected("my.vct", listOf("secret")))
        assertFalse(CredentialDisclosureGuard.isProtected(nym, listOf(nym, "ssc")))
    }

    // ---- enforcement point 1: matching ----

    @Test
    fun `a query for ssc or psc matches nothing, a query for birth_date matches`() {
        val cred = mdoc(nym)
        assertTrue(CredentialMatcher.match(query("mso_mdoc", nym, "ssc"), listOf(cred)).single().candidates.isEmpty())
        assertTrue(CredentialMatcher.match(query("mso_mdoc", nym, "psc"), listOf(cred)).single().candidates.isEmpty())
        assertTrue(CredentialMatcher.match(query("mso_mdoc", nym, "birth_date", "ssc"), listOf(cred)).single().candidates.isEmpty())
        assertEquals(1, CredentialMatcher.match(query("mso_mdoc", nym, "birth_date"), listOf(cred)).single().candidates.size)
        assertEquals(1, CredentialMatcher.match(query("mso_mdoc", nym), listOf(cred)).single().candidates.size)
    }

    @Test
    fun `a legacy zk query for a protected claim matches nothing either`() {
        val q = json.parseToJsonElement(
            """{"credentials":[{"id":"q","format":"mso_mdoc_zk","meta":{"doctype_value":"$nym"},"claims":[{"path":["$nym","ssc"]}]}]}"""
        ).jsonObject
        assertTrue(CredentialMatcher.match(q, listOf(mdoc(nym))).single().candidates.isEmpty())
    }

    @Test
    fun `a type without a policy entry is unaffected`() {
        val other = mdoc("other.doctype")
        assertEquals(1, CredentialMatcher.match(query("mso_mdoc", "other.doctype", "ssc"), listOf(other)).single().candidates.size)
        assertEquals(4, CredentialUtils.extractClaims(other).size)
        assertEquals(4, SharedDcqlMatcher.buildFfiClaims(other).size)
    }

    @Test
    fun `an sd-jwt vct with a policy entry is protected the same way`() {
        CredentialDisclosureGuard.policy = NonDisclosurePolicy(mapOf("my.vct" to setOf(listOf("secret"))))
        val c = sdJwt("my.vct", "secret" to "s", "name" to "Jane")
        assertTrue(CredentialMatcher.match(query("dc+sd-jwt", "my.vct", "secret"), listOf(c)).single().candidates.isEmpty())
        assertEquals(1, CredentialMatcher.match(query("dc+sd-jwt", "my.vct", "name"), listOf(c)).single().candidates.size)
        val shown = CredentialUtils.extractClaims(c).map { it.key }
        assertFalse("secret" in shown)
        assertTrue("name" in shown)
        assertFalse(CredentialUtils.flattenClaimPaths(c).any { it.first == listOf("secret") })
        assertTrue(CredentialUtils.flattenClaimPaths(c).any { it.first == listOf("name") })
        assertTrue(SharedDcqlMatcher.buildFfiClaims(c).none { it.path == listOf("secret") })
        assertTrue(SharedDcqlMatcher.buildFfiClaims(c).any { it.path == listOf("name") })
        // Another vct is unaffected.
        val d = sdJwt("another.vct", "secret" to "s")
        assertEquals(1, CredentialMatcher.match(query("dc+sd-jwt", "another.vct", "secret"), listOf(d)).single().candidates.size)
    }

    // ---- enforcement points 2 and 4: the blob's claims, display ----

    @Test
    fun `no protected claim is registered, listed or displayed`() {
        val cred = mdoc(nym)
        val displayed = CredentialUtils.extractClaims(cred)
        assertEquals(setOf("$nym.birth_date", "$nym.given_name"), displayed.map { it.key }.toSet())
        for (c in displayed) {
            assertFalse(c.value.contains("0101") && c.key.endsWith("ssc"))
        }
        assertEquals(displayed.map { it.key }, CredentialUtils.extractMdocClaims(cred).map { it.key })
        val ffi = SharedDcqlMatcher.buildFfiClaims(cred)
        assertEquals(setOf(listOf(nym, "birth_date"), listOf(nym, "given_name")), ffi.map { it.path }.toSet())
        assertTrue(ffi.none { f -> f.path.last() == "ssc" || f.path.last() == "psc" })
    }

    // ---- the guard's own failure ----

    @Test
    fun `a presentation of a protected element is refused, and the refusal names no claim`() {
        val e = assertThrows(DisclosureRefusedException::class.java) {
            CredentialDisclosureGuard.requireNoneProtected(nym, mapOf(nym to listOf("birth_date", "ssc")))
        }
        assertFalse(e.message!!.contains("ssc"))
        CredentialDisclosureGuard.requireNoneProtected(nym, mapOf(nym to listOf("birth_date")))
        CredentialDisclosureGuard.requireNoneProtected("other.doctype", mapOf("other.doctype" to listOf("ssc")))
    }

    @Test
    fun `an sd-jwt presentation with a protected disclosure is refused`() {
        CredentialDisclosureGuard.policy = NonDisclosurePolicy(mapOf("my.vct" to setOf(listOf("secret"))))
        val c = sdJwt("my.vct", "secret" to "s", "name" to "Jane")
        val parts = c.raw.split("~").filter { it.isNotEmpty() }
        val disclosures = parts.drop(1)
        assertThrows(DisclosureRefusedException::class.java) { CredentialDisclosureGuard.requireNoneProtectedSdJwt(c.raw, disclosures) }
        CredentialDisclosureGuard.requireNoneProtectedSdJwt(c.raw, disclosures.drop(1))
        // An unreadable disclosure could be anything, so it is refused too.
        assertThrows(DisclosureRefusedException::class.java) { CredentialDisclosureGuard.requireNoneProtectedSdJwt(c.raw, listOf("!!")) }
        CredentialDisclosureGuard.requireNoneProtectedSdJwt(sdJwt("other.vct", "secret" to "s").raw, listOf(parts[1]))
    }

    // ---- consent summary ----

    @Test
    fun `the consent summary is built from the plan and holds no credential value`() {
        val plan = CircuitZkPlan(
            listOf(
                CircuitZkFunction("pseudonym-v1-sha256", "n", json.parseToJsonElement("""{"config":"known-offender-matching-psc","verifier_id_type":"semantic"}""").jsonObject),
                CircuitZkFunction("age_check", "a", json.parseToJsonElement("""{"ge":"2000-01-01"}""").jsonObject),
            ),
        )
        val s = CircuitZkConsentSummary.from(plan, "Example RP")
        assertEquals(PseudonymSummary("known-offender-matching-psc"), s.pseudonym)
        assertEquals(AgeRangeSummary("2000-01-01", null), s.ageRange)
        assertEquals("Example RP", s.verifierLabel)
        val onlyAge = CircuitZkConsentSummary.from(CircuitZkPlan(listOf(plan.functions[1])), "x")
        assertNull(onlyAge.pseudonym)
    }
}
