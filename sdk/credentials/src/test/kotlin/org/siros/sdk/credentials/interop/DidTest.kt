package org.siros.sdk.credentials.interop

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class DidTest {

    private val p256Jwk = Json.parseToJsonElement(
        """{"kty":"EC","crv":"P-256",
            "x":"acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
            "y":"_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"}""",
    ) as JsonObject

    // ── did:jwk ─────────────────────────────────────────────────────

    @Test
    fun `a did jwk round-trips back to the key it was built from`() {
        val did = createDidJwk(p256Jwk)
        assertTrue(did.startsWith("did:jwk:"))

        val resolution = resolveDidJwk(did)
        val document = resolution.documentOrNull
        assertNotNull("did:jwk resolves offline", document)
        assertEquals(did, document!!.id)

        val key = document.findPublicKey("$did#0", DidRelationship.AUTHENTICATION)
        assertNotNull(key)
        assertEquals(
            p256Jwk["x"]!!.jsonPrimitive.content,
            key!!["x"]!!.jsonPrimitive.content,
        )
    }

    @Test
    fun `the only verification method of a did jwk is hash zero`() {
        val did = createDidJwk(p256Jwk)
        assertEquals("$did#0", didJwkKeyId(did))
        val document = resolveDidJwk(did).documentOrNull!!
        assertEquals(listOf("$did#0"), document.authentication)
        assertEquals(listOf("$did#0"), document.assertionMethod)
    }

    @Test
    fun `WebCrypto bookkeeping and private material never reach the identifier`() {
        // A key exported by WebCrypto carries `ext`/`key_ops`, and a private
        // key carries `d`. Including either would make the same key produce
        // two different DIDs - or publish the private key.
        val noisy = Json.parseToJsonElement(
            """{"kty":"EC","crv":"P-256",
                "x":"acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
                "y":"_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE",
                "d":"secret","ext":true,"key_ops":["sign"]}""",
        ) as JsonObject
        assertEquals(createDidJwk(p256Jwk), createDidJwk(noisy))

        val encoded = createDidJwk(noisy).removePrefix("did:jwk:")
        val decoded = String(Base64.getUrlDecoder().decode(encoded), Charsets.UTF_8)
        assertTrue("no private key material in the DID", !decoded.contains("\"d\""))
        assertTrue(!decoded.contains("key_ops"))
    }

    @Test
    fun `member order does not change the identifier`() {
        val reordered = Json.parseToJsonElement(
            """{"y":"_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE",
                "x":"acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
                "crv":"P-256","kty":"EC"}""",
        ) as JsonObject
        assertEquals(createDidJwk(p256Jwk), createDidJwk(reordered))
    }

    @Test
    fun `a malformed did jwk fails rather than resolving to nothing`() {
        assertTrue(resolveDidJwk("did:jwk:not-base64url!!") is DidResolution.Failed)
        assertTrue(resolveDidJwk("did:web:example.com") is DidResolution.Failed)
    }

    // ── did:web ─────────────────────────────────────────────────────

    @Test
    fun `a bare did web resolves to the well-known path`() {
        assertEquals(
            "https://example.com/.well-known/did.json",
            DidResolver.didWebToUrl("did:web:example.com"),
        )
    }

    @Test
    fun `path segments of a did web become URL path segments`() {
        assertEquals(
            "https://example.com/issuers/1/did.json",
            DidResolver.didWebToUrl("did:web:example.com:issuers:1"),
        )
    }

    @Test
    fun `a percent-encoded port is decoded back into the host`() {
        assertEquals(
            "https://example.com:8443/.well-known/did.json",
            DidResolver.didWebToUrl("did:web:example.com%3A8443"),
        )
    }

    @Test
    fun `a document served for a different subject is rejected`() = runBlocking {
        // Otherwise any domain could serve a document for any DID.
        val resolver = DidResolver(httpGet = { """{"id":"did:web:evil.example"}""" })
        val result = resolver.resolve("did:web:example.com")
        assertTrue(result is DidResolution.Failed)
    }

    @Test
    fun `a did web document resolves its assertionMethod key`() = runBlocking {
        val body = """
            {
              "id": "did:web:issuer.example",
              "verificationMethod": [{
                "id": "did:web:issuer.example#key-1",
                "type": "JsonWebKey2020",
                "controller": "did:web:issuer.example",
                "publicKeyJwk": {"kty":"EC","crv":"P-256","x":"aa","y":"bb"}
              }],
              "assertionMethod": ["did:web:issuer.example#key-1"]
            }
        """.trimIndent()
        val resolver = DidResolver(httpGet = { body })
        val document = resolver.resolve("did:web:issuer.example").documentOrNull
        assertNotNull(document)
        val key = document!!.findPublicKey("did:web:issuer.example#key-1", DidRelationship.ASSERTION_METHOD)
        assertEquals("aa", key!!["x"]!!.jsonPrimitive.content)
    }

    @Test
    fun `an unreachable did web is a failure, not an empty document`() = runBlocking {
        val resolver = DidResolver(httpGet = { null })
        assertTrue(resolver.resolve("did:web:example.com") is DidResolution.Failed)
    }

    // ── did:webvh ───────────────────────────────────────────────────

    @Test
    fun `did webvh fails closed rather than serving an unverified document`() = runBlocking {
        // Its whole value over did:web is the verifiable log; a resolver that
        // skipped the proof chain would offer did:web trust while looking
        // like more.
        val resolver = DidResolver(profile = DiipProfile.V6, httpGet = { "{}" })
        val result = resolver.resolve("did:webvh:scid:example.com")
        assertTrue(result is DidResolution.Failed)
        assertTrue(DidMethod.WEBVH in resolver.requiredMethods)
    }

    // ── documents and cnf ───────────────────────────────────────────

    @Test
    fun `an inline verification method is registered as well as a referenced one`() {
        val document = parseDidDocument(
            Json.parseToJsonElement(
                """
                {
                  "id": "did:web:x.example",
                  "authentication": [{
                    "id": "#inline",
                    "type": "JsonWebKey2020",
                    "publicKeyJwk": {"kty":"EC","crv":"P-256","x":"cc","y":"dd"}
                  }]
                }
                """.trimIndent(),
            ) as JsonObject,
        )
        // A relative fragment is resolved against the document's own id.
        val key = document.findPublicKey("did:web:x.example#inline", DidRelationship.AUTHENTICATION)
        assertEquals("cc", key!!["x"]!!.jsonPrimitive.content)
    }

    @Test
    fun `a kid is matched by fragment when it is not the full DID URL`() {
        val did = createDidJwk(p256Jwk)
        val document = resolveDidJwk(did).documentOrNull!!
        assertNotNull(document.findPublicKey("#0", DidRelationship.AUTHENTICATION))
    }

    @Test
    fun `cnf kid wins over cnf jwk, and an absent binding is null`() {
        val thumbprint = { _: JsonObject -> "THUMB" }
        assertEquals(
            "did:jwk:abc#0",
            resolveCnfKid(
                Json.parseToJsonElement("""{"kid":"did:jwk:abc#0","jwk":{"kty":"EC"}}""") as JsonObject,
                thumbprint,
            ),
        )
        assertEquals(
            "THUMB",
            resolveCnfKid(Json.parseToJsonElement("""{"jwk":{"kty":"EC"}}""") as JsonObject, thumbprint),
        )
        assertNull(resolveCnfKid(null, thumbprint))
        assertNull(resolveCnfKid(Json.parseToJsonElement("{}") as JsonObject, thumbprint))
    }

    @Test
    fun `a DID's method is read from the identifier`() {
        assertEquals(DidMethod.JWK, DidMethod.of("did:jwk:abc"))
        assertEquals(DidMethod.WEB, DidMethod.of("did:web:example.com"))
        assertEquals(DidMethod.WEBVH, DidMethod.of("did:webvh:scid:example.com"))
        assertNull(DidMethod.of("https://example.com"))
        assertNull(DidMethod.of("did:unknown:x"))
    }
}
