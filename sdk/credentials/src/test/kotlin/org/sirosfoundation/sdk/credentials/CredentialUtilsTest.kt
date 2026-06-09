package org.sirosfoundation.sdk.credentials

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CredentialUtilsTest {

    // A valid SD-JWT VC with header.payload.signature format
    // Header: {"alg":"ES256","typ":"vc+sd-jwt"}
    // Payload below
    private val sampleJwt: String by lazy {
        val header = b64url("""{"alg":"ES256","typ":"vc+sd-jwt"}""")
        val payload = b64url("""{
            "iss": "https://issuer.example.com",
            "sub": "user123",
            "iat": 1700000000,
            "exp": 1800000000,
            "vct": "urn:example:diploma",
            "given_name": "Alice",
            "family_name": "Smith",
            "degree": "MSc Computer Science",
            "cnf": {"jwk": {}},
            "_sd_alg": "sha-256"
        }""")
        "$header.$payload.fakesig"
    }

    private fun b64url(s: String): String =
        java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(s.toByteArray())

    @Test
    fun `parseJwtPayload extracts payload from JWT`() {
        val payload = CredentialUtils.parseJwtPayload(sampleJwt)
        assertNotNull(payload)
        assertEquals("https://issuer.example.com", payload!!["iss"]?.let {
            (it as kotlinx.serialization.json.JsonPrimitive).content
        })
        assertEquals("Alice", payload["given_name"]?.let {
            (it as kotlinx.serialization.json.JsonPrimitive).content
        })
    }

    @Test
    fun `parseJwtPayload handles SD-JWT with disclosures`() {
        val sdJwt = "$sampleJwt~disclosure1~disclosure2"
        val payload = CredentialUtils.parseJwtPayload(sdJwt)
        assertNotNull(payload)
        assertEquals("Alice", payload!!["given_name"]?.let {
            (it as kotlinx.serialization.json.JsonPrimitive).content
        })
    }

    @Test
    fun `parseJwtPayload returns null for invalid input`() {
        assertNull(CredentialUtils.parseJwtPayload("not-a-jwt"))
        assertNull(CredentialUtils.parseJwtPayload(""))
        assertNull(CredentialUtils.parseJwtPayload("only-one-part"))
    }

    @Test
    fun `parseJwtPayload returns null for malformed base64`() {
        assertNull(CredentialUtils.parseJwtPayload("aaa.!!!invalid!!!.bbb"))
    }

    @Test
    fun `extractClaims returns user-facing claims`() {
        val cred = StoredCredential(
            id = "test-id",
            format = "vc+sd-jwt",
            raw = sampleJwt,
        )
        val claims = CredentialUtils.extractClaims(cred)
        // Should exclude JWT metadata keys (iss, sub, iat, exp, vct, cnf, _sd_alg)
        val keys = claims.map { it.key }
        assertTrue("given_name" in keys)
        assertTrue("family_name" in keys)
        assertTrue("degree" in keys)
        assertTrue("iss" !in keys)
        assertTrue("exp" !in keys)
        assertTrue("cnf" !in keys)
        assertTrue("_sd_alg" !in keys)
        assertTrue("vct" !in keys)
    }

    @Test
    fun `extractClaims uses VCTM labels when available`() {
        val cred = StoredCredential(
            id = "test-id",
            format = "vc+sd-jwt",
            raw = sampleJwt,
            metadata = CredentialMetadata(
                claims = listOf(
                    ClaimMeta(path = listOf("given_name"), label = "First Name"),
                    ClaimMeta(path = listOf("family_name"), label = "Surname"),
                ),
            ),
        )
        val claims = CredentialUtils.extractClaims(cred)
        val givenName = claims.find { it.key == "given_name" }
        assertNotNull(givenName)
        assertEquals("First Name", givenName!!.label)

        val familyName = claims.find { it.key == "family_name" }
        assertNotNull(familyName)
        assertEquals("Surname", familyName!!.label)
    }

    @Test
    fun `extractClaims formats keys when no VCTM`() {
        val cred = StoredCredential(
            id = "test-id",
            format = "vc+sd-jwt",
            raw = sampleJwt,
        )
        val claims = CredentialUtils.extractClaims(cred)
        val givenName = claims.find { it.key == "given_name" }
        assertEquals("Given Name", givenName!!.label)
    }

    @Test
    fun `extractClaims returns empty for unparseable credential`() {
        val cred = StoredCredential(id = "bad", format = "vc+sd-jwt", raw = "not-a-jwt")
        assertTrue(CredentialUtils.extractClaims(cred).isEmpty())
    }

    @Test
    fun `formatClaimKey formats snake_case and kebab-case`() {
        assertEquals("Given Name", CredentialUtils.formatClaimKey("given_name"))
        assertEquals("Family Name", CredentialUtils.formatClaimKey("family-name"))
        assertEquals("Degree", CredentialUtils.formatClaimKey("degree"))
    }

    @Test
    fun `buildMetadata combines offer and VCTM`() {
        val offer = CredentialOffer(
            credentialConfigurationId = "diploma",
            credentialIssuerIdentifier = "https://issuer.example.com",
            credentialName = "Diploma (offer)",
            issuerName = "Test Issuer",
            backgroundColor = "#000000",
        )
        val vctm = Vctm(
            vct = "urn:example:diploma",
            display = listOf(
                VctmDisplay(
                    locale = "en",
                    name = "University Diploma",
                    description = "A diploma from VCTM",
                    rendering = VctmRendering(
                        simple = VctmSimpleRendering(
                            backgroundColor = "#003366",
                            textColor = "#ffffff",
                        ),
                    ),
                ),
            ),
            claims = listOf(
                VctmClaim(
                    path = listOf("given_name"),
                    display = listOf(VctmClaimDisplay(locale = "en", label = "Given Name")),
                    sd = "allowed",
                    mandatory = true,
                ),
            ),
        )

        val metadata = CredentialUtils.buildMetadata(
            offer = offer,
            vctm = vctm,
            rawCredential = sampleJwt,
        )

        // VCTM display should take precedence
        assertEquals("University Diploma", metadata.name)
        assertEquals("A diploma from VCTM", metadata.description)
        assertEquals("#003366", metadata.backgroundColor)
        assertEquals("#ffffff", metadata.textColor)
        assertEquals("urn:example:diploma", metadata.vct)
        assertEquals("Test Issuer", metadata.issuer?.name)
        assertEquals(1, metadata.claims?.size)
        assertEquals("Given Name", metadata.claims!![0].label)
        assertEquals(true, metadata.claims!![0].mandatory)
    }

    @Test
    fun `buildMetadata falls back to offer when no VCTM`() {
        val offer = CredentialOffer(
            credentialConfigurationId = "diploma",
            credentialIssuerIdentifier = "https://issuer.example.com",
            credentialName = "Diploma (offer)",
            issuerName = "Test Issuer",
            backgroundColor = "#000000",
        )
        val metadata = CredentialUtils.buildMetadata(offer = offer)
        assertEquals("Diploma (offer)", metadata.name)
        assertEquals("#000000", metadata.backgroundColor)
        assertNull(metadata.claims)
    }
}
