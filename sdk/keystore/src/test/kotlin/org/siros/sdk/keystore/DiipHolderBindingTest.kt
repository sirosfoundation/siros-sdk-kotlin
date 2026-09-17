package org.siros.sdk.keystore

import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.SignedJWT
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.diip.DidRelationship
import org.siros.sdk.credentials.diip.resolveDidJwk
import java.util.Base64

/**
 * The DIIP holder-binding half of the keystore: `did:jwk` key naming, the
 * `jwt` proof shape, and looking a key up by whichever identifier a
 * credential happens to name it with.
 */
class DiipHolderBindingTest {

    private val prfOutput = ByteArray(32) { it.toByte() }
    private val hkdfSalt = ByteArray(32) { (it + 0x10).toByte() }
    private val hkdfInfo = "SIROS Wallet PRF".toByteArray(Charsets.UTF_8)

    private suspend fun unlocked(version: DidKeyVersion = DidKeyVersion.JWK): JweKeystore =
        JweKeystore(didKeyVersion = version).also { it.unlock(prfOutput, ByteArray(0), hkdfSalt, hkdfInfo) }

    // ── key naming ──────────────────────────────────────────────────

    @Test
    fun `a wallet is did jwk out of the box`() = runTest {
        assertEquals(DidKeyVersion.JWK, DidKeyVersion.fromValue(null))
        assertEquals(DidKeyVersion.JWK, DidKeyVersion.fromValue("something-unknown"))
        assertEquals(DidKeyVersion.P256_PUB, DidKeyVersion.fromValue("p256-pub"))
        assertEquals(DidKeyVersion.JWK_JCS_PUB, DidKeyVersion.fromValue("jwk_jcs-pub"))
    }

    @Test
    fun `a new key is named by its did jwk verification method`() = runTest {
        val keystore = unlocked()
        val kid = keystore.generateKey()
        assertTrue("kid is a DID URL, not a thumbprint: $kid", kid.startsWith("did:jwk:"))
        assertTrue(kid.endsWith("#0"))
        // The DID resolves back to the key it names.
        val document = resolveDidJwk(kid.substringBefore('#')).documentOrNull
        assertNotNull(document)
        assertNotNull(document!!.findPublicKey(kid, DidRelationship.AUTHENTICATION))
    }

    @Test
    fun `the legacy did key versions keep naming keys by thumbprint`() = runTest {
        val keystore = unlocked(DidKeyVersion.P256_PUB)
        val kid = keystore.generateKey()
        assertFalse(kid.startsWith("did:"))
    }

    @Test
    fun `a key pair's DID survives a container round trip`() = runTest {
        val keystore = unlocked()
        val kid = keystore.generateKey()
        val container = keystore.exportEncryptedContainer()

        // A wallet reconfigured for a legacy version must not re-identify a
        // key that credentials are already bound to.
        val reloaded = JweKeystore(didKeyVersion = DidKeyVersion.P256_PUB)
        reloaded.unlock(prfOutput, container, hkdfSalt, hkdfInfo)
        assertEquals(listOf(kid), reloaded.listKeys().map { it.keyId })
        assertEquals(kid.substringBefore('#'), reloaded.didForKid(kid))
    }

    // ── the OID4VCI proof ───────────────────────────────────────────

    @Test
    fun `the jwt proof names the holder's DID rather than embedding the key`() = runTest {
        val keystore = unlocked()
        val kid = keystore.generateKey()
        val proof = SignedJWT.parse(keystore.generateProof("https://issuer.example", "n-0S6_WzA2Mj"))

        assertEquals("openid4vci-proof+jwt", proof.header.type.toString())
        assertEquals(kid, proof.header.keyID)
        assertNull("the key is named, not embedded", proof.header.jwk)
        assertEquals(kid.substringBefore('#'), proof.jwtClaimsSet.issuer)
        assertEquals(listOf("https://issuer.example"), proof.jwtClaimsSet.audience)
        assertEquals("n-0S6_WzA2Mj", proof.jwtClaimsSet.getClaim("nonce"))
    }

    @Test
    fun `the proof verifies under the key its DID resolves to`() = runTest {
        // An issuer verifying the proof resolves the DID and checks the
        // signature - this is the seam a mismatch would only show up at.
        val keystore = unlocked()
        val proof = SignedJWT.parse(keystore.generateProof("https://issuer.example", "nonce"))
        val did = proof.jwtClaimsSet.issuer
        val jwk = resolveDidJwk(did).documentOrNull!!
            .findPublicKey(proof.header.keyID, DidRelationship.AUTHENTICATION)!!
        val verifier = com.nimbusds.jose.crypto.ECDSAVerifier(ECKey.parse(jwk.toString()))
        assertTrue(proof.verify(verifier))
    }

    @Test
    fun `without a DID the proof still carries the key in the header`() = runTest {
        // A non-DIIP issuer has nothing to resolve, so the legacy form is the
        // only one it can verify.
        val keystore = unlocked(DidKeyVersion.P256_PUB)
        keystore.generateKey()
        val proof = SignedJWT.parse(keystore.generateProof("https://issuer.example", "nonce"))
        assertNotNull(proof.header.jwk)
        assertNull(proof.jwtClaimsSet.issuer)
    }

    // ── presenting what the wallet already holds ────────────────────

    @Test
    fun `a credential bound by cnf kid is presented with a KB-JWT naming that key`() = runTest {
        val keystore = unlocked()
        val kid = keystore.generateKey()
        val credential = sdJwt("""{"vct":"urn:example:x","cnf":{"kid":"$kid"}}""")

        val vp = keystore.signVpToken(credential, null, "nonce", "https://verifier.example")
        val kb = SignedJWT.parse(vp.substringAfterLast('~'))
        assertEquals("kb+jwt", kb.header.type.toString())
        assertEquals(kid, kb.header.keyID)
        assertNull("a kid-bound credential does not re-embed the key", kb.header.jwk)
    }

    @Test
    fun `a credential bound by cnf jwk keeps the embedded-key KB-JWT`() = runTest {
        // This is the regression that bites an existing wallet: the key pair
        // is named by a DID URL, but the credential can only name it by
        // value, so the lookup has to fall back to the thumbprint.
        val keystore = unlocked()
        val kid = keystore.generateKey()
        val publicJwk = keystore.exportKeypairJwks()[kid]!!.let { ECKey.parse(it).toPublicJWK() }
        val thumbprint = publicJwk.computeThumbprint().toString()
        assertFalse("the stored kid is not the thumbprint", kid == thumbprint)

        val credential = sdJwt("""{"vct":"urn:example:x","cnf":{"jwk":${publicJwk.toJSONString()}}}""")
        val vp = keystore.signVpToken(credential, null, "nonce", "https://verifier.example")
        val kb = SignedJWT.parse(vp.substringAfterLast('~'))
        assertNotNull("a jwk-bound credential keeps the embedded key", kb.header.jwk)
        assertTrue(kb.verify(com.nimbusds.jose.crypto.ECDSAVerifier(publicJwk)))
    }

    @Test
    fun `a key pair is found by thumbprint even when it is named by a DID URL`() = runTest {
        val keystore = unlocked()
        val kid = keystore.generateKey()
        val publicJwk = ECKey.parse(keystore.exportKeypairJwks()[kid]!!).toPublicJWK()
        val thumbprint = publicJwk.computeThumbprint().toString()

        // signPresentation with the thumbprint must reach the same key rather
        // than reporting it unavailable - this is what an mdoc device key or a
        // container written by another client hands us.
        val jwt = SignedJWT.parse(
            keystore.signPresentation("nonce", "https://verifier.example", emptyList(), thumbprint),
        )
        assertTrue(jwt.verify(com.nimbusds.jose.crypto.ECDSAVerifier(publicJwk)))
    }

    @Test
    fun `an unknown kid is still refused`() = runTest {
        // The fallback must not become "sign with whatever key is around".
        val keystore = unlocked()
        keystore.generateKey()
        var threw = false
        try {
            keystore.signPresentation("nonce", "https://verifier.example", emptyList(), "no-such-key")
        } catch (e: Exception) {
            threw = true
        }
        assertTrue("signing with the wrong key is never a safe substitute", threw)
    }

    // ── cnf reading ─────────────────────────────────────────────────

    @Test
    fun `cnf kid is preferred over cnf jwk, and an absent cnf is null`() {
        val jwk = """{"kty":"EC","crv":"P-256","x":"acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0","y":"_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"}"""
        assertEquals(
            "did:jwk:abc#0",
            resolveCnfKid(Json.parseToJsonElement("""{"kid":"did:jwk:abc#0","jwk":$jwk}""") as JsonObject),
        )
        assertEquals(
            ECKey.parse(jwk).computeThumbprint().toString(),
            resolveCnfKid(Json.parseToJsonElement("""{"jwk":$jwk}""") as JsonObject),
        )
        assertNull(resolveCnfKid(null))
    }

    private fun sdJwt(payload: String): String {
        fun b64(s: String) = Base64.getUrlEncoder().withoutPadding().encodeToString(s.toByteArray(Charsets.UTF_8))
        return "${b64("""{"alg":"ES256","typ":"dc+sd-jwt"}""")}.${b64(payload)}.sig~"
    }
}
