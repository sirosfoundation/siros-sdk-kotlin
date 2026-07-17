package org.siros.sdk.auth

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.AuthException
import java.util.Base64

class AccessTokenTest {

    private fun buildJwt(payload: String): String {
        val header = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("""{"alg":"RS256","typ":"JWT"}""".toByteArray())
        val body = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(payload.toByteArray())
        val signature = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("fake-signature".toByteArray())
        return "$header.$body.$signature"
    }

    @Test
    fun `parses valid access token`() {
        val exp = (System.currentTimeMillis() / 1000) + 3600
        val jwt = buildJwt("""
            {"sub":"user-123","aud":"wallet-backend","tenant_id":"t1",
             "tac":"rwl","acr":"urn:siros:acr:passkey","exp":$exp}
        """.trimIndent())

        val token = AccessToken(jwt)
        assertEquals("user-123", token.sub)
        assertEquals("wallet-backend", token.aud)
        assertEquals("t1", token.tenantId)
        assertEquals(
            setOf(TacPermission.READ, TacPermission.WRITE, TacPermission.LIST),
            token.tac
        )
        assertEquals(Acr.PASSKEY, token.acr)
        assertFalse(token.isExpired())
        assertEquals(jwt, token.token())
    }

    @Test
    fun `parses OIDC acr`() {
        val exp = (System.currentTimeMillis() / 1000) + 3600
        val jwt = buildJwt("""
            {"sub":"u","aud":"a","tenant_id":"t",
             "tac":"r","acr":"urn:siros:acr:oidc","exp":$exp}
        """.trimIndent())

        val token = AccessToken(jwt)
        assertEquals(Acr.OIDC, token.acr)
    }

    @Test
    fun `isExpired returns true for past expiry`() {
        val exp = (System.currentTimeMillis() / 1000) - 100
        val jwt = buildJwt("""
            {"sub":"u","aud":"a","tenant_id":"t",
             "tac":"r","acr":"urn:siros:acr:passkey","exp":$exp}
        """.trimIndent())

        val token = AccessToken(jwt)
        assertTrue(token.isExpired())
    }

    @Test
    fun `isExpired returns true within 10 second margin`() {
        val exp = (System.currentTimeMillis() / 1000) + 5 // 5 seconds from now
        val jwt = buildJwt("""
            {"sub":"u","aud":"a","tenant_id":"t",
             "tac":"r","acr":"urn:siros:acr:passkey","exp":$exp}
        """.trimIndent())

        val token = AccessToken(jwt)
        assertTrue(token.isExpired())
    }

    @Test(expected = AuthException::class)
    fun `throws on invalid JWT format`() {
        AccessToken("not-a-jwt")
    }

    @Test
    fun `maps unknown ACR to UNKNOWN`() {
        val exp = (System.currentTimeMillis() / 1000) + 3600
        val jwt = buildJwt("""
            {"sub":"u","aud":"a","tenant_id":"t",
             "tac":"r","acr":"urn:unknown:acr","exp":$exp}
        """.trimIndent())
        val token = AccessToken(jwt)
        assertEquals(Acr.UNKNOWN, token.acr)
    }

    @Test
    fun `parses all TAC permissions`() {
        val exp = (System.currentTimeMillis() / 1000) + 3600
        val jwt = buildJwt("""
            {"sub":"u","aud":"a","tenant_id":"t",
             "tac":"rwlidka","acr":"urn:siros:acr:passkey","exp":$exp}
        """.trimIndent())

        val token = AccessToken(jwt)
        assertEquals(TacPermission.entries.toSet(), token.tac)
    }
}

class TacPermissionTest {
    @Test
    fun `parse returns correct set`() {
        val result = TacPermission.parse("rwl")
        assertEquals(
            setOf(TacPermission.READ, TacPermission.WRITE, TacPermission.LIST),
            result
        )
    }

    @Test
    fun `parse ignores unknown chars`() {
        val result = TacPermission.parse("rxw")
        assertEquals(setOf(TacPermission.READ, TacPermission.WRITE), result)
    }

    @Test
    fun `parse empty string returns empty set`() {
        assertEquals(emptySet<TacPermission>(), TacPermission.parse(""))
    }
}
