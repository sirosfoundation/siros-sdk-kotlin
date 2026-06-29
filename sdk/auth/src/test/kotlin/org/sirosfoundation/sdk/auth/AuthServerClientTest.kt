package org.sirosfoundation.sdk.auth

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import org.sirosfoundation.sdk.credentials.AuthException
import java.util.Base64

class AuthServerClientTest {

    private lateinit var server: MockWebServer
    private lateinit var client: AuthServerClient

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
        client = AuthServerClient(
            baseUrl = server.url("/").toString().trimEnd('/'),
            tenantId = "test-tenant",
            httpClient = okhttp3.OkHttpClient.Builder()
                .cookieJar(InMemoryCookieJar())
                .build(),
        )
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    private fun buildJwt(payload: String): String {
        val header = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("""{"alg":"RS256","typ":"JWT"}""".toByteArray())
        val body = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(payload.toByteArray())
        val signature = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("fake".toByteArray())
        return "$header.$body.$signature"
    }

    // ---- loginBegin ----

    @Test
    fun `loginBegin sends correct headers`() = runBlocking {
        server.enqueue(MockResponse()
            .setBody("""{"challengeId":"c1","getOptions":{"publicKey":{"rpId":"example.com","challenge":"AAAA"}}}""")
            .setHeader("Content-Type", "application/json"))

        val response = client.loginBegin()
        assertEquals("c1", response["challengeId"].toString().trim('"'))

        val request = server.takeRequest()
        assertEquals("POST", request.method)
        assertEquals("/auth/passkey/login/begin", request.path)
        assertEquals("session", request.getHeader("X-Token-Mode"))
        assertEquals("test-tenant", request.getHeader("X-Tenant-ID"))
    }

    @Test
    fun `loginBegin sends oidc token as bearer header`() = runBlocking {
        server.enqueue(MockResponse()
            .setBody("""{"challengeId":"c1","getOptions":{"publicKey":{}}}""")
            .setHeader("Content-Type", "application/json"))

        client.loginBegin(oidcIdToken = "my-id-token")
        val request = server.takeRequest()
        assertEquals("Bearer my-id-token", request.getHeader("Authorization"))
    }

    // ---- loginFinish ----

    @Test
    fun `loginFinish returns parsed result`() = runBlocking {
        server.enqueue(MockResponse()
            .setBody("""{"uuid":"u1","displayName":"Alice","tenantId":"t1"}""")
            .setHeader("Content-Type", "application/json"))

        val credential = buildJsonObject {
            put("id", "cred-id")
            put("type", "public-key")
        }
        val result = client.loginFinish("challenge-1", credential)
        assertEquals("u1", result.uuid)
        assertEquals("Alice", result.displayName)
        assertEquals("t1", result.tenantId)

        val request = server.takeRequest()
        assertEquals("/auth/passkey/login/finish", request.path)
    }

    // ---- registerBegin ----

    @Test
    fun `registerBegin sends tenant and invite code`() = runBlocking {
        server.enqueue(MockResponse()
            .setBody("""{"challengeId":"c2","createOptions":{"publicKey":{}}}""")
            .setHeader("Content-Type", "application/json"))

        client.registerBegin(inviteCode = "inv-123")
        val request = server.takeRequest()
        assertEquals("/auth/passkey/register/begin", request.path)
        val body = request.body.readUtf8()
        assert(body.contains("\"inviteCode\":\"inv-123\"")) { "Body should contain inviteCode" }
        assert(body.contains("\"tenantId\":\"test-tenant\"")) { "Body should contain tenantId" }
    }

    // ---- registerFinish ----

    @Test
    fun `registerFinish returns parsed result`() = runBlocking {
        server.enqueue(MockResponse()
            .setBody("""{"uuid":"u2","displayName":"Bob","tenantId":"t1"}""")
            .setHeader("Content-Type", "application/json"))

        val credential = buildJsonObject {
            put("id", "cred-id")
            put("type", "public-key")
        }
        val result = client.registerFinish("ch-1", credential, "Bob")
        assertEquals("u2", result.uuid)
        assertEquals("Bob", result.displayName)

        val request = server.takeRequest()
        assertEquals("/auth/passkey/register/finish", request.path)
    }

    // ---- requestAccessToken ----

    @Test
    fun `requestAccessToken returns parsed token`() = runBlocking {
        val exp = (System.currentTimeMillis() / 1000) + 3600
        val jwt = buildJwt("""{"sub":"u","aud":"wallet-backend","tenant_id":"t1","tac":"rwl","acr":"urn:siros:acr:passkey","exp":$exp}""")

        server.enqueue(MockResponse()
            .setBody("""{"access_token":"$jwt","token_type":"Bearer","expires_in":3600}""")
            .setHeader("Content-Type", "application/json"))

        val token = client.requestAccessToken("wallet-backend", "rwl")
        assertEquals("wallet-backend", token.aud)
        assertEquals("u", token.sub)

        val request = server.takeRequest()
        assertEquals("/auth/token", request.path)
        val body = request.body.readUtf8()
        assert(body.contains("\"aud\":\"wallet-backend\""))
        assert(body.contains("\"tac\":\"rwl\""))
        assert(body.contains("\"tenant_id\":\"test-tenant\""))
    }

    @Test
    fun `requestAccessToken caches token`() = runBlocking {
        val exp = (System.currentTimeMillis() / 1000) + 3600
        val jwt = buildJwt("""{"sub":"u","aud":"wb","tenant_id":"t","tac":"r","acr":"urn:siros:acr:passkey","exp":$exp}""")

        server.enqueue(MockResponse()
            .setBody("""{"access_token":"$jwt","token_type":"Bearer","expires_in":3600}""")
            .setHeader("Content-Type", "application/json"))

        val token1 = client.requestAccessToken("wb", "r")
        val token2 = client.requestAccessToken("wb", "r")
        // Should only have made 1 request (second served from cache)
        assertEquals(1, server.requestCount)
        assertEquals(token1.raw, token2.raw)
    }

    // ---- logout ----

    @Test
    fun `logout sends DELETE to auth session`() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(204))
        client.logout()

        val request = server.takeRequest()
        assertEquals("DELETE", request.method)
        assertEquals("/auth/session", request.path)
    }

    // ---- error handling ----

    @Test(expected = AuthException::class)
    fun `loginBegin throws on non-2xx response`(): Unit = runBlocking {
        server.enqueue(MockResponse().setResponseCode(401).setBody("""{"error":"unauthorized"}"""))
        client.loginBegin()
    }
}
