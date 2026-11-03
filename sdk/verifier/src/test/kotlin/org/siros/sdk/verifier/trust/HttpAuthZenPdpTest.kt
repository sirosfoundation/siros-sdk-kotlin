// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.trust

import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class HttpAuthZenPdpTest {
    private lateinit var server: MockWebServer

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun permit_postsExactCoreJsonToFullEndpoint_withTenantAndNoAuthentication() = runTest {
        val coreJson = "{\n  \"subject\": {\"id\": \"reader\", \"type\": \"key\"},\n  \"action\": {\"name\": \"verify\"}\n}"
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"decision":true,"context":{"reason":"ok"}}"""))
        val endpoint = server.url("/access/v1/evaluation?mode=sync").toString()
        val pdp = HttpAuthZenPdp(endpoint, "tenant-42", OkHttpClient())

        assertTrue(pdp.evaluate(coreJson))

        val request = server.takeRequest()
        assertEquals("POST", request.method)
        assertEquals("/access/v1/evaluation?mode=sync", request.path)
        assertEquals(coreJson, request.body.readUtf8())
        assertEquals("tenant-42", request.getHeader("X-Tenant-ID"))
        assertNull(request.getHeader("Authorization"))
        assertNull(request.getHeader("Cookie"))
        assertTrue(request.getHeader("Content-Type")?.startsWith("application/json") == true)
    }

    @Test
    fun explicitDeny_failsClosedWithTypedError() = runTest {
        server.enqueue(MockResponse().setBody("""{"decision":false}"""))
        val pdp = pdp()

        expectFailure<AuthZenDeniedException> { pdp.evaluate("{}") }
    }

    @Test
    fun missingMalformedAndNonBooleanDecisions_failClosedWithTypedErrors() = runTest {
        val responses = listOf(
            "{}",
            "[]",
            "not-json",
            """{"decision":true} trailing""",
            """{"decision":null}""",
            """{"decision":"true"}""",
            """{"decision":1}""",
            """{"decision":[]}""",
            """{"decision":false,"decision":true}""",
            """{"decision":true,"decision":false}""",
            """{"\u0064ecision":false,"decision":true}""",
        )
        responses.forEach { server.enqueue(MockResponse().setBody(it)) }
        val pdp = pdp()

        responses.forEach {
            expectFailure<AuthZenResponseException> { pdp.evaluate("{}") }
        }
    }

    @Test
    fun nonSuccessfulHttpStatus_failsClosedWithStatus() = runTest {
        server.enqueue(MockResponse().setResponseCode(503).setBody("""{"decision":true}"""))
        val pdp = pdp()

        val error = expectFailure<AuthZenHttpException> { pdp.evaluate("{}") }
        assertEquals(503, error.statusCode)
    }

    @Test
    fun outage_failsClosedWithTypedNetworkError() = runTest {
        val endpoint = server.url("/v1/evaluate").toString()
        val pdp = HttpAuthZenPdp(endpoint, "default")
        server.shutdown()

        expectFailure<AuthZenNetworkException> { pdp.evaluate("{}") }
    }

    @Test
    fun responseCookies_areNotStoredOrSentOnLaterRequests() = runTest {
        server.enqueue(
            MockResponse().setBody("""{"decision":true}""")
                .addHeader("Set-Cookie", "session=must-not-be-used; Path=/"),
        )
        server.enqueue(MockResponse().setBody("""{"decision":true}"""))
        val pdp = pdp()

        pdp.evaluate("""{"first":true}""")
        pdp.evaluate("""{"second":true}""")
        server.takeRequest()
        val second = server.takeRequest()
        assertNull(second.getHeader("Authorization"))
        assertNull(second.getHeader("Cookie"))
    }

    private fun pdp(): HttpAuthZenPdp = HttpAuthZenPdp(server.url("/v1/evaluate").toString(), "default")

    private suspend inline fun <reified T : Throwable> expectFailure(block: suspend () -> Unit): T {
        try {
            block()
        } catch (error: Throwable) {
            if (error is T) return error
            throw AssertionError("Expected ${T::class.java.name}, got $error", error)
        }
        throw AssertionError("Expected ${T::class.java.name}")
    }
}
