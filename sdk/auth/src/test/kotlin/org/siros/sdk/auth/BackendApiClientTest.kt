package org.siros.sdk.auth

import org.siros.sdk.credentials.BackendApiException
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class BackendApiClientTest {

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
    fun get_account_info_sends_expected_headers() = runBlocking {
        server.enqueue(MockResponse().setBody("{}"))

        val client = newClient()
        client.setAppToken("token-abc")
        client.getAccountInfo()

        val request = server.takeRequest()
        assertEquals("/user/session/account-info", request.path)
        assertEquals("default", request.getHeader("X-Tenant-ID"))
        assertEquals("Bearer token-abc", request.getHeader("Authorization"))
    }

    @Test
    fun unauthenticated_request_omits_authorization_header() = runBlocking {
        server.enqueue(MockResponse().setBody("{}"))

        val client = newClient()
        client.healthCheck()

        val request = server.takeRequest()
        assertEquals("/health", request.path)
        assertEquals(null, request.getHeader("Authorization"))
    }

    @Test
    fun get_issuers_accepts_array_payload() = runBlocking {
        server.enqueue(MockResponse().setBody("""[{"id": 1, "visible": true}]"""))

        val client = newClient()
        val issuers = client.getIssuers()

        assertTrue(issuers is JsonArray)
    }

    @Test
    fun update_private_data_posts_json_body() = runBlocking {
        server.enqueue(MockResponse().setBody("{}"))

        val client = newClient()
        client.setAppToken("token-xyz")
        client.updatePrivateData(
            buildJsonObject {
                put("privateData", "opaque")
            }
        )

        val request = server.takeRequest()
        assertEquals("/user/session/private-data", request.path)
        assertEquals("POST", request.method)
        assertTrue(request.body.readUtf8().contains("privateData"))
    }

    @Test
    fun evaluate_trust_posts_to_expected_endpoint_with_auth_header() = runBlocking {
        server.enqueue(MockResponse().setBody("{\"decision\":true}"))

        val client = newClient()
        client.setAppToken("token-trust")
        val response = client.evaluateTrust(
            buildJsonObject {
                put("subject", "issuer-123")
            }
        )

        val request = server.takeRequest()
        assertEquals("/v1/evaluate", request.path)
        assertEquals("POST", request.method)
        assertEquals("Bearer token-trust", request.getHeader("Authorization"))
        assertTrue(request.body.readUtf8().contains("issuer-123"))
        assertEquals(true, response["decision"]?.toString()?.contains("true"))
    }

    @Test
    fun delete_credential_uses_delete_method() = runBlocking {
        server.enqueue(MockResponse().setBody("{}"))

        val client = newClient()
        client.deleteCredential("cred-42")

        val request = server.takeRequest()
        assertEquals("/storage/vc/cred-42", request.path)
        assertEquals("DELETE", request.method)
    }

    @Test
    fun tenant_config_uses_tenant_specific_path() = runBlocking {
        server.enqueue(MockResponse().setBody("{}"))

        val client = BackendApiClient(
            baseUrl = server.url("/").toString().trimEnd('/'),
            tenantId = "tenant-42",
        )
        client.getTenantConfig()

        val request = server.takeRequest()
        assertEquals("/api/v1/tenants/tenant-42/config", request.path)
        assertEquals("tenant-42", request.getHeader("X-Tenant-ID"))
    }

    @Test
    fun blank_success_body_returns_empty_json_object() = runBlocking {
        server.enqueue(MockResponse().setBody(""))

        val client = newClient()
        val response = client.healthCheck()

        assertEquals(JsonObject(emptyMap()), response)
    }

    @Test
    fun non_success_response_throws_backend_api_exception() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(500).setBody("boom"))

        val client = newClient()

        try {
            client.healthCheck()
            throw AssertionError("Expected BackendApiException")
        } catch (e: BackendApiException) {
            assertEquals(500, e.code)
            assertTrue(e.body?.contains("boom") == true)
        }
    }

    @Test
    fun requestKeyAttestation_sendsJwksNonceAndCredentialIssuer() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"key_attestation": "signed-jwt"}"""))

        val client = newClient()
        val jwk = buildJsonObject { put("kty", "EC") }
        val result = client.requestKeyAttestation(
            jwks = listOf(jwk),
            nonce = "nonce-1",
            securityProperties = org.siros.sdk.credentials.SignerSecurityProperties(
                keyStorage = listOf("iso_18045_high"),
                userAuthentication = listOf("iso_18045_high"),
            ),
            credentialIssuer = "https://issuer.example.com",
        )

        assertEquals("signed-jwt", result)
        val request = server.takeRequest()
        assertEquals("/wallet-provider/key-attestation/generate", request.path)
        val body = kotlinx.serialization.json.Json.parseToJsonElement(request.body.readUtf8()).jsonObject
        assertEquals(1, body["jwks"]!!.jsonArray.size)
        assertEquals("nonce-1", body["openid4vci"]!!.jsonObject["nonce"]!!.jsonPrimitive.content)
        assertEquals(
            "https://issuer.example.com",
            body["openid4vci"]!!.jsonObject["credential_issuer"]!!.jsonPrimitive.content,
        )
        assertEquals(
            listOf("iso_18045_high"),
            body["security_properties"]!!.jsonObject["key_storage"]!!.jsonArray.map { it.jsonPrimitive.content },
        )
    }

    @Test
    fun requestKeyAttestation_omitsCredentialIssuer_whenNotProvided() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"key_attestation": "signed-jwt"}"""))

        val client = newClient()
        client.requestKeyAttestation(
            jwks = listOf(buildJsonObject { put("kty", "EC") }),
            nonce = "nonce-1",
        )

        val request = server.takeRequest()
        val body = kotlinx.serialization.json.Json.parseToJsonElement(request.body.readUtf8()).jsonObject
        assertEquals(false, body["openid4vci"]!!.jsonObject.containsKey("credential_issuer"))
    }

    private fun newClient(): BackendApiClient {
        val baseUrl = server.url("/").toString().trimEnd('/')
        return BackendApiClient(baseUrl = baseUrl, tenantId = "default")
    }
}
