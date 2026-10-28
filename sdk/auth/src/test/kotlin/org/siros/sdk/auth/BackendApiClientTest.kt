package org.siros.sdk.auth

import org.siros.sdk.credentials.BackendApiException
import io.mockk.coEvery
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
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
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.util.Base64

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
    fun resolve_key_posts_key_subject_type_to_resolve_endpoint() = runBlocking {
        server.enqueue(MockResponse().setBody("{\"context\":{}}"))

        val client = newClient()
        client.setAppToken("token-resolve")
        client.resolveKey("did:web:verifier.example.com")

        val request = server.takeRequest()
        assertEquals("/v1/resolve", request.path)
        assertEquals("POST", request.method)
        assertEquals("Bearer token-resolve", request.getHeader("Authorization"))
        val body = kotlinx.serialization.json.Json.parseToJsonElement(request.body.readUtf8()).jsonObject
        assertEquals("did:web:verifier.example.com", body["subject_id"]?.jsonPrimitive?.content)
        // subject_type: "key" is the core distinction from resolveIssuer's
        // subject_type: "url" - the two must never be confused (#219 review
        // finding).
        assertEquals("key", body["subject_type"]?.jsonPrimitive?.content)
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
    fun requestKeyAttestation_sendsTheClaimedPluginAsSecurityPropertiesPlugin_andNeverAltersTheOtherProperties() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"key_attestation": "signed-jwt"}"""))
        server.enqueue(MockResponse().setBody("""{"key_attestation": "signed-jwt"}"""))
        server.enqueue(MockResponse().setBody("""{"key_attestation": "signed-jwt"}"""))
        val client = newClient()
        val props = org.siros.sdk.credentials.SignerSecurityProperties(keyStorage = listOf("software"), userAuthentication = listOf("pin"))
        val jwk = buildJsonObject { put("kty", "EC") }
        client.requestKeyAttestation(listOf(jwk), "n", securityProperties = props, plugin = "soft")
        client.requestKeyAttestation(listOf(jwk), "n", securityProperties = props)
        client.requestKeyAttestation(listOf(jwk), "n", securityProperties = null, plugin = "soft")
        fun sp() = kotlinx.serialization.json.Json.parseToJsonElement(server.takeRequest().body.readUtf8()).jsonObject["security_properties"]?.jsonObject
        val withPlugin = sp()!!
        assertEquals("soft", withPlugin["plugin"]!!.jsonPrimitive.content)
        assertEquals(listOf("software"), withPlugin["key_storage"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertEquals(listOf("pin"), withPlugin["user_authentication"]!!.jsonArray.map { it.jsonPrimitive.content })
        // Unset: no plugin member at all.
        assertEquals(null, sp()!!["plugin"])
        // Only the claim, no properties from the keystore: just {"plugin": "soft"}.
        assertEquals(setOf("plugin"), sp()!!.keys)
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

    @Test
    fun requestKeyAttestation_sendsWalletInstanceId_whenProvided() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"key_attestation": "signed-jwt"}"""))

        val client = newClient()
        client.requestKeyAttestation(
            jwks = listOf(buildJsonObject { put("kty", "EC") }),
            nonce = "nonce-1",
            walletInstanceId = "test-jkt",
        )

        val request = server.takeRequest()
        val body = kotlinx.serialization.json.Json.parseToJsonElement(request.body.readUtf8()).jsonObject
        assertEquals("test-jkt", body["wallet_instance_id"]!!.jsonPrimitive.content)
    }

    @Test
    fun requestKeyAttestation_omitsWalletInstanceId_whenNotProvided() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"key_attestation": "signed-jwt"}"""))

        val client = newClient()
        client.requestKeyAttestation(
            jwks = listOf(buildJsonObject { put("kty", "EC") }),
            nonce = "nonce-1",
        )

        val request = server.takeRequest()
        val body = kotlinx.serialization.json.Json.parseToJsonElement(request.body.readUtf8()).jsonObject
        assertEquals(false, body.containsKey("wallet_instance_id"))
    }

    @Test
    fun registerFido2Attestation_sendsExpectedFields() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"verified": true}"""))

        val client = newClient()
        client.registerFido2Attestation(
            walletInstanceId = "test-jkt",
            attestationObject = byteArrayOf(0x01, 0x02, 0x03),
            clientDataHash = ByteArray(32) { 0x09 },
        )

        val request = server.takeRequest()
        assertEquals("/wallet-provider/fido2-attestation/register", request.path)
        assertEquals("POST", request.method)
        val body = kotlinx.serialization.json.Json.parseToJsonElement(request.body.readUtf8()).jsonObject
        assertEquals("test-jkt", body["wallet_instance_id"]!!.jsonPrimitive.content)
        assertEquals(
            WebAuthnAuthClient.encodeBase64Url(byteArrayOf(0x01, 0x02, 0x03)),
            body["attestation_object"]!!.jsonPrimitive.content,
        )
        assertEquals(
            WebAuthnAuthClient.encodeBase64Url(ByteArray(32) { 0x09 }),
            body["client_data_hash"]!!.jsonPrimitive.content,
        )
    }

    @Test
    fun registerFido2Attestation_throwsOnRejection() = runBlocking {
        server.enqueue(
            MockResponse().setResponseCode(400).setBody("""{"error": "ATTESTATION_INVALID"}""")
        )

        val client = newClient()

        try {
            client.registerFido2Attestation(
                walletInstanceId = "test-jkt",
                attestationObject = byteArrayOf(0x01),
                clientDataHash = ByteArray(32),
            )
            throw AssertionError("Expected BackendApiException")
        } catch (e: BackendApiException) {
            assertEquals(400, e.code)
        }
    }

    @Test
    fun non_success_401_response_registers_token_rejection() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(401).setBody("""{"error":"unauthorized"}"""))

        val authTokens = mockk<AuthTokens>(relaxed = true)
        coEvery { authTokens.ensureBackendToken() } returns fakeBackendToken()

        val client = newClient()
        client.setAuthTokens(authTokens)

        try {
            client.healthCheck()
            throw AssertionError("Expected BackendApiException")
        } catch (e: BackendApiException) {
            assertEquals(401, e.code)
        }

        verify(exactly = 1) { authTokens.registerTokenRejection(AuthTokens.TOKEN_BACKEND) }
    }

    @Test
    fun non_401_failure_does_not_register_token_rejection() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(500).setBody("boom"))

        val authTokens = mockk<AuthTokens>(relaxed = true)
        coEvery { authTokens.ensureBackendToken() } returns fakeBackendToken()

        val client = newClient()
        client.setAuthTokens(authTokens)

        try {
            client.healthCheck()
            throw AssertionError("Expected BackendApiException")
        } catch (e: BackendApiException) {
            assertEquals(500, e.code)
        }

        verify(exactly = 0) { authTokens.registerTokenRejection(any()) }
    }

    /** A syntactically valid, unexpired access token JWT for stubbing [AuthTokens.ensureBackendToken]. */
    private fun fakeBackendToken(): AccessToken {
        val exp = (System.currentTimeMillis() / 1000) + 3600
        val header = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("""{"alg":"RS256","typ":"JWT"}""".toByteArray())
        val body = Base64.getUrlEncoder().withoutPadding().encodeToString(
            ("""{"sub":"user-1","aud":"wallet-backend","tenant_id":"default",""" +
                """"tac":"rwlid","acr":"urn:siros:acr:passkey","exp":$exp}""").toByteArray()
        )
        val signature = Base64.getUrlEncoder().withoutPadding().encodeToString("sig".toByteArray())
        return AccessToken("$header.$body.$signature")
    }

    // ---- wallet instance lifecycle (SID-AUTH-06, go-wallet-backend#319) ----

    @Test
    fun generate_wia_sends_credential_id_when_given_and_omits_it_otherwise() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"wallet_instance_attestation":"wia.jwt"}"""))
        server.enqueue(MockResponse().setBody("""{"wallet_instance_attestation":"wia.jwt"}"""))
        val client = newClient()
        client.setAppToken("t")

        client.generateWIA(pop = "pop.jwt", challenge = "c-1", clientId = "siros://cb", credentialId = "pk-1")
        val withId = server.takeRequest().body.readUtf8()
        assertTrue(withId, withId.contains("\"credential_id\":\"pk-1\""))

        client.generateWIA(pop = "pop.jwt", challenge = "c-2")
        val without = server.takeRequest().body.readUtf8()
        assertTrue(without, !without.contains("credential_id"))
    }

    @Test
    fun list_wallet_instances_decodes_backend_shape() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """{"instances":[{"id":"jkt-1","tenant_id":"default","user_id":"u1","status":"suspended",
                   "wscd_type":"native_android","credential_id":"pk-1","attestation_source":"play_integrity",
                   "last_attested_at":"2026-09-08T10:00:00Z","status_reason":"lost phone","unknown_member":1}]}"""
            )
        )
        val client = newClient()
        client.setAppToken("t")

        val instances = client.listWalletInstances()

        assertEquals("/user/session/instances", server.takeRequest().path)
        assertEquals(1, instances.size)
        assertEquals("jkt-1", instances[0].id)
        assertEquals(WalletInstance.STATUS_SUSPENDED, instances[0].status)
        assertEquals("pk-1", instances[0].credentialId)
        assertEquals("lost phone", instances[0].statusReason)
    }

    @Test
    fun list_wallet_instances_fails_on_malformed_response() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"unexpected":true}"""))
        val client = newClient()
        client.setAppToken("t")
        try {
            client.listWalletInstances()
            fail("a response without the instances array must not read as 'no instances'")
        } catch (e: BackendApiException) {
            assertTrue(e.message!!.contains("instances"))
        }
    }

    // ---- Account deletion (SID-AUTH-06, go-wallet-backend#352) ----

    private val assertion = AuthenticateResult(
        credentialId = byteArrayOf(1, 2, 3),
        authenticatorData = byteArrayOf(4, 5),
        clientDataJSON = byteArrayOf(6),
        signature = byteArrayOf(7, 8),
        userHandle = byteArrayOf(9),
    )

    private fun b64(vararg bytes: Byte) = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    private suspend fun deleteWith(response: MockResponse): DeleteAccountOutcome {
        server.enqueue(response)
        val client = newClient().apply { setAppToken("tok") }
        return client.deleteAccount("ch-1", assertion, "DELETE")
    }

    private fun body(code: Int, json: String = "{}") = MockResponse().setResponseCode(code).setBody(json)

    @Test
    fun delete_begin_posts_and_decodes_the_assertion_options() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """{"challengeId":"ch-1","publicKey":{"rpId":"example.com","challenge":{"${'$'}b64u":"${b64(1, 2)}"},
                "allowCredentials":[{"type":"public-key","id":{"${'$'}b64u":"${b64(3)}"}}],"userVerification":"required"}}"""
            )
        )
        val client = newClient().apply { setAppToken("tok") }

        val challenge = (client.deleteAccountBegin() as DeleteAccountBegin.Ready).challenge

        val request = server.takeRequest()
        assertEquals("POST", request.method)
        assertEquals("/user/session/delete-begin", request.path)
        assertEquals("Bearer tok", request.getHeader("Authorization"))
        assertEquals("default", request.getHeader("X-Tenant-ID"))
        assertEquals("ch-1", challenge.challengeId)
        assertEquals("example.com", challenge.options.rpId)
        assertEquals(listOf<Byte>(1, 2), challenge.options.challenge.toList())
        assertEquals(listOf<Byte>(3), challenge.options.allowCredentials!!.single().id.toList())
        assertEquals("required", challenge.options.userVerification)
    }

    @Test
    fun delete_begin_rejects_a_response_without_a_challenge_id() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"publicKey":{"rpId":"x","challenge":"AQ"}}"""))
        val client = newClient().apply { setAppToken("tok") }
        try {
            client.deleteAccountBegin()
            fail("a begin response without challengeId must not be usable")
        } catch (e: BackendApiException) {
            assertTrue(e.message!!.contains("challengeId"))
        }
    }

    @Test
    fun delete_begin_maps_every_defined_refusal_without_throwing() = runBlocking {
        val client = newClient().apply { setAppToken("tok") }
        val cases = listOf(
            body(400, """{"error":"NO_PASSKEY","message":"none"}""") to DeleteAccountBegin.NoPasskey("none"),
            body(403, """{"error":"INSUFFICIENT_SCOPE"}""") to DeleteAccountBegin.Forbidden(null),
            body(401) to DeleteAccountBegin.SessionRevoked(null),
            body(404) to DeleteAccountBegin.NotFound(null),
        )
        for ((response, expected) in cases) {
            server.enqueue(response)
            assertEquals(expected, client.deleteAccountBegin())
        }
        server.enqueue(body(400, """{"error":"SOMETHING_ELSE"}"""))
        try {
            client.deleteAccountBegin()
            fail("an unrelated 400 must throw")
        } catch (e: BackendApiException) {
            assertEquals(400, e.code)
        }
    }

    @Test
    fun delete_sends_the_json_body_with_assertion_and_confirmation() = runBlocking {
        val outcome = deleteWith(body(200, """{"result":"DELETED"}"""))

        assertEquals(DeleteAccountOutcome.Deleted, outcome)
        val request = server.takeRequest()
        assertEquals("DELETE", request.method)
        assertEquals("/user/session", request.path)
        assertEquals("Bearer tok", request.getHeader("Authorization"))
        assertEquals("default", request.getHeader("X-Tenant-ID"))
        assertTrue(request.getHeader("Content-Type")!!.startsWith("application/json"))
        val sent = Json.parseToJsonElement(request.body.readUtf8()).jsonObject
        assertEquals("ch-1", sent["challengeId"]!!.jsonPrimitive.content)
        assertEquals("DELETE", sent["confirm"]!!.jsonPrimitive.content)
        val credential = sent["credential"]!!.jsonObject
        assertEquals(b64(1, 2, 3), credential["id"]!!.jsonPrimitive.content)
        assertEquals(b64(1, 2, 3), credential["rawId"]!!.jsonPrimitive.content)
        assertEquals("public-key", credential["type"]!!.jsonPrimitive.content)
        val response = credential["response"]!!.jsonObject
        assertEquals(b64(4, 5), response["authenticatorData"]!!.jsonPrimitive.content)
        assertEquals(b64(6), response["clientDataJSON"]!!.jsonPrimitive.content)
        assertEquals(b64(7, 8), response["signature"]!!.jsonPrimitive.content)
        assertEquals(b64(9), response["userHandle"]!!.jsonPrimitive.content)
    }

    @Test
    fun begin_then_delete_is_the_documented_sequence() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"challengeId":"ch-9","publicKey":{"rpId":"x","challenge":"AQ"}}"""))
        server.enqueue(body(200))
        val client = newClient().apply { setAppToken("tok") }

        val challenge = (client.deleteAccountBegin() as DeleteAccountBegin.Ready).challenge
        client.deleteAccount(challenge.challengeId, assertion, "DELETE")

        assertEquals("/user/session/delete-begin", server.takeRequest().path)
        val second = server.takeRequest()
        assertEquals("DELETE", second.method)
        assertTrue(second.body.readUtf8().contains("\"challengeId\":\"ch-9\""))
    }

    @Test
    fun delete_maps_202_cleanup_pending() = runBlocking {
        assertEquals(
            DeleteAccountOutcome.CleanupPending,
            deleteWith(body(202, """{"result":"DELETION_CLEANUP_PENDING"}""")),
        )
    }

    @Test
    fun delete_maps_202_operator_required() = runBlocking {
        assertEquals(
            DeleteAccountOutcome.OperatorRequired,
            deleteWith(body(202, """{"result":"DELETION_OPERATOR_REQUIRED"}""")),
        )
    }

    @Test
    fun delete_does_not_guess_an_unrecognised_202() = runBlocking {
        try {
            deleteWith(body(202, """{"result":"SOMETHING_NEW"}"""))
            fail("an unknown 202 must not read as a deletion")
        } catch (e: BackendApiException) {
            assertEquals(202, e.code)
        }
    }

    @Test
    fun delete_maps_409_to_retry_needed() = runBlocking {
        val outcome = deleteWith(body(409, """{"error":"DELETION_INCOMPLETE","message":"try again"}"""))
        assertEquals(DeleteAccountOutcome.RetryNeeded("try again"), outcome)
    }

    @Test
    fun delete_maps_step_up_required_and_failed() = runBlocking {
        assertEquals(
            DeleteAccountOutcome.StepUpRequired(null),
            deleteWith(body(401, """{"error":"STEP_UP_REQUIRED"}""")),
        )
        assertEquals(
            DeleteAccountOutcome.StepUpFailed("bad"),
            deleteWith(body(401, """{"error":"STEP_UP_FAILED","message":"bad"}""")),
        )
    }

    @Test
    fun delete_maps_410_to_step_up_expired() = runBlocking {
        assertEquals(
            DeleteAccountOutcome.StepUpExpired(null),
            deleteWith(body(410, """{"error":"STEP_UP_EXPIRED"}""")),
        )
    }

    @Test
    fun delete_maps_400_confirmation_required_but_not_other_400s() = runBlocking {
        assertEquals(
            DeleteAccountOutcome.ConfirmationRequired(null),
            deleteWith(body(400, """{"error":"CONFIRMATION_REQUIRED"}""")),
        )
        try {
            deleteWith(body(400, """{"error":"BAD_REQUEST"}"""))
            fail("an unrelated 400 must throw")
        } catch (e: BackendApiException) {
            assertEquals(400, e.code)
        }
    }

    @Test
    fun delete_maps_a_plain_401_to_session_revoked_and_404_to_not_found() = runBlocking {
        assertEquals(DeleteAccountOutcome.SessionRevoked(null), deleteWith(body(401, """{"error":"TOKEN_REVOKED"}""")))
        assertEquals(DeleteAccountOutcome.NotFound(null), deleteWith(body(404)))
    }

    @Test
    fun a_step_up_401_is_not_counted_as_a_rejected_bearer_token() = runBlocking {
        val tokens = mockk<AuthTokens>(relaxed = true)
        coEvery { tokens.ensureBackendToken() } returns mockk<AccessToken>(relaxed = true) { io.mockk.every { raw } returns "jwt" }
        val client = newClient().apply { setAuthTokens(tokens) }

        server.enqueue(body(401, """{"error":"STEP_UP_FAILED"}"""))
        client.deleteAccount("ch-1", assertion, "DELETE")
        verify(exactly = 0) { tokens.registerTokenRejection(any()) }

        server.enqueue(body(401, """{"error":"TOKEN_REVOKED"}"""))
        client.deleteAccount("ch-1", assertion, "DELETE")
        verify(exactly = 1) { tokens.registerTokenRejection(AuthTokens.TOKEN_BACKEND) }
    }

    /** Every status the contract defines comes back as a value; none throws. */
    @Test
    fun no_expected_outcome_throws() = runBlocking {
        val expected = listOf(
            body(200),
            body(202, """{"result":"DELETION_CLEANUP_PENDING"}"""),
            body(202, """{"result":"DELETION_OPERATOR_REQUIRED"}"""),
            body(409, """{"error":"DELETION_INCOMPLETE"}"""),
            body(401, """{"error":"STEP_UP_REQUIRED"}"""),
            body(401, """{"error":"STEP_UP_FAILED"}"""),
            body(401, """{"error":"TOKEN_REVOKED"}"""),
            body(410, """{"error":"STEP_UP_EXPIRED"}"""),
            body(400, """{"error":"CONFIRMATION_REQUIRED"}"""),
            body(404, """{"error":"NOT_FOUND"}"""),
            body(401, "not json"),
        )
        for (response in expected) {
            deleteWith(response) // throws -> test fails
        }
        assertEquals(expected.size, server.requestCount)
    }

    @Test
    fun an_unexpected_status_throws() = runBlocking {
        try {
            deleteWith(body(500))
            fail("a 500 is not a defined outcome")
        } catch (e: BackendApiException) {
            assertEquals(500, e.code)
        }
    }

    // ---- Adding a passkey (go-wallet-backend#453) ----

    private val created = RegisterResult(
        credentialId = byteArrayOf(5, 6),
        attestationObject = byteArrayOf(7),
        clientDataJSON = byteArrayOf(8),
    )

    private fun beginBody(authorization: String = "") = """{"username":"alice","challengeId":"enr-1","createOptions":{"publicKey":{
        "rp":{"id":"example.com","name":"Example"},"user":{"id":{"${'$'}b64u":"${b64(1)}"},"name":"alice","displayName":"Alice"},
        "challenge":{"${'$'}b64u":"${b64(2, 3)}"},"authenticatorSelection":{"residentKey":"required","userVerification":"preferred"}}}$authorization}"""

    private suspend fun finishWith(response: MockResponse, authorization: AuthenticateResult? = assertion): AddPasskeyOutcome {
        server.enqueue(response)
        val client = newClient().apply { setAppToken("tok") }
        return client.passkeyRegisterFinish("enr-1", created, "Phone", byteArrayOf(1, 2), authorization, ifMatch = null)
    }

    @Test
    fun passkey_begin_decodes_create_and_authorization_options() = runBlocking {
        val authorization = ""","authorization":{"publicKey":{"rpId":"example.com","challenge":{"${'$'}b64u":"${b64(9)}"},
            "allowCredentials":[{"type":"public-key","id":{"${'$'}b64u":"${b64(4)}"}}],"userVerification":"required"}}"""
        server.enqueue(MockResponse().setBody(beginBody(authorization)))
        val client = newClient().apply { setAppToken("tok") }

        val challenge = (client.passkeyRegisterBegin() as AddPasskeyBegin.Ready).challenge

        val request = server.takeRequest()
        assertEquals("POST", request.method)
        assertEquals("/user/session/webauthn/register-begin", request.path)
        assertEquals("enr-1", challenge.challengeId)
        assertEquals("example.com", challenge.createOptions.rpId)
        assertEquals("Alice", challenge.createOptions.userDisplayName)
        assertEquals(listOf<Byte>(2, 3), challenge.createOptions.challenge.toList())
        assertEquals(listOf<Byte>(1), challenge.createOptions.userId.toList())
        val auth = challenge.authorization!!
        assertEquals(listOf<Byte>(9), auth.challenge.toList())
        assertEquals(listOf<Byte>(4), auth.allowCredentials!!.single().id.toList())
        assertEquals("required", auth.userVerification)
    }

    @Test
    fun passkey_begin_has_no_authorization_for_an_account_without_a_passkey() = runBlocking {
        server.enqueue(MockResponse().setBody(beginBody()))
        val client = newClient().apply { setAppToken("tok") }
        assertEquals(null, (client.passkeyRegisterBegin() as AddPasskeyBegin.Ready).challenge.authorization)
    }

    @Test
    fun passkey_begin_maps_refusals() = runBlocking {
        server.enqueue(body(403, """{"message":"no scope"}"""))
        server.enqueue(body(401, """{"message":"gone"}"""))
        val client = newClient().apply { setAppToken("tok") }
        assertEquals(AddPasskeyBegin.Forbidden("no scope"), client.passkeyRegisterBegin())
        assertEquals(AddPasskeyBegin.SessionRevoked("gone"), client.passkeyRegisterBegin())
    }

    @Test
    fun passkey_finish_sends_credential_authorization_private_data_and_if_match() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"credentialId":"cred-9"}""").setHeader("X-Private-Data-ETag", "\"new\""))
        val client = newClient().apply { setAppToken("tok") }

        val outcome = client.passkeyRegisterFinish("enr-1", created, "Phone", byteArrayOf(1, 2), assertion, ifMatch = "\"old\"")

        assertEquals(AddPasskeyOutcome.Added("cred-9"), outcome)
        assertEquals("\"new\"", client.privateDataEtag)
        val request = server.takeRequest()
        assertEquals("/user/session/webauthn/register-finish", request.path)
        assertEquals("\"old\"", request.getHeader("X-Private-Data-If-Match"))
        val sent = Json.parseToJsonElement(request.body.readUtf8()).jsonObject
        assertEquals("enr-1", sent["challengeId"]!!.jsonPrimitive.content)
        assertEquals("Phone", sent["nickname"]!!.jsonPrimitive.content)
        assertEquals(b64(5, 6), sent["credential"]!!.jsonObject["id"]!!.jsonPrimitive.content)
        assertEquals(b64(7), sent["credential"]!!.jsonObject["response"]!!.jsonObject["attestationObject"]!!.jsonPrimitive.content)
        assertEquals(b64(1, 2), sent["privateData"]!!.jsonObject["${'$'}b64u"]!!.jsonPrimitive.content)
        assertEquals(b64(7, 8), sent["authorization"]!!.jsonObject["response"]!!.jsonObject["signature"]!!.jsonPrimitive.content)
    }

    @Test
    fun passkey_finish_omits_authorization_when_there_is_none() = runBlocking {
        finishWith(MockResponse().setBody("{}"), authorization = null)
        val sent = Json.parseToJsonElement(server.takeRequest().body.readUtf8()).jsonObject
        assertTrue("authorization" !in sent)
    }

    @Test
    fun passkey_finish_defaults_if_match_to_the_last_seen_etag() = runBlocking {
        server.enqueue(MockResponse().setBody("{}").setHeader("X-Private-Data-ETag", "\"seen\""))
        server.enqueue(MockResponse().setBody("{}"))
        val client = newClient().apply { setAppToken("tok") }
        client.getPrivateData()
        client.passkeyRegisterFinish("enr-1", created, "Phone", null, null)
        server.takeRequest()
        assertEquals("\"seen\"", server.takeRequest().getHeader("X-Private-Data-If-Match"))
    }

    @Test
    fun passkey_finish_maps_every_defined_outcome() = runBlocking {
        assertEquals(
            AddPasskeyOutcome.AuthorizationRequired("m"),
            finishWith(body(401, """{"error":"ENROLLMENT_AUTHORIZATION_REQUIRED","message":"m"}""")),
        )
        assertEquals(
            AddPasskeyOutcome.AuthorizationFailed("m"),
            finishWith(body(401, """{"error":"ENROLLMENT_AUTHORIZATION_FAILED","message":"m"}""")),
        )
        assertEquals(AddPasskeyOutcome.SessionRevoked(null), finishWith(body(401)))
        assertEquals(AddPasskeyOutcome.RetryNeeded(null), finishWith(body(404)))
        assertEquals(
            AddPasskeyOutcome.PrivateDataConflict("\"cur\""),
            finishWith(MockResponse().setResponseCode(412).setHeader("X-Private-Data-ETag", "\"cur\"")),
        )
        assertEquals(
            AddPasskeyOutcome.RegistrationRejected(400, "Registration response could not be verified"),
            finishWith(body(400, """{"error":"Registration response could not be verified"}""")),
        )
        assertEquals(AddPasskeyOutcome.RegistrationRejected(403, "Authenticator not allowed"), finishWith(body(403, """{"error":"Authenticator not allowed"}""")))
    }

    @Test
    fun passkey_finish_412_does_not_adopt_the_remote_etag() = runBlocking {
        // This device's cache is at "mine"; another device has since written
        // "newer", which the 412 response reports back.
        server.enqueue(MockResponse().setBody("{}").setHeader("X-Private-Data-ETag", "\"mine\""))
        server.enqueue(MockResponse().setResponseCode(412).setHeader("X-Private-Data-ETag", "\"newer-from-another-device\""))
        val client = newClient().apply { setAppToken("tok") }
        client.getPrivateData()
        assertEquals("\"mine\"", client.privateDataEtag)

        val outcome = client.passkeyRegisterFinish("enr-1", created, "Phone", byteArrayOf(1, 2), assertion, ifMatch = "\"mine\"")

        assertEquals(AddPasskeyOutcome.PrivateDataConflict("\"newer-from-another-device\""), outcome)
        // The cached ETag must NOT move to the server's newer value: this
        // device's cached container was never updated to match it, so a
        // later retry using the adopted ETag as If-Match would submit stale
        // data tagged as current, silently overwriting the other device's
        // write. The remote value is only ever surfaced via the conflict
        // result above, for the caller to fetch-and-reconcile explicitly.
        assertEquals("\"mine\"", client.privateDataEtag)
    }

    @Test
    fun passkey_finish_throws_on_an_unexpected_status() = runBlocking {
        try {
            finishWith(body(500))
            fail("a 500 is not a defined outcome")
        } catch (e: BackendApiException) {
            assertEquals(500, e.code)
        }
    }

    private fun newClient(): BackendApiClient {
        val baseUrl = server.url("/").toString().trimEnd('/')
        return BackendApiClient(baseUrl = baseUrl, tenantId = "default")
    }
}
