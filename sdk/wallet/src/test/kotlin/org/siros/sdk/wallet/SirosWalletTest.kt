package org.siros.sdk.wallet

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.runs
import io.mockk.slot
import io.mockk.verify
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlin.reflect.full.callSuspend
import kotlin.reflect.full.declaredMemberFunctions
import kotlin.reflect.jvm.isAccessible
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.siros.sdk.auth.BackendApiClient
import org.siros.sdk.credentials.CredentialConsumptionPolicy
import org.siros.sdk.credentials.CredentialMetadata
import org.siros.sdk.credentials.CredentialStore
import org.siros.sdk.credentials.PresentationRecord
import org.siros.sdk.credentials.SignerSecurityProperties
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.credentials.WalletException
import org.siros.sdk.keystore.AttestationChain
import org.siros.sdk.keystore.KeypairInfo
import org.siros.sdk.keystore.KeystoreManager
import org.siros.sdk.keystore.NativeAttestationEvidence
import org.siros.sdk.keystore.NativeAttestationProvider
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.siros.sdk.transport.engine.CredentialNotificationEvent
import org.siros.sdk.transport.engine.CredentialResult
import org.siros.sdk.transport.engine.CredentialMatch
import org.siros.sdk.transport.engine.FlowCompleteMessage
import org.siros.sdk.transport.engine.FlowError
import org.siros.sdk.transport.engine.FlowErrorMessage
import org.siros.sdk.transport.engine.FlowProgressMessage
import org.siros.sdk.transport.engine.MatchRequestMessage
import org.siros.sdk.transport.engine.ProofObject
import org.siros.sdk.transport.engine.SignRequestMessage
import org.siros.sdk.transport.engine.SignRequestParams
import org.siros.sdk.transport.engine.WalletEngineSession

@OptIn(ExperimentalCoroutinesApi::class)
class SirosWalletTest {

    private val dispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(dispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        SirosWallet.createEngineSession = { baseUrl, tenantId -> WalletEngineSession(baseUrl, tenantId) }
    }

    @Test
    fun logout_disconnects_clears_and_sets_disconnected_state() {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val keystore = mockk<KeystoreManager>(relaxed = true)
        val sessionStore = mockk<SessionStore>(relaxed = true)
        val accountRegistry = mockk<AccountRegistry>(relaxed = true)
        every { accountRegistry.listLoginableAccounts() } returns emptyList()
        val scope = CoroutineScope(Dispatchers.Unconfined + SupervisorJob())
        val stateFlow = MutableStateFlow<WalletState>(
            WalletState.Ready(userId = "user-1", displayName = "Alice")
        )
        val wallet = newWallet(
            "_state" to stateFlow,
            "engineSession" to engine,
            "keystore" to keystore,
            "sessionStore" to sessionStore,
            "accountRegistry" to accountRegistry,
            "scope" to scope,
            "apiClient" to mockk<BackendApiClient>(relaxed = true),
        )

        wallet.logout()

        verify(exactly = 1) { engine.disconnect() }
        verify(exactly = 1) { keystore.lock() }
        verify(exactly = 1) { sessionStore.clear() }
        assertEquals(WalletState.Disconnected(), wallet.state.value)
    }

    @Test
    fun completeAuthorization_sends_authorization_complete_action() {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "engineSession" to engine,
            "pendingAuthorizations" to mutableMapOf<String, Any?>(),
        )

        wallet.completeAuthorization(flowId = "flow-123", code = "code-abc", state = "state-xyz")

        verify(exactly = 1) {
            engine.sendFlowAction(
                "flow-123",
                "authorization_complete",
                match {
                    it.toString().contains("\"code\":\"code-abc\"") &&
                        it.toString().contains("\"state\":\"state-xyz\"")
                }
            )
        }
    }

    @Test
    fun getIssuers_accepts_plain_array_and_filters_hidden_entries() = runBlocking {
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.getIssuers() } returns JsonArray(
            listOf(
                buildJsonObject {
                    put("id", 1)
                    put("credentialIssuerIdentifier", "https://issuer-1.example.com")
                    put("visible", true)
                },
                buildJsonObject {
                    put("id", 2)
                    put("credentialIssuerIdentifier", "https://issuer-2.example.com")
                    put("visible", false)
                },
            )
        )
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "apiClient" to apiClient,
            "json" to Json { ignoreUnknownKeys = true },
        )

        val issuers = wallet.getIssuers()

        assertEquals(1, issuers.size)
        assertEquals(1L, issuers.first().id)
        assertEquals("https://issuer-1.example.com", issuers.first().credentialIssuerIdentifier)
    }

    @Test
    fun getAvailableCredentials_uses_backend_metadata_proxy_and_merges_display_fields() = runBlocking {
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.getIssuers() } returns JsonArray(
            listOf(
                buildJsonObject {
                    put("id", 7)
                    put("credentialIssuerIdentifier", "https://issuer-1.example.com")
                    put("visible", true)
                }
            )
        )
        coEvery { apiClient.getIssuerMetadata(7) } returns buildJsonObject {
            put("credential_issuer", "https://issuer-1.example.com")
            putJsonArray("display") {
                add(buildJsonObject {
                    put("name", "Issuer One")
                    put("background_color", "#102030")
                    put("text_color", "#f0f4f8")
                    putJsonObject("logo") {
                        put("uri", "https://issuer-1.example.com/logo.png")
                    }
                })
            }
            putJsonObject("credential_configurations_supported") {
                putJsonObject("pid") {
                    put("format", "dc+sd-jwt")
                    putJsonObject("credential_metadata") {
                        putJsonArray("display") {
                            add(buildJsonObject {
                                put("name", "Personal ID")
                                put("description", "Government issued PID")
                                put("background_color", "#223344")
                                put("text_color", "#ffffff")
                                putJsonObject("logo") {
                                    put("uri", "https://issuer-1.example.com/pid.png")
                                }
                            })
                        }
                    }
                }
            }
        }
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "apiClient" to apiClient,
            "json" to Json { ignoreUnknownKeys = true },
        )

        val offers = wallet.getAvailableCredentials()

        coVerify(exactly = 1) { apiClient.getIssuerMetadata(7) }
        assertEquals(1, offers.size)
        assertEquals("pid", offers.single().credentialConfigurationId)
        assertEquals("Personal ID", offers.single().credentialName)
        assertEquals("Issuer One", offers.single().issuerName)
        assertEquals("#223344", offers.single().backgroundColor)
        assertEquals("#ffffff", offers.single().textColor)
        assertEquals("https://issuer-1.example.com/pid.png", offers.single().logoUri)
        assertEquals("https://issuer-1.example.com/logo.png", offers.single().issuerLogoUri)
    }

    @Test
    fun deleteCredential_updates_ready_state_without_backend_sync_when_keystore_locked() = runBlocking {
        val remainingCredential = StoredCredential(
            id = 2L,
            format = "dc+sd-jwt",
            raw = "raw-2",
            metadata = CredentialMetadata(name = "Credential Two"),
            batchId = 2L,
            instanceId = 0,
        )
        val store = FakeCredentialStore(
            mutableListOf(
                StoredCredential(id = 1L, format = "dc+sd-jwt", raw = "raw-1", batchId = 1L, instanceId = 0),
                remainingCredential,
            )
        )
        val keystore = mockk<KeystoreManager>()
        every { keystore.isUnlocked } returns false
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.Ready(
                    userId = "user-1",
                    displayName = "Alice",
                    credentials = store.getAll(),
                )
            ),
            "credentialStore" to store,
            "keystore" to keystore,
        )

        wallet.deleteCredential(1L)

        val state = wallet.state.value as WalletState.Ready
        assertEquals(listOf(2L), state.credentials.map { it.id })
    }

    @Test
    fun deleteCredential_syncs_private_data_when_keystore_unlocked() = runBlocking {
        val store = FakeCredentialStore(mutableListOf())
        val keystore = mockk<KeystoreManager>()
        val sessionStore = mockk<SessionStore>(relaxed = true)
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        var privateDataJwe: String? = null
        val containerJson = """{"prfKeys":[],"jwe":"test-jwe"}"""
        every { keystore.isUnlocked } returns true
        every { sessionStore.privateDataJwe } answers { privateDataJwe }
        every { sessionStore.privateDataJwe = any() } answers { privateDataJwe = firstArg() }
        coEvery { keystore.exportEncryptedContainer() } returns containerJson.toByteArray()
        coEvery { apiClient.updatePrivateData(any()) } returns buildJsonObject {}
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.Ready(userId = "user-1", displayName = "Alice")
            ),
            "credentialStore" to store,
            "keystore" to keystore,
            "sessionStore" to sessionStore,
            "apiClient" to apiClient,
        )

        wallet.deleteCredential(999L)

        coVerify(exactly = 1) { keystore.exportEncryptedContainer() }
        verify(exactly = 1) { sessionStore.privateDataJwe = containerJson }
        coVerify(exactly = 1) {
            apiClient.updatePrivateData(match { it["jwe"]?.jsonPrimitive?.content == "test-jwe" })
        }
    }

    @Test
    fun handleTrustEvaluation_rejects_missing_subject_id_without_backend_call() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val apiClient = mockk<BackendApiClient>()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
        )

        invokeHandleTrustEvaluation(
            wallet,
            engine,
            "flow-1",
            buildJsonObject {
                putJsonObject("request") {
                    put("subject_type", "credential_issuer")
                }
            }
        )
        advanceUntilIdle()

        coVerify(exactly = 0) { apiClient.evaluateTrust(any()) }
        verify(exactly = 1) { engine.sendTrustResult("flow-1", false, "Missing subject_id") }
    }

    @Test
    fun handleTrustEvaluation_builds_authzen_request_and_returns_backend_decision() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } returns buildJsonObject {
            put("decision", true)
        }
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "lastTrustResults" to mutableMapOf<String, TrustResult>(),
            "trustCache" to TrustCache(),
        )

        invokeHandleTrustEvaluation(
            wallet,
            engine,
            "flow-2",
            buildJsonObject {
                putJsonObject("request") {
                    put("subject_id", "verifier-123")
                    put("subject_type", "credential_verifier")
                    putJsonObject("key_material") {
                        put("type", "jwk")
                        putJsonObject("jwk") {
                            put("kty", "EC")
                            put("crv", "P-256")
                            put("x", "abc")
                            put("y", "def")
                        }
                    }
                    putJsonObject("context") {
                        put("policy", "strict")
                    }
                }
            }
        )
        advanceUntilIdle()

        coVerify(exactly = 1) {
            apiClient.evaluateTrust(match { request ->
                request["subject"]?.toString() == "{\"type\":\"key\",\"id\":\"verifier-123\"}" &&
                    request["action"]?.toString() == "{\"name\":\"credential-verifier\"}" &&
                    request["context"]?.toString() == "{\"policy\":\"strict\"}" &&
                    request["resource"]?.toString()?.contains("\"type\":\"jwk\"") == true &&
                    request["resource"]?.toString()?.contains("\"key\":[{") == true &&
                    request["resource"]?.toString()?.contains("\"kty\":\"EC\"") == true
            })
        }
        verify(exactly = 1) { engine.sendTrustResult("flow-2", true, null) }
    }

    @Test
    fun handleTrustEvaluation_returns_failure_reason_when_backend_throws() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } throws IllegalStateException("trust backend offline")
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "lastTrustResults" to mutableMapOf<String, TrustResult>(),
            "trustCache" to TrustCache(),
        )

        invokeHandleTrustEvaluation(
            wallet,
            engine,
            "flow-3",
            buildJsonObject {
                putJsonObject("request") {
                    put("subject_id", "issuer-456")
                    put("subject_type", "credential_issuer")
                    putJsonObject("key_material") {
                        put("type", "x5c")
                        putJsonArray("x5c") {
                            add(JsonPrimitive("cert-1"))
                        }
                    }
                }
            }
        )
        advanceUntilIdle()

        verify(exactly = 1) { engine.sendTrustResult("flow-3", false, "trust backend offline") }
    }

    @Test
    fun connectEngine_forwards_authorization_required_and_transitions_to_flow_active() = runTest(dispatcher) {
        val progressFlow = MutableSharedFlow<FlowProgressMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val store = FakeCredentialStore(mutableListOf())
        val engine = mockEngineConstructor(progressFlow = progressFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.Ready(userId = "user-1", displayName = "Alice")
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                tenantId = "tenant-1",
                redirectUri = "siros://callback",
            ),
            "credentialStore" to store,
            "eventListener" to listener,
            "pendingAuthorizations" to mutableMapOf<String, Any?>(),
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        progressFlow.emit(
            FlowProgressMessage(
                flowId = "flow-auth",
                step = "authorization_required",
                payload = buildJsonObject {
                    put("authorization_url", "https://issuer.example.com/auth?state=state-from-url")
                    put("expected_redirect_uri", "siros://callback")
                    put("state", "state-from-url")
                },
            )
        )
        advanceUntilIdle()

        verify(exactly = 1) {
            listener.onAuthorizationRequired(
                "flow-auth",
                "https://issuer.example.com/auth?state=state-from-url",
                "siros://callback",
                "state-from-url",
            )
        }
        verify(exactly = 1) { engine.connect("app-token", any()) }
        assertEquals(
            WalletState.FlowActive(
                userId = "user-1",
                displayName = "Alice",
                flowId = "flow-auth",
                flowType = "authorization_required",
                status = "authorization_required",
                credentials = emptyList(),
            ),
            wallet.state.value,
        )
    }

    @Test
    fun connectEngine_reauth_required_state_notifies_listener_and_logs_out() = runTest(dispatcher) {
        // The engineStateJob started by connectEngine() is the only currently-wired
        // path to WalletEngineSession.State.REAUTH_REQUIRED (e.g. the background
        // reconnect loop's token refresh being rejected) - this locks in that the
        // host app is notified and the SDK's own session state is put back in sync.
        val listener = mockk<WalletEventListener>(relaxed = true)
        val keystore = mockk<KeystoreManager>(relaxed = true)
        val sessionStore = mockk<SessionStore>(relaxed = true)
        val accountRegistry = mockk<AccountRegistry>(relaxed = true)
        every { accountRegistry.listLoginableAccounts() } returns emptyList()
        val engineState = MutableStateFlow(WalletEngineSession.State.CONNECTED)
        val engine = mockEngineConstructor()
        every { engine.state } returns engineState
        every { engine.disconnect() } just runs
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.Ready(userId = "user-1", displayName = "Alice")
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                tenantId = "tenant-1",
                redirectUri = "siros://callback",
            ),
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "eventListener" to listener,
            "keystore" to keystore,
            "sessionStore" to sessionStore,
            "accountRegistry" to accountRegistry,
            "pendingAuthorizations" to mutableMapOf<String, Any?>(),
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()

        engineState.value = WalletEngineSession.State.REAUTH_REQUIRED
        advanceUntilIdle()

        verify(exactly = 1) { listener.onReauthenticationRequired() }
        verify(exactly = 1) { engine.disconnect() }
        verify(exactly = 1) { keystore.lock() }
        assertEquals(WalletState.Disconnected(), wallet.state.value)
    }

    @Test
    fun completeAuthorization_resumes_via_stateless_flow_start_using_saved_context() = runTest(dispatcher) {
        // The WebSocket session that started the flow is very often already gone by the
        // time the browser redirects back (Android backgrounds/throttles the app for the
        // OAuth login) - completeAuthorization must resume on a fresh flow_start using the
        // code_verifier/credential_offer saved from the original authorization_required
        // message, not a flow_action on the (likely dead) original flow_id.
        val progressFlow = MutableSharedFlow<FlowProgressMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val store = FakeCredentialStore(mutableListOf())
        val engine = mockEngineConstructor(progressFlow = progressFlow)
        every { engine.resumeIssuance(any(), any(), any(), any(), any()) } just runs
        coEvery { engine.awaitConnected(any()) } just runs
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.Ready(userId = "user-1", displayName = "Alice")
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                tenantId = "tenant-1",
                redirectUri = "siros://callback",
            ),
            "credentialStore" to store,
            "eventListener" to listener,
            "pendingAuthorizations" to mutableMapOf<String, Any?>(),
            "json" to Json { ignoreUnknownKeys = true },
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        progressFlow.emit(
            FlowProgressMessage(
                flowId = "flow-auth",
                step = "authorization_required",
                payload = buildJsonObject {
                    put("authorization_url", "https://issuer.example.com/auth?state=state-from-url")
                    put("expected_redirect_uri", "siros://callback")
                    put("state", "state-from-url")
                    put("code_verifier", "verifier-abc")
                    putJsonObject("credential_offer") {
                        put("credential_issuer", "https://issuer.example.com")
                    }
                },
            )
        )
        advanceUntilIdle()

        wallet.completeAuthorization(flowId = "flow-auth", code = "auth-code-xyz", state = "state-from-url")
        advanceUntilIdle()

        coVerify(exactly = 1) { engine.forceReconnect() }
        verify(exactly = 1) {
            engine.resumeIssuance(
                offer = match { it != null && it.contains("\"credential_issuer\":\"https://issuer.example.com\"") },
                credentialOfferUri = null,
                redirectUri = "siros://callback",
                authCode = "auth-code-xyz",
                codeVerifier = "verifier-abc",
            )
        }
        verify(exactly = 0) { engine.sendFlowAction("flow-auth", "authorization_complete", any()) }
    }

    /**
     * The token request only ever happens via this resume-after-redirect path
     * for redirect-based authorization_code issuers - go-wallet-backend's
     * Execute() sets up its attestation provider identically whether
     * msg.AuthCode is set or not, so completeAuthorization must resolve and
     * attach client attestation just like startIssuance does. Confirmed
     * missing via a real geneva2026.mdoc.online conformance run ("No OAuth
     * Client Attestations were provided" on the token request specifically).
     */
    @Test
    fun completeAuthorization_attachesClientAttestation_whenBackendSupportsWia() = runTest(dispatcher) {
        val server = MockWebServer()
        server.start()
        try {
            // resolveClientAttestation's own getIssuerMetadata call (no
            // authorization_servers field, so asUrl falls back to issuerUrl),
            // then two 404s for fetchAttestationChallenge's well-known-path
            // probing (this issuer doesn't publish a challenge_endpoint -
            // that mechanism is covered by its own dedicated test above).
            server.enqueue(MockResponse().setBody(issuerMetadataJson(server, "org.iso.18013.5.1.mDL")))
            server.enqueue(MockResponse().setResponseCode(404))
            server.enqueue(MockResponse().setResponseCode(404))

            val progressFlow = MutableSharedFlow<FlowProgressMessage>()
            val listener = mockk<WalletEventListener>(relaxed = true)
            val store = FakeCredentialStore(mutableListOf())
            val engine = mockEngineConstructor(progressFlow = progressFlow)
            every { engine.resumeIssuance(any(), any(), any(), any(), any(), any(), any()) } just runs
            coEvery { engine.awaitConnected(any()) } just runs

            val sessionStore = mockk<SessionStore>(relaxed = true)
            every { sessionStore.instanceKeyId } returns "instance-key-1"
            val keystore = mockk<KeystoreManager>(relaxed = true)
            coEvery {
                keystore.generateKeyProof(keyId = any(), typ = any(), issuer = any(), audience = "https://wallet.example.com", extraClaims = any())
            } returns "wia-pop-jwt"
            coEvery {
                keystore.generateKeyProof(keyId = any(), typ = any(), issuer = any(), audience = server.url("/").toString().trimEnd('/'), extraClaims = any())
            } returns "resume-pop-jwt"
            val apiClient = mockk<BackendApiClient>(relaxed = true)
            coEvery { apiClient.requestWIAChallenge() } returns buildJsonObject { put("challenge", "chal-1") }
            val wiaJwt = fakeJwtWithExp(System.currentTimeMillis() / 1000 + 3600)
            coEvery { apiClient.generateWIA(pop = any(), challenge = "chal-1", clientId = any()) } returns wiaJwt

            val issuerUrl = server.url("/").toString().trimEnd('/')
            val wallet = newWallet(
                "_state" to MutableStateFlow<WalletState>(
                    WalletState.Ready(userId = "user-1", displayName = "Alice")
                ),
                "scope" to CoroutineScope(dispatcher + SupervisorJob()),
                "config" to WalletConfig(
                    backendUrl = "https://wallet.example.com",
                    tenantId = "tenant-1",
                    redirectUri = "siros://callback",
                ),
                "credentialStore" to store,
                "eventListener" to listener,
                "pendingAuthorizations" to mutableMapOf<String, Any?>(),
                "sessionStore" to sessionStore,
                "keystore" to keystore,
                "apiClient" to apiClient,
                "json" to Json { ignoreUnknownKeys = true },
                "httpClient" to OkHttpClient(),
            )

            invokeConnectEngine(wallet, "app-token")
            advanceUntilIdle()
            progressFlow.emit(
                FlowProgressMessage(
                    flowId = "flow-auth",
                    step = "authorization_required",
                    payload = buildJsonObject {
                        put("authorization_url", "$issuerUrl/auth?state=state-from-url")
                        put("expected_redirect_uri", "siros://callback")
                        put("state", "state-from-url")
                        put("code_verifier", "verifier-abc")
                        putJsonObject("credential_offer") {
                            put("credential_issuer", issuerUrl)
                        }
                    },
                )
            )
            advanceUntilIdle()

            wallet.completeAuthorization(flowId = "flow-auth", code = "auth-code-xyz", state = "state-from-url")
            // completeAuthorization's coroutine hops onto the real
            // Dispatchers.IO for each MockWebServer HTTP call
            // (getIssuerMetadata, then fetchOAuthServerMetadata's two
            // well-known-path attempts) - genuine OS-thread work the virtual
            // test dispatcher's advanceUntilIdle() alone doesn't wait for,
            // and each hop-and-return needs its own real-time gap before the
            // next advanceUntilIdle() can drain the resumed continuation.
            repeat(10) {
                runBlocking(Dispatchers.Default) { kotlinx.coroutines.delay(100) }
                advanceUntilIdle()
            }

            coVerify(exactly = 1) {
                apiClient.generateWIA(pop = any(), challenge = "chal-1", clientId = "siros://callback")
            }
            verify(exactly = 1) {
                engine.resumeIssuance(
                    offer = match { it != null && it.contains("\"credential_issuer\":\"$issuerUrl\"") },
                    credentialOfferUri = null,
                    redirectUri = "siros://callback",
                    authCode = "auth-code-xyz",
                    codeVerifier = "verifier-abc",
                    clientAttestation = wiaJwt,
                    clientAttestationPoP = "resume-pop-jwt",
                )
            }
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun completeAuthorization_surfaces_error_via_onFlowError_when_reconnect_fails() = runTest(dispatcher) {
        // If forcing a fresh connection fails outright, the failure must be visible to
        // the app immediately (onFlowError) rather than leaving it stuck showing
        // whatever UI state was current when completeAuthorization was called.
        val progressFlow = MutableSharedFlow<FlowProgressMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val store = FakeCredentialStore(mutableListOf())
        val engine = mockEngineConstructor(progressFlow = progressFlow)
        coEvery { engine.forceReconnect() } throws IllegalStateException("Engine WebSocket connection failed")
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.Ready(userId = "user-1", displayName = "Alice")
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                tenantId = "tenant-1",
                redirectUri = "siros://callback",
            ),
            "credentialStore" to store,
            "eventListener" to listener,
            "pendingAuthorizations" to mutableMapOf<String, Any?>(),
            "json" to Json { ignoreUnknownKeys = true },
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        progressFlow.emit(
            FlowProgressMessage(
                flowId = "flow-auth",
                step = "authorization_required",
                payload = buildJsonObject {
                    put("authorization_url", "https://issuer.example.com/auth?state=state-from-url")
                    put("expected_redirect_uri", "siros://callback")
                    put("state", "state-from-url")
                },
            )
        )
        advanceUntilIdle()

        wallet.completeAuthorization(flowId = "flow-auth", code = "auth-code-xyz", state = "state-from-url")
        advanceUntilIdle()

        verify(exactly = 1) { listener.onFlowError("flow-auth", any()) }
        verify(exactly = 0) { engine.resumeIssuance(any(), any(), any(), any(), any()) }
    }

    @Test
    fun completeAuthorization_throws_on_state_mismatch_instead_of_resuming() = runTest(dispatcher) {
        val progressFlow = MutableSharedFlow<FlowProgressMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val store = FakeCredentialStore(mutableListOf())
        val engine = mockEngineConstructor(progressFlow = progressFlow)
        every { engine.resumeIssuance(any(), any(), any(), any(), any()) } just runs
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.Ready(userId = "user-1", displayName = "Alice")
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                tenantId = "tenant-1",
                redirectUri = "siros://callback",
            ),
            "credentialStore" to store,
            "eventListener" to listener,
            "pendingAuthorizations" to mutableMapOf<String, Any?>(),
            "json" to Json { ignoreUnknownKeys = true },
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        progressFlow.emit(
            FlowProgressMessage(
                flowId = "flow-auth",
                step = "authorization_required",
                payload = buildJsonObject {
                    put("authorization_url", "https://issuer.example.com/auth?state=state-from-url")
                    put("expected_redirect_uri", "siros://callback")
                    put("state", "state-from-url")
                },
            )
        )
        advanceUntilIdle()

        var thrown: Throwable? = null
        try {
            wallet.completeAuthorization(flowId = "flow-auth", code = "auth-code-xyz", state = "wrong-state")
        } catch (e: Throwable) {
            thrown = e
        }
        assertTrue(thrown is WalletException)
        verify(exactly = 0) { engine.resumeIssuance(any(), any(), any(), any(), any()) }
    }

    @Test
    fun startIssuanceByOffer_passes_redirect_uri_to_engine() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "engineSession" to engine,
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                tenantId = "tenant-42",
                redirectUri = "siros-sample://callback",
            ),
        )

        wallet.startIssuanceByOffer(
            org.siros.sdk.credentials.CredentialOffer(
                credentialConfigurationId = "pid",
                credentialIssuerIdentifier = "https://issuer.example.com",
                credentialName = "Personal ID",
                issuerName = "Issuer",
            )
        )

        verify(exactly = 1) {
            engine.startIssuance(
                offer = match { offer ->
                    offer.contains("\"credential_issuer\":\"https://issuer.example.com\"") &&
                        offer.contains("\"credential_configuration_ids\":[\"pid\"]")
                },
                credentialOfferUri = null,
                redirectUri = "siros-sample://callback",
            )
        }
    }

    /**
     * go-wallet-backend's credential-type registry service (TS11-backed,
     * carries `attestation_los`/`Vctm.requiredKeyStorage`) was never queried
     * by this SDK at all - only issuer-direct strategies existed. Confirms
     * [WalletConfig.registryUrl]'s zero-config default (derived from
     * [WalletConfig.backendUrl] as `<backendUrl>/registry`) actually reaches
     * [VctmFetcher.fetch] via [SirosWallet.startIssuanceByOffer].
     */
    @Test
    fun startIssuanceByOffer_passesDerivedRegistryUrl_toVctmFetcher() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val vctmFetcher = mockk<org.siros.sdk.credentials.VctmFetcher>(relaxed = true)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "engineSession" to engine,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "vctmFetcher" to vctmFetcher,
        )

        wallet.startIssuanceByOffer(
            org.siros.sdk.credentials.CredentialOffer(
                credentialConfigurationId = "pid",
                credentialIssuerIdentifier = "https://issuer.example.com",
                credentialName = "Personal ID",
                issuerName = "Issuer",
            )
        )

        coVerify(exactly = 1) {
            vctmFetcher.fetch(
                issuerUrl = "https://issuer.example.com",
                scope = "pid",
                vct = null,
                registryUrl = "https://wallet.example.com/registry",
            )
        }
    }

    /**
     * Companion to the above: an integrator whose registry is deployed
     * separately from their main wallet backend must be able to override
     * [WalletConfig.registryUrl] independently - mirroring wallet-frontend's
     * `VCT_REGISTRY_URL` being a distinct, independently-settable config
     * value in that reference implementation, not merely derived.
     */
    @Test
    fun startIssuanceByOffer_passesExplicitConfigRegistryUrl_toVctmFetcher() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val vctmFetcher = mockk<org.siros.sdk.credentials.VctmFetcher>(relaxed = true)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "engineSession" to engine,
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                registryUrl = "https://registry.other-example.com/type-metadata-service",
            ),
            "vctmFetcher" to vctmFetcher,
        )

        wallet.startIssuanceByOffer(
            org.siros.sdk.credentials.CredentialOffer(
                credentialConfigurationId = "pid",
                credentialIssuerIdentifier = "https://issuer.example.com",
                credentialName = "Personal ID",
                issuerName = "Issuer",
            )
        )

        coVerify(exactly = 1) {
            vctmFetcher.fetch(
                issuerUrl = "https://issuer.example.com",
                scope = "pid",
                vct = null,
                registryUrl = "https://registry.other-example.com/type-metadata-service",
            )
        }
    }

    /**
     * Same registryUrl wiring, mdoc side: [SirosWallet.resolveEffectiveKeystoreForIssuance]
     * fetches the MDDL schema via [MddlSchemaFetcher] when no [Vctm] is
     * already active, and must pass the same derived/overridable registryUrl
     * through so the registry-first strategy can run there too.
     */
    @Test
    fun resolveEffectiveKeystoreForIssuance_passesRegistryUrl_toMddlSchemaFetcher() = runTest(dispatcher) {
        val defaultKeystore = mockk<KeystoreManager>(relaxed = true)
        // Not relaxed: a relaxed mock would auto-generate a non-null
        // MddlSchema with a mocked (non-blank) requiredKeyStorage/doctype,
        // which would then send resolveEffectiveKeystoreForIssuance down the
        // real WscdSelectionPolicy resolution path and throw
        // NoEligibleWscdPluginException - this test only cares about the
        // registryUrl argument reaching the fetcher, so the schema itself is
        // stubbed to null (registry/issuer both "no data" - the common case).
        val mddlSchemaFetcher = mockk<org.siros.sdk.credentials.MddlSchemaFetcher>()
        coEvery {
            mddlSchemaFetcher.fetch(issuerUrl = any(), scope = any(), vct = any(), registryUrl = any())
        } returns null
        val config = WalletConfig(
            backendUrl = "https://wallet.example.com",
            availableKeystores = mapOf("softkey" to defaultKeystore),
        )
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to config,
            "keystore" to defaultKeystore,
            "mddlSchemaFetcher" to mddlSchemaFetcher,
            "wscdSelectionPolicy" to WscdSelectionPolicy(tofuStore = InMemoryWscdTofuStore()),
        )
        setField(
            wallet,
            "activeOffer",
            org.siros.sdk.credentials.CredentialOffer(
                credentialConfigurationId = "mdl",
                credentialIssuerIdentifier = "https://issuer.example.com",
                credentialName = "mDL",
                issuerName = "Issuer",
            ),
        )

        val method = wallet::class.declaredMemberFunctions.first { it.name == "resolveEffectiveKeystoreForIssuance" }
        method.isAccessible = true
        kotlinx.coroutines.runBlocking { method.callSuspend(wallet) }

        coVerify(exactly = 1) {
            mddlSchemaFetcher.fetch(
                issuerUrl = "https://issuer.example.com",
                scope = "mdl",
                vct = null,
                registryUrl = "https://wallet.example.com/registry",
            )
        }
    }

    /**
     * `activeOffer` (used to build display metadata for a stored credential -
     * see [CredentialUtils.buildMetadata]/[CredentialUtils.buildMdocMetadata])
     * was previously only ever populated by [SirosWallet.startIssuanceByOffer].
     * The QR/deep-link entry point, [SirosWallet.startIssuance], never set it,
     * so credentials issued via a scanned offer (real-world issuers included)
     * were always stored with no display metadata at all - confirmed against a
     * real geneva2026.mdoc.online mDL credential offer. These tests confirm
     * [SirosWallet.startIssuance] now resolves it by fetching the issuer's
     * standard OID4VCI metadata, for both offer-URI shapes it accepts.
     */
    @Test
    fun startIssuance_resolvesActiveOffer_fromBareOfferJson() = runTest(dispatcher) {
        val server = MockWebServer()
        server.start()
        try {
            server.enqueue(MockResponse().setBody(issuerMetadataJson(server, "org.iso.18013.5.1.mDL")))
            val engine = mockk<WalletEngineSession>(relaxed = true)
            val wallet = newWallet(
                "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
                "engineSession" to engine,
                "config" to WalletConfig(backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback"),
                "json" to Json { ignoreUnknownKeys = true },
                "httpClient" to OkHttpClient(),
            )
            val issuerUrl = server.url("/").toString().trimEnd('/')
            val offerJson = """{"credential_issuer":"$issuerUrl","credential_configuration_ids":["org.iso.18013.5.1.mDL"]}"""

            wallet.startIssuance(offerJson)
            advanceUntilIdle()

            val activeOffer = getField(wallet, "activeOffer") as? org.siros.sdk.credentials.CredentialOffer
            assertEquals("Mobile Driving License", activeOffer?.credentialName)
            assertEquals(issuerUrl, activeOffer?.credentialIssuerIdentifier)
            assertEquals("org.iso.18013.5.1.mDL", activeOffer?.credentialConfigurationId)
            verify(exactly = 1) { engine.startIssuance(offer = offerJson, credentialOfferUri = null, redirectUri = "siros-sample://callback") }
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun startIssuance_resolvesActiveOffer_fromOpenidCredentialOfferDeepLink() = runTest(dispatcher) {
        val server = MockWebServer()
        server.start()
        try {
            server.enqueue(MockResponse().setBody(issuerMetadataJson(server, "org.iso.18013.5.1.mDL")))
            val engine = mockk<WalletEngineSession>(relaxed = true)
            val wallet = newWallet(
                "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
                "engineSession" to engine,
                "config" to WalletConfig(backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback"),
                "json" to Json { ignoreUnknownKeys = true },
                "httpClient" to OkHttpClient(),
            )
            val issuerUrl = server.url("/").toString().trimEnd('/')
            val offerJson = """{"credential_issuer":"$issuerUrl","credential_configuration_ids":["org.iso.18013.5.1.mDL"]}"""
            val deepLink = "openid-credential-offer://?credential_offer=" +
                java.net.URLEncoder.encode(offerJson, "UTF-8")

            wallet.startIssuance(deepLink)
            advanceUntilIdle()

            val activeOffer = getField(wallet, "activeOffer") as? org.siros.sdk.credentials.CredentialOffer
            assertEquals("Mobile Driving License", activeOffer?.credentialName)
            assertEquals(issuerUrl, activeOffer?.credentialIssuerIdentifier)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun startIssuance_leavesActiveOfferNull_andStillIssues_whenIssuerMetadataUnreachable() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "engineSession" to engine,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback"),
            "json" to Json { ignoreUnknownKeys = true },
            "httpClient" to OkHttpClient(),
        )
        // No mdoc/scope matches any listening server - metadata resolution fails,
        // but issuance must still proceed.
        val offerJson = """{"credential_issuer":"https://issuer.invalid","credential_configuration_ids":["pid"]}"""

        wallet.startIssuance(offerJson)
        advanceUntilIdle()

        assertEquals(null, getField(wallet, "activeOffer"))
        verify(exactly = 1) { engine.startIssuance(offer = offerJson, credentialOfferUri = null, redirectUri = "siros-sample://callback") }
    }

    /** header.{"exp": exp}.sig - just enough for CredentialUtils.parseJwtPayload to read `exp`. */
    private fun fakeJwtWithExp(exp: Long): String {
        val payload = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("""{"exp":$exp}""".toByteArray(Charsets.UTF_8))
        return "eyJhbGciOiJub25lIn0.$payload.sig"
    }

    /** A fake WIA JWT carrying `exp`, `cnf.jkt`, and `attestation_source` - for currentWalletInstanceId() tests. */
    private fun fakeWiaJwt(exp: Long, jkt: String?, attestationSource: String?): String {
        val cnfField = if (jkt != null) ""","cnf":{"jkt":"$jkt"}""" else ""
        val sourceField = if (attestationSource != null) ""","attestation_source":"$attestationSource"""" else ""
        val payload = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("""{"exp":$exp$cnfField$sourceField}""".toByteArray(Charsets.UTF_8))
        return "eyJhbGciOiJub25lIn0.$payload.sig"
    }

    /**
     * OAuth Client Attestation (draft-ietf-oauth-attestation-based-client-auth-04
     * §3.1): startIssuance must obtain a Wallet Instance Attestation (via a
     * challenge round trip + instance-key PoP) and a fresh per-issuer PoP,
     * and thread both into the outbound flow_start - see SirosWallet.kt's
     * resolveClientAttestation/ensureWalletInstanceAttestation.
     */
    @Test
    fun startIssuance_attachesClientAttestation_whenBackendSupportsWia() = runTest(dispatcher) {
        val server = MockWebServer()
        server.start()
        try {
            server.enqueue(MockResponse().setBody(issuerMetadataJson(server, "org.iso.18013.5.1.mDL")))
            val engine = mockk<WalletEngineSession>(relaxed = true)
            val sessionStore = mockk<SessionStore>(relaxed = true)
            every { sessionStore.instanceKeyId } returns "instance-key-1"
            val keystore = mockk<KeystoreManager>(relaxed = true)
            coEvery {
                keystore.generateKeyProof(keyId = any(), typ = any(), issuer = any(), audience = any(), extraClaims = any())
            } returns "pop-jwt"
            val apiClient = mockk<BackendApiClient>(relaxed = true)
            coEvery { apiClient.requestWIAChallenge() } returns buildJsonObject { put("challenge", "chal-1") }
            val wiaJwt = fakeJwtWithExp(System.currentTimeMillis() / 1000 + 3600)
            coEvery { apiClient.generateWIA(pop = any(), challenge = "chal-1", clientId = any()) } returns wiaJwt

            val wallet = newWallet(
                "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
                "engineSession" to engine,
                "sessionStore" to sessionStore,
                "keystore" to keystore,
                "apiClient" to apiClient,
                "config" to WalletConfig(backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback"),
                "json" to Json { ignoreUnknownKeys = true },
                "httpClient" to OkHttpClient(),
            )
            val issuerUrl = server.url("/").toString().trimEnd('/')
            val offerJson = """{"credential_issuer":"$issuerUrl","credential_configuration_ids":["org.iso.18013.5.1.mDL"]}"""

            wallet.startIssuance(offerJson)
            advanceUntilIdle()

            verify(exactly = 1) {
                engine.startIssuance(
                    offer = offerJson,
                    credentialOfferUri = null,
                    redirectUri = "siros-sample://callback",
                    clientAttestation = wiaJwt,
                    clientAttestationPoP = "pop-jwt",
                )
            }
        } finally {
            server.shutdown()
        }
    }

    /**
     * When a `nativeAttestationProvider` is configured, `ensureWalletInstanceAttestation()`
     * must attach its evidence to the WIA generate call as `native_attestation`,
     * snake_case `key_id` included, so the backend's KA trust gate can see it.
     */
    @Test
    fun startIssuance_includesNativeAttestation_whenProviderConfigured() = runTest(dispatcher) {
        val server = MockWebServer()
        server.start()
        try {
            server.enqueue(MockResponse().setBody(issuerMetadataJson(server, "org.iso.18013.5.1.mDL")))
            val engine = mockk<WalletEngineSession>(relaxed = true)
            val sessionStore = mockk<SessionStore>(relaxed = true)
            every { sessionStore.instanceKeyId } returns "instance-key-1"
            val keystore = mockk<KeystoreManager>(relaxed = true)
            coEvery {
                keystore.generateKeyProof(keyId = any(), typ = any(), issuer = any(), audience = any(), extraClaims = any())
            } returns "pop-jwt"
            val apiClient = mockk<BackendApiClient>(relaxed = true)
            coEvery { apiClient.requestWIAChallenge() } returns buildJsonObject { put("challenge", "chal-1") }
            val wiaJwt = fakeJwtWithExp(System.currentTimeMillis() / 1000 + 3600)
            val nativeAttestationSlot = slot<JsonObject>()
            coEvery {
                apiClient.generateWIA(pop = any(), challenge = "chal-1", clientId = any(), nativeAttestation = capture(nativeAttestationSlot))
            } returns wiaJwt
            val provider = object : NativeAttestationProvider {
                override val isAvailable = true
                override suspend fun generateEvidence(challenge: String, keyId: String) = NativeAttestationEvidence(
                    type = "google_play_integrity",
                    token = "integrity-token-abc",
                    keyId = keyId,
                    challenge = challenge,
                )
            }

            val wallet = newWallet(
                "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
                "engineSession" to engine,
                "sessionStore" to sessionStore,
                "keystore" to keystore,
                "apiClient" to apiClient,
                "config" to WalletConfig(
                    backendUrl = "https://wallet.example.com",
                    redirectUri = "siros-sample://callback",
                    nativeAttestationProvider = provider,
                ),
                "json" to Json { ignoreUnknownKeys = true },
                "httpClient" to OkHttpClient(),
            )
            val issuerUrl = server.url("/").toString().trimEnd('/')
            val offerJson = """{"credential_issuer":"$issuerUrl","credential_configuration_ids":["org.iso.18013.5.1.mDL"]}"""

            wallet.startIssuance(offerJson)
            advanceUntilIdle()

            val nativeAttestation = nativeAttestationSlot.captured
            assertEquals("google_play_integrity", nativeAttestation["type"]?.jsonPrimitive?.content)
            assertEquals("integrity-token-abc", nativeAttestation["token"]?.jsonPrimitive?.content)
            assertEquals("instance-key-1", nativeAttestation["key_id"]?.jsonPrimitive?.content)
            assertEquals("chal-1", nativeAttestation["challenge"]?.jsonPrimitive?.content)
        } finally {
            server.shutdown()
        }
    }

    /**
     * When requesting a backend Key Attestation, each freshly generated
     * credential-issuance key's own FIDO2/CTAP2 attestation (not the wallet's
     * identity key) must be registered with the backend individually, so the
     * per-key trust evidence lines up with the actual keys the KA request's
     * `attested_keys`/`security_properties` claim is about (see
     * `registerFido2AttestationsForBatch`'s doc comment).
     */
    @Test
    fun requestBackendKeyAttestation_registersFido2Attestation_perHardwareBackedKey() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val keystore = mockk<KeystoreManager>()
        val keypairs = listOf(
            KeypairInfo(keyId = "key-1", publicKeyJWK = buildJsonObject { put("kty", "EC") }),
            KeypairInfo(keyId = "key-2", publicKeyJWK = buildJsonObject { put("kty", "EC") }),
        )
        coEvery { keystore.generateKeypairs(2) } returns keypairs
        val chain1 = AttestationChain(certificates = listOf(byteArrayOf(0x01)), clientDataHash = ByteArray(32) { 0x09 })
        val chain2 = AttestationChain(certificates = listOf(byteArrayOf(0x02)), clientDataHash = ByteArray(32) { 0x0a })
        coEvery { keystore.attestationChain("key-1") } returns chain1
        coEvery { keystore.attestationChain("key-2") } returns chain2
        coEvery { keystore.securityProperties("key-1") } returns null
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        coEvery {
            apiClient.requestKeyAttestation(
                jwks = keypairs.map { it.publicKeyJWK },
                nonce = "nonce-1",
                securityProperties = null,
                credentialIssuer = "aud-1",
                walletInstanceId = "test-jkt",
            )
        } returns "backend-signed-attestation-jwt"
        val engine = mockEngineConstructor(signRequests = signFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to keystore,
        )

        invokeConnectEngine(wallet, "app-token")
        setField(wallet, "apiClient", apiClient)
        setField(wallet, "cachedWia", fakeWiaJwt(System.currentTimeMillis() / 1000 + 3600, jkt = "test-jkt", attestationSource = "ios_app_attest"))
        setField(wallet, "cachedWiaExpiresAt", System.currentTimeMillis() / 1000 + 3600)
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(
                    audience = "aud-1",
                    nonce = "nonce-1",
                    count = 2,
                    proofTypesSupported = buildJsonObject { putJsonObject("attestation") {} },
                ),
            )
        )
        advanceUntilIdle()

        coVerify(exactly = 1) {
            apiClient.registerFido2Attestation(
                walletInstanceId = "test-jkt",
                attestationObject = chain1.certificates[0],
                clientDataHash = chain1.clientDataHash,
            )
        }
        coVerify(exactly = 1) {
            apiClient.registerFido2Attestation(
                walletInstanceId = "test-jkt",
                attestationObject = chain2.certificates[0],
                clientDataHash = chain2.clientDataHash,
            )
        }
    }

    /**
     * A key generated by a non-hardware-backed (e.g. softkey) plugin has no
     * attestation chain - registration for that key must be skipped, not
     * fail the whole batch or the KA request itself.
     */
    @Test
    fun requestBackendKeyAttestation_skipsFido2Registration_forSoftwareBackedKeys() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val keystore = mockk<KeystoreManager>()
        val keypairs = listOf(KeypairInfo(keyId = "key-1", publicKeyJWK = buildJsonObject { put("kty", "EC") }))
        coEvery { keystore.generateKeypairs(1) } returns keypairs
        coEvery { keystore.attestationChain("key-1") } returns null
        coEvery { keystore.securityProperties("key-1") } returns null
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        coEvery {
            apiClient.requestKeyAttestation(
                jwks = keypairs.map { it.publicKeyJWK },
                nonce = "nonce-1",
                securityProperties = null,
                credentialIssuer = "aud-1",
                walletInstanceId = "test-jkt",
            )
        } returns "backend-signed-attestation-jwt"
        val engine = mockEngineConstructor(signRequests = signFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to keystore,
        )

        invokeConnectEngine(wallet, "app-token")
        setField(wallet, "apiClient", apiClient)
        setField(wallet, "cachedWia", fakeWiaJwt(System.currentTimeMillis() / 1000 + 3600, jkt = "test-jkt", attestationSource = "ios_app_attest"))
        setField(wallet, "cachedWiaExpiresAt", System.currentTimeMillis() / 1000 + 3600)
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(
                    audience = "aud-1",
                    nonce = "nonce-1",
                    count = 1,
                    proofTypesSupported = buildJsonObject { putJsonObject("attestation") {} },
                ),
            )
        )
        advanceUntilIdle()

        coVerify(exactly = 0) {
            apiClient.registerFido2Attestation(any<String>(), any<ByteArray>(), any<ByteArray>())
        }
    }

    /**
     * With no cached WIA available, there's no `wallet_instance_id` to
     * scope the registration record to - `registerFido2AttestationsForBatch`
     * must skip registration entirely without touching `attestationChain`,
     * and must not block the KA request itself.
     */
    @Test
    fun requestBackendKeyAttestation_skipsFido2Registration_whenNoCachedWia() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val keystore = mockk<KeystoreManager>()
        val keypairs = listOf(KeypairInfo(keyId = "key-1", publicKeyJWK = buildJsonObject { put("kty", "EC") }))
        coEvery { keystore.generateKeypairs(1) } returns keypairs
        coEvery { keystore.securityProperties("key-1") } returns null
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        coEvery {
            apiClient.requestKeyAttestation(
                jwks = keypairs.map { it.publicKeyJWK },
                nonce = "nonce-1",
                securityProperties = null,
                credentialIssuer = "aud-1",
                walletInstanceId = null,
            )
        } returns "backend-signed-attestation-jwt"
        val engine = mockEngineConstructor(signRequests = signFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to keystore,
        )

        invokeConnectEngine(wallet, "app-token")
        setField(wallet, "apiClient", apiClient)
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(
                    audience = "aud-1",
                    nonce = "nonce-1",
                    count = 1,
                    proofTypesSupported = buildJsonObject { putJsonObject("attestation") {} },
                ),
            )
        )
        advanceUntilIdle()

        coVerify(exactly = 0) { keystore.attestationChain(any<String>()) }
        coVerify(exactly = 0) {
            apiClient.registerFido2Attestation(any<String>(), any<ByteArray>(), any<ByteArray>())
        }
    }

    private class InMemoryWscdTofuStore : WscdTofuStore {
        val entries = mutableMapOf<String, String>()
        private fun key(issuer: String, credentialType: String) = "$issuer|$credentialType"
        override fun get(issuer: String, credentialType: String): String? = entries[key(issuer, credentialType)]
        override fun put(issuer: String, credentialType: String, pluginId: String) {
            entries[key(issuer, credentialType)] = pluginId
        }
    }

    /**
     * End-to-end: an issuer with multiple registered [WalletConfig.availableKeystores]
     * plugins, requesting a Key Attestation for a credential type that
     * declares (via [Vctm.requiredKeyStorage]) it needs `iso_18045_high` -
     * only the "fido2" plugin's static tier meets that per
     * [org.siros.sdk.keystore.WscdPluginCapabilities], so
     * [WscdSelectionPolicy] must auto-pick it (the only eligible plugin, see
     * that class's resolution order) and `generateKeypairs` must be called
     * on the fido2 keystore instance, never on the wallet's own default
     * [keystore].
     */
    @Test
    fun requestBackendKeyAttestation_usesEligiblePlugin_forCredentialTypeRequiringHigherTier() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val defaultKeystore = mockk<KeystoreManager>()
        val fido2Keystore = mockk<KeystoreManager>()
        val keypairs = listOf(KeypairInfo(keyId = "fido2-key-1", publicKeyJWK = buildJsonObject { put("kty", "EC") }))
        coEvery { fido2Keystore.generateKeypairs(1) } returns keypairs
        coEvery { fido2Keystore.attestationChain(any()) } returns null
        coEvery { fido2Keystore.securityProperties("fido2-key-1") } returns null
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        coEvery {
            apiClient.requestKeyAttestation(
                jwks = keypairs.map { it.publicKeyJWK },
                nonce = "nonce-1",
                securityProperties = null,
                credentialIssuer = "https://issuer.example.com",
                walletInstanceId = null,
            )
        } returns "backend-signed-attestation-jwt"
        val engine = mockEngineConstructor(signRequests = signFlow)
        val config = WalletConfig(
            backendUrl = "https://wallet.example.com",
            availableKeystores = mapOf("softkey" to defaultKeystore, "fido2" to fido2Keystore),
        )
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to config,
            "keystore" to defaultKeystore,
            "wscdSelectionPolicy" to WscdSelectionPolicy(tofuStore = InMemoryWscdTofuStore()),
        )
        setField(
            wallet,
            "activeOffer",
            org.siros.sdk.credentials.CredentialOffer(
                credentialConfigurationId = "pid",
                credentialIssuerIdentifier = "https://issuer.example.com",
                credentialName = "PID",
                issuerName = "Issuer",
            ),
        )
        setField(
            wallet,
            "activeVctm",
            org.siros.sdk.credentials.Vctm(vct = "urn:eu.europa.ec.eudi:pid:1", requiredKeyStorage = "iso_18045_high"),
        )

        invokeConnectEngine(wallet, "app-token")
        setField(wallet, "apiClient", apiClient)
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(
                    audience = "https://issuer.example.com",
                    nonce = "nonce-1",
                    count = 1,
                    proofTypesSupported = buildJsonObject { putJsonObject("attestation") {} },
                ),
            )
        )
        advanceUntilIdle()

        coVerify(exactly = 1) { fido2Keystore.generateKeypairs(1) }
        coVerify(exactly = 0) { defaultKeystore.generateKeypairs(any()) }
    }

    /**
     * When zero registered plugins meet a credential type's declared
     * requirement, [WscdSelectionPolicy] throws [NoEligibleWscdPluginException]
     * - `requestBackendKeyAttestation` must let it propagate rather than
     * quietly falling back to the (insufficient) default keystore, so no
     * keys are ever generated with a plugin that can't satisfy the
     * requirement and no sign response is sent for that request.
     */
    @Test
    fun requestBackendKeyAttestation_doesNotFallBack_whenNoPluginMeetsRequirement() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val defaultKeystore = mockk<KeystoreManager>(relaxed = true)
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        val engine = mockEngineConstructor(signRequests = signFlow)
        val config = WalletConfig(
            backendUrl = "https://wallet.example.com",
            // Only "softkey" ("basic") registered - insufficient for "high".
            availableKeystores = mapOf("softkey" to defaultKeystore),
        )
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to config,
            "keystore" to defaultKeystore,
            "wscdSelectionPolicy" to WscdSelectionPolicy(tofuStore = InMemoryWscdTofuStore()),
        )
        setField(
            wallet,
            "activeOffer",
            org.siros.sdk.credentials.CredentialOffer(
                credentialConfigurationId = "pid",
                credentialIssuerIdentifier = "https://issuer.example.com",
                credentialName = "PID",
                issuerName = "Issuer",
            ),
        )
        setField(
            wallet,
            "activeVctm",
            org.siros.sdk.credentials.Vctm(vct = "urn:eu.europa.ec.eudi:pid:1", requiredKeyStorage = "iso_18045_high"),
        )

        invokeConnectEngine(wallet, "app-token")
        setField(wallet, "apiClient", apiClient)
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(
                    audience = "https://issuer.example.com",
                    nonce = "nonce-1",
                    count = 1,
                    proofTypesSupported = buildJsonObject { putJsonObject("attestation") {} },
                ),
            )
        )
        advanceUntilIdle()

        coVerify(exactly = 0) { defaultKeystore.generateKeypairs(any()) }
        coVerify(exactly = 0) { engine.sendSignResponse(any(), any(), any(), any()) }
    }

    /**
     * Regression (PR #85 review, bug 1): `resolveEffectiveKeystoreForIssuance`
     * must key [WscdSelectionPolicy] lookups (TOFU/defaultMapping) by the
     * credential type's real `vct`/`doctype` identifier, NOT
     * `CredentialOffer.credentialConfigurationId` - the two are deliberately
     * different here (`credentialConfigurationId` is an OID4VCI-internal ID
     * the docs/config examples never use as a key). A TOFU entry keyed by the
     * `vct` for a plugin that's the ONLY one of two eligible plugins must be
     * found and used without prompting - if the buggy `credentialConfigurationId`
     * key were still used instead, this TOFU lookup would miss, both eligible
     * plugins ("fido2"/"r2ps") would fall through to the ask-user step, and
     * (with no `requestWscdChoice` configured) resolution would throw
     * [AmbiguousWscdPluginException] instead of silently succeeding.
     */
    @Test
    fun resolveEffectiveKeystoreForIssuance_keysWscdLookupByVct_notCredentialConfigurationId() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val fido2Keystore = mockk<KeystoreManager>()
        val r2psKeystore = mockk<KeystoreManager>(relaxed = true)
        val keypairs = listOf(KeypairInfo(keyId = "fido2-key-1", publicKeyJWK = buildJsonObject { put("kty", "EC") }))
        coEvery { fido2Keystore.generateKeypairs(1) } returns keypairs
        coEvery { fido2Keystore.attestationChain(any()) } returns null
        coEvery { fido2Keystore.securityProperties("fido2-key-1") } returns null
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        coEvery {
            apiClient.requestKeyAttestation(
                jwks = keypairs.map { it.publicKeyJWK },
                nonce = "nonce-1",
                securityProperties = null,
                credentialIssuer = "https://issuer.example.com",
                walletInstanceId = null,
            )
        } returns "backend-signed-attestation-jwt"
        val engine = mockEngineConstructor(signRequests = signFlow)
        val config = WalletConfig(
            backendUrl = "https://wallet.example.com",
            availableKeystores = mapOf("fido2" to fido2Keystore, "r2ps" to r2psKeystore),
        )
        // TOFU pre-populated keyed by the real vct, not the (deliberately
        // different) credentialConfigurationId set below.
        val tofuStore = InMemoryWscdTofuStore().apply {
            put("https://issuer.example.com", "urn:eu.europa.ec.eudi:pid:1", "fido2")
        }
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to config,
            "keystore" to fido2Keystore,
            "wscdSelectionPolicy" to WscdSelectionPolicy(tofuStore = tofuStore),
        )
        setField(
            wallet,
            "activeOffer",
            org.siros.sdk.credentials.CredentialOffer(
                credentialConfigurationId = "totally-different-internal-config-id",
                credentialIssuerIdentifier = "https://issuer.example.com",
                credentialName = "PID",
                issuerName = "Issuer",
            ),
        )
        setField(
            wallet,
            "activeVctm",
            org.siros.sdk.credentials.Vctm(vct = "urn:eu.europa.ec.eudi:pid:1", requiredKeyStorage = "iso_18045_high"),
        )

        invokeConnectEngine(wallet, "app-token")
        setField(wallet, "apiClient", apiClient)
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(
                    audience = "https://issuer.example.com",
                    nonce = "nonce-1",
                    count = 1,
                    proofTypesSupported = buildJsonObject { putJsonObject("attestation") {} },
                ),
            )
        )
        advanceUntilIdle()

        coVerify(exactly = 1) { fido2Keystore.generateKeypairs(1) }
        coVerify(exactly = 0) { r2psKeystore.generateKeypairs(any()) }
    }

    /**
     * Regression (PR #85 review, bug 2): when the backend Key Attestation
     * call fails, the self-signed fallback
     * ([KeystoreManager.generateKeyAttestation]) must be invoked on the SAME
     * resolved plugin [WscdSelectionPolicy] picked for this call (here,
     * "fido2"), never on the wallet's own unconditional default `keystore`
     * field - otherwise a resolved higher-tier plugin is silently bypassed on
     * fallback, downgrading to a lower-tier self-signed attestation.
     */
    @Test
    fun requestBackendKeyAttestation_selfSignedFallback_usesResolvedKeystore_notWalletDefault() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val defaultKeystore = mockk<KeystoreManager>(relaxed = true)
        val fido2Keystore = mockk<KeystoreManager>()
        val keypairs = listOf(KeypairInfo(keyId = "fido2-key-1", publicKeyJWK = buildJsonObject { put("kty", "EC") }))
        coEvery { fido2Keystore.generateKeypairs(1) } returns keypairs
        coEvery { fido2Keystore.attestationChain(any()) } returns null
        coEvery { fido2Keystore.securityProperties("fido2-key-1") } returns null
        coEvery { fido2Keystore.generateKeyAttestation(nonce = "nonce-1", count = 1) } returns "self-signed-by-fido2"
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        // Simulate the backend attestation call failing, forcing the
        // self-signed fallback path.
        coEvery {
            apiClient.requestKeyAttestation(
                jwks = any(),
                nonce = any(),
                securityProperties = any(),
                credentialIssuer = any(),
                walletInstanceId = any(),
            )
        } throws RuntimeException("backend unavailable")
        val engine = mockEngineConstructor(signRequests = signFlow)
        val config = WalletConfig(
            backendUrl = "https://wallet.example.com",
            availableKeystores = mapOf("softkey" to defaultKeystore, "fido2" to fido2Keystore),
        )
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to config,
            "keystore" to defaultKeystore,
            "wscdSelectionPolicy" to WscdSelectionPolicy(tofuStore = InMemoryWscdTofuStore()),
        )
        setField(
            wallet,
            "activeOffer",
            org.siros.sdk.credentials.CredentialOffer(
                credentialConfigurationId = "pid",
                credentialIssuerIdentifier = "https://issuer.example.com",
                credentialName = "PID",
                issuerName = "Issuer",
            ),
        )
        setField(
            wallet,
            "activeVctm",
            org.siros.sdk.credentials.Vctm(vct = "urn:eu.europa.ec.eudi:pid:1", requiredKeyStorage = "iso_18045_high"),
        )

        invokeConnectEngine(wallet, "app-token")
        setField(wallet, "apiClient", apiClient)
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(
                    audience = "https://issuer.example.com",
                    nonce = "nonce-1",
                    count = 1,
                    proofTypesSupported = buildJsonObject { putJsonObject("attestation") {} },
                ),
            )
        )
        advanceUntilIdle()

        coVerify(exactly = 1) { fido2Keystore.generateKeyAttestation(nonce = "nonce-1", count = 1) }
        coVerify(exactly = 0) { defaultKeystore.generateKeyAttestation(any(), any()) }
    }

    /**
     * A native-attestation failure (device doesn't support it, Play Services
     * missing, etc.) must degrade to a plain backend-attested WIA, not abort
     * issuance entirely - this is the same best-effort contract as every
     * other step of ensureWalletInstanceAttestation().
     */
    @Test
    fun startIssuance_omitsNativeAttestation_whenProviderThrows() = runTest(dispatcher) {
        val server = MockWebServer()
        server.start()
        try {
            server.enqueue(MockResponse().setBody(issuerMetadataJson(server, "org.iso.18013.5.1.mDL")))
            val engine = mockk<WalletEngineSession>(relaxed = true)
            val sessionStore = mockk<SessionStore>(relaxed = true)
            every { sessionStore.instanceKeyId } returns "instance-key-1"
            val keystore = mockk<KeystoreManager>(relaxed = true)
            coEvery {
                keystore.generateKeyProof(keyId = any(), typ = any(), issuer = any(), audience = any(), extraClaims = any())
            } returns "pop-jwt"
            val apiClient = mockk<BackendApiClient>(relaxed = true)
            coEvery { apiClient.requestWIAChallenge() } returns buildJsonObject { put("challenge", "chal-1") }
            val wiaJwt = fakeJwtWithExp(System.currentTimeMillis() / 1000 + 3600)
            coEvery {
                apiClient.generateWIA(pop = any(), challenge = "chal-1", clientId = any(), nativeAttestation = null)
            } returns wiaJwt
            val throwingProvider = object : NativeAttestationProvider {
                override val isAvailable = true
                override suspend fun generateEvidence(challenge: String, keyId: String): NativeAttestationEvidence {
                    throw IllegalStateException("device attestation unavailable")
                }
            }

            val wallet = newWallet(
                "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
                "engineSession" to engine,
                "sessionStore" to sessionStore,
                "keystore" to keystore,
                "apiClient" to apiClient,
                "config" to WalletConfig(
                    backendUrl = "https://wallet.example.com",
                    redirectUri = "siros-sample://callback",
                    nativeAttestationProvider = throwingProvider,
                ),
                "json" to Json { ignoreUnknownKeys = true },
                "httpClient" to OkHttpClient(),
            )
            val issuerUrl = server.url("/").toString().trimEnd('/')
            val offerJson = """{"credential_issuer":"$issuerUrl","credential_configuration_ids":["org.iso.18013.5.1.mDL"]}"""

            wallet.startIssuance(offerJson)
            advanceUntilIdle()

            verify(exactly = 1) {
                engine.startIssuance(
                    offer = offerJson,
                    credentialOfferUri = null,
                    redirectUri = "siros-sample://callback",
                    clientAttestation = wiaJwt,
                    clientAttestationPoP = "pop-jwt",
                )
            }
        } finally {
            server.shutdown()
        }
    }

    /**
     * draft-ietf-oauth-attestation-based-client-auth-10 fixes, confirmed
     * against a real geneva2026.mdoc.online conformance run:
     * - the WIA's `sub` and the per-issuer PoP's `iss` must both equal the
     *   OAuth client_id (config.redirectUri) - a real credential offer
     *   flagged sub/iss=<instance jkt> as FAILs.
     * - the per-issuer PoP's optional `challenge` claim, when the issuer's AS
     *   publishes a `challenge_endpoint` in its metadata, must be fetched
     *   from there and included - flagged as a FAIL when absent.
     */
    @Test
    fun startIssuance_usesClientIdForSubAndIss_andFetchesChallengeFromIssuerAs() = runTest(dispatcher) {
        val server = MockWebServer()
        server.start()
        try {
            val configId = "org.iso.18013.5.1.mDL"
            // startIssuance fetches issuer metadata twice - once for display
            // (resolveOfferForDisplay), once for client attestation
            // (resolveClientAttestation) - both against the same URL.
            server.enqueue(MockResponse().setBody(issuerMetadataJson(server, configId)))
            server.enqueue(MockResponse().setBody(issuerMetadataJson(server, configId)))
            val asUrl = server.url("/").toString().trimEnd('/')
            server.enqueue(MockResponse().setBody("""{"challenge_endpoint":"$asUrl/attestation/challenge"}"""))
            server.enqueue(MockResponse().setBody("""{"attestation_challenge":"chal-from-issuer-as"}"""))

            val engine = mockk<WalletEngineSession>(relaxed = true)
            val sessionStore = mockk<SessionStore>(relaxed = true)
            every { sessionStore.instanceKeyId } returns "instance-key-1"
            val keystore = mockk<KeystoreManager>(relaxed = true)
            coEvery {
                keystore.generateKeyProof(
                    keyId = any(), typ = any(), issuer = "siros-sample://callback",
                    audience = "https://wallet.example.com", extraClaims = any(),
                )
            } returns "wia-pop-jwt"
            val perIssuerExtraClaims = slot<Map<String, String>>()
            coEvery {
                keystore.generateKeyProof(
                    keyId = any(), typ = any(), issuer = "siros-sample://callback",
                    audience = asUrl, extraClaims = capture(perIssuerExtraClaims),
                )
            } returns "issuer-pop-jwt"
            val apiClient = mockk<BackendApiClient>(relaxed = true)
            coEvery { apiClient.requestWIAChallenge() } returns buildJsonObject { put("challenge", "chal-1") }
            val wiaJwt = fakeJwtWithExp(System.currentTimeMillis() / 1000 + 3600)
            coEvery { apiClient.generateWIA(pop = any(), challenge = "chal-1", clientId = any()) } returns wiaJwt

            val wallet = newWallet(
                "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
                "engineSession" to engine,
                "sessionStore" to sessionStore,
                "keystore" to keystore,
                "apiClient" to apiClient,
                "config" to WalletConfig(backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback"),
                "json" to Json { ignoreUnknownKeys = true },
                "httpClient" to OkHttpClient(),
            )
            val offerJson = """{"credential_issuer":"$asUrl","credential_configuration_ids":["$configId"]}"""

            wallet.startIssuance(offerJson)
            advanceUntilIdle()

            coVerify(exactly = 1) {
                apiClient.generateWIA(pop = any(), challenge = "chal-1", clientId = "siros-sample://callback")
            }
            assertEquals("chal-from-issuer-as", perIssuerExtraClaims.captured["challenge"])
            verify(exactly = 1) {
                engine.startIssuance(
                    offer = offerJson,
                    credentialOfferUri = null,
                    redirectUri = "siros-sample://callback",
                    clientAttestation = wiaJwt,
                    clientAttestationPoP = "issuer-pop-jwt",
                )
            }
        } finally {
            server.shutdown()
        }
    }

    /** Missing/unavailable WIA support must never block issuance - engine.startIssuance still fires, with nulls. */
    @Test
    fun startIssuance_stillIssues_whenWiaChallengeFails() = runTest(dispatcher) {
        val server = MockWebServer()
        server.start()
        try {
            server.enqueue(MockResponse().setBody(issuerMetadataJson(server, "org.iso.18013.5.1.mDL")))
            val engine = mockk<WalletEngineSession>(relaxed = true)
            val sessionStore = mockk<SessionStore>(relaxed = true)
            every { sessionStore.instanceKeyId } returns "instance-key-1"
            val keystore = mockk<KeystoreManager>(relaxed = true)
            val apiClient = mockk<BackendApiClient>(relaxed = true)
            coEvery { apiClient.requestWIAChallenge() } throws java.io.IOException("backend unreachable")

            val wallet = newWallet(
                "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
                "engineSession" to engine,
                "sessionStore" to sessionStore,
                "keystore" to keystore,
                "apiClient" to apiClient,
                "config" to WalletConfig(backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback"),
                "json" to Json { ignoreUnknownKeys = true },
                "httpClient" to OkHttpClient(),
            )
            val issuerUrl = server.url("/").toString().trimEnd('/')
            val offerJson = """{"credential_issuer":"$issuerUrl","credential_configuration_ids":["org.iso.18013.5.1.mDL"]}"""

            wallet.startIssuance(offerJson)
            advanceUntilIdle()

            verify(exactly = 1) {
                engine.startIssuance(
                    offer = offerJson,
                    credentialOfferUri = null,
                    redirectUri = "siros-sample://callback",
                    clientAttestation = null,
                    clientAttestationPoP = null,
                )
            }
        } finally {
            server.shutdown()
        }
    }

    private fun issuerMetadataJson(server: MockWebServer, configId: String): String {
        val issuerUrl = server.url("/").toString().trimEnd('/')
        return """
            {
              "credential_issuer": "$issuerUrl",
              "credential_configurations_supported": {
                "$configId": {
                  "format": "mso_mdoc",
                  "doctype": "$configId",
                  "credential_metadata": {
                    "display": [
                      {"name": "Mobile Driving License", "locale": "en-US", "logo": {"uri": "https://issuer.example.com/logo.png"}}
                    ]
                  }
                }
              }
            }
        """.trimIndent()
    }

    @Test
    fun connectEngine_flowComplete_stores_credentials_notifies_listener_and_returns_ready() = runTest(dispatcher) {
        // Minimal valid JWT: {"alg":"none"}.{"sub":"test","iat":1700000000,"exp":9999999999}.
        val testCredential = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjk5OTk5OTk5OTl9."
        val completeFlow = MutableSharedFlow<FlowCompleteMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val store = FakeCredentialStore(mutableListOf())
        val keystore = mockk<KeystoreManager>()
        val sessionStore = mockk<SessionStore>(relaxed = true)
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        var privateDataJwe: String? = null
        every { keystore.isUnlocked } returns true
        every { sessionStore.privateDataJwe } answers { privateDataJwe }
        every { sessionStore.privateDataJwe = any() } answers { privateDataJwe = firstArg() }
        coEvery { keystore.exportEncryptedContainer() } returns """{"prfKeys":[],"jwe":"updated-jwe"}""".toByteArray()
        coEvery { apiClient.updatePrivateData(any()) } returns buildJsonObject {}
        mockEngineConstructor(flowComplete = completeFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.FlowActive(
                    userId = "user-1",
                    displayName = "Alice",
                    flowId = "flow-complete",
                    flowType = "issuance",
                    status = "in_progress",
                    credentials = emptyList(),
                )
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "keystore" to keystore,
            "sessionStore" to sessionStore,
            "apiClient" to apiClient,
            "eventListener" to listener,
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        completeFlow.emit(
            FlowCompleteMessage(
                flowId = "flow-complete",
                credentials = listOf(
                    CredentialResult(format = "dc+sd-jwt", credential = testCredential)
                ),
            )
        )
        advanceUntilIdle()

        verify(exactly = 1) { listener.onFlowComplete("flow-complete") }
        verify(exactly = 1) {
            listener.onCredentialReceived(match { it.format == "dc+sd-jwt" && it.raw == testCredential })
        }
        coVerify(exactly = 1) { keystore.exportEncryptedContainer() }
        coVerify(exactly = 1) { apiClient.updatePrivateData(any()) }
        val ready = wallet.state.value as WalletState.Ready
        assertEquals("user-1", ready.userId)
        assertEquals(1, ready.credentials.size)
        assertEquals(testCredential, ready.credentials.single().raw)
    }

    @Test
    fun connectEngine_flowComplete_assignsSharedBatchIdAndSequentialInstanceIds_forMultiCredentialBatch() = runTest(dispatcher) {
        // Minimal valid JWTs: {"alg":"none"}.{"sub":"test","iat":1700000000,"exp":9999999999}.
        val cred = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjk5OTk5OTk5OTl9."
        val completeFlow = MutableSharedFlow<FlowCompleteMessage>()
        val store = FakeCredentialStore(mutableListOf())
        val keystore = mockk<KeystoreManager>()
        val sessionStore = mockk<SessionStore>(relaxed = true)
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        var privateDataJwe: String? = null
        every { keystore.isUnlocked } returns true
        every { sessionStore.privateDataJwe } answers { privateDataJwe }
        every { sessionStore.privateDataJwe = any() } answers { privateDataJwe = firstArg() }
        coEvery { keystore.exportEncryptedContainer() } returns """{"prfKeys":[],"jwe":"updated-jwe"}""".toByteArray()
        coEvery { apiClient.updatePrivateData(any()) } returns buildJsonObject {}
        mockEngineConstructor(flowComplete = completeFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.FlowActive(
                    userId = "user-1",
                    displayName = "Alice",
                    flowId = "flow-batch",
                    flowType = "issuance",
                    status = "in_progress",
                    credentials = emptyList(),
                )
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "keystore" to keystore,
            "sessionStore" to sessionStore,
            "apiClient" to apiClient,
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        completeFlow.emit(
            FlowCompleteMessage(
                flowId = "flow-batch",
                credentials = listOf(
                    CredentialResult(format = "dc+sd-jwt", credential = cred),
                    CredentialResult(format = "dc+sd-jwt", credential = cred),
                    CredentialResult(format = "dc+sd-jwt", credential = cred),
                ),
            )
        )
        advanceUntilIdle()

        val stored = store.getAll()
        assertEquals(3, stored.size)
        val batchId = stored.first().batchId
        assertNotNull(batchId)
        assertTrue(stored.all { it.batchId == batchId })
        assertEquals(listOf(0, 1, 2), stored.map { it.instanceId })
    }

    @Test
    fun connectEngine_flowComplete_assignsPerInstanceKid_fromAttestedKeyIds_forBatchIssuance() = runTest(dispatcher) {
        // Regression test for the wrong-key-signing bug: a batch issuance
        // where each instance is bound to its own device key (e.g. an
        // OID4VCI issuer minting credential N from attested_keys[N], see
        // SirosWallet.activeAttestedKeyIds's doc comment) must record which
        // key each STORED credential actually uses - not just its position
        // in the batch. Directly injects activeAttestedKeyIds (the
        // generate_proof -> attestedKeyIds wiring itself is covered by
        // connectEngine_signRequest_usesBackendKeyAttestation_whenAvailable)
        // to isolate testing that flowComplete correctly consumes it.
        val cred = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjk5OTk5OTk5OTl9."
        val completeFlow = MutableSharedFlow<FlowCompleteMessage>()
        val store = FakeCredentialStore(mutableListOf())
        val keystore = mockk<KeystoreManager>()
        val sessionStore = mockk<SessionStore>(relaxed = true)
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        var privateDataJwe: String? = null
        every { keystore.isUnlocked } returns true
        every { sessionStore.privateDataJwe } answers { privateDataJwe }
        every { sessionStore.privateDataJwe = any() } answers { privateDataJwe = firstArg() }
        coEvery { keystore.exportEncryptedContainer() } returns """{"prfKeys":[],"jwe":"updated-jwe"}""".toByteArray()
        coEvery { apiClient.updatePrivateData(any()) } returns buildJsonObject {}
        mockEngineConstructor(flowComplete = completeFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.FlowActive(
                    userId = "user-1",
                    displayName = "Alice",
                    flowId = "flow-batch-keys",
                    flowType = "issuance",
                    status = "in_progress",
                    credentials = emptyList(),
                )
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "keystore" to keystore,
            "sessionStore" to sessionStore,
            "apiClient" to apiClient,
            "activeAttestedKeyIds" to listOf("key-a", "key-b", "key-c"),
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        completeFlow.emit(
            FlowCompleteMessage(
                flowId = "flow-batch-keys",
                credentials = listOf(
                    CredentialResult(format = "dc+sd-jwt", credential = cred),
                    CredentialResult(format = "dc+sd-jwt", credential = cred),
                    CredentialResult(format = "dc+sd-jwt", credential = cred),
                ),
            )
        )
        advanceUntilIdle()

        val stored = store.getAll().sortedBy { it.instanceId }
        assertEquals(3, stored.size)
        assertEquals(listOf("key-a", "key-b", "key-c"), stored.map { it.kid })
    }

    @Test
    fun connectEngine_flowComplete_assignsBatchIdAndZeroInstanceId_forSingleCredentialIssuance() = runTest(dispatcher) {
        // Minimal valid JWT: {"alg":"none"}.{"sub":"test","iat":1700000000,"exp":9999999999}.
        val cred = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjk5OTk5OTk5OTl9."
        val completeFlow = MutableSharedFlow<FlowCompleteMessage>()
        val store = FakeCredentialStore(mutableListOf())
        val keystore = mockk<KeystoreManager>()
        val sessionStore = mockk<SessionStore>(relaxed = true)
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        var privateDataJwe: String? = null
        every { keystore.isUnlocked } returns true
        every { sessionStore.privateDataJwe } answers { privateDataJwe }
        every { sessionStore.privateDataJwe = any() } answers { privateDataJwe = firstArg() }
        coEvery { keystore.exportEncryptedContainer() } returns """{"prfKeys":[],"jwe":"updated-jwe"}""".toByteArray()
        coEvery { apiClient.updatePrivateData(any()) } returns buildJsonObject {}
        mockEngineConstructor(flowComplete = completeFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.FlowActive(
                    userId = "user-1",
                    displayName = "Alice",
                    flowId = "flow-single",
                    flowType = "issuance",
                    status = "in_progress",
                    credentials = emptyList(),
                )
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "keystore" to keystore,
            "sessionStore" to sessionStore,
            "apiClient" to apiClient,
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        completeFlow.emit(
            FlowCompleteMessage(
                flowId = "flow-single",
                credentials = listOf(CredentialResult(format = "dc+sd-jwt", credential = cred)),
            )
        )
        advanceUntilIdle()

        val stored = store.getAll()
        assertEquals(1, stored.size)
        // Every issuance response - batch of one or many - gets its own
        // batchId (matching wallet-frontend's Date.now()-per-issuance model,
        // see StoredCredential.batchId's KDoc); a single credential is
        // simply a batch of one, always instanceId 0.
        assertNotNull(stored.single().batchId)
        assertEquals(0, stored.single().instanceId)
    }

    @Test
    fun connectEngine_flowComplete_sends_credential_notification_when_notification_id_present() = runTest(dispatcher) {
        // Minimal valid JWT: {"alg":"none"}.{"sub":"test","iat":1700000000,"exp":9999999999}.
        val testCredential = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjk5OTk5OTk5OTl9."
        val completeFlow = MutableSharedFlow<FlowCompleteMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val store = FakeCredentialStore(mutableListOf())
        val keystore = mockk<KeystoreManager>()
        val sessionStore = mockk<SessionStore>(relaxed = true)
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        var privateDataJwe: String? = null
        every { keystore.isUnlocked } returns true
        every { sessionStore.privateDataJwe } answers { privateDataJwe }
        every { sessionStore.privateDataJwe = any() } answers { privateDataJwe = firstArg() }
        coEvery { keystore.exportEncryptedContainer() } returns """{"prfKeys":[],"jwe":"updated-jwe"}""".toByteArray()
        coEvery { apiClient.updatePrivateData(any()) } returns buildJsonObject {}
        val engine = mockEngineConstructor(flowComplete = completeFlow)
        every {
            engine.sendCredentialNotification(any(), any(), any(), any())
        } just runs
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.FlowActive(
                    userId = "user-1",
                    displayName = "Alice",
                    flowId = "flow-notify",
                    flowType = "issuance",
                    status = "in_progress",
                    credentials = emptyList(),
                )
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "keystore" to keystore,
            "sessionStore" to sessionStore,
            "apiClient" to apiClient,
            "eventListener" to listener,
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        completeFlow.emit(
            FlowCompleteMessage(
                flowId = "flow-notify",
                credentials = listOf(
                    CredentialResult(
                        format = "dc+sd-jwt",
                        credential = testCredential,
                        notificationId = "notif-xyz",
                    )
                ),
            )
        )
        advanceUntilIdle()

        verify(exactly = 1) {
            engine.sendCredentialNotification(
                flowId = "flow-notify",
                notificationId = "notif-xyz",
                event = CredentialNotificationEvent.ACCEPTED,
            )
        }
        // The stored credential retains the issuer's notification_id.
        assertEquals("notif-xyz", store.let { runBlocking { it.getAll() }.single().notificationId })
    }

    @Test
    fun connectEngine_flowComplete_omits_credential_notification_without_notification_id() = runTest(dispatcher) {
        val testCredential = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjk5OTk5OTk5OTl9."
        val completeFlow = MutableSharedFlow<FlowCompleteMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val store = FakeCredentialStore(mutableListOf())
        val keystore = mockk<KeystoreManager>()
        val sessionStore = mockk<SessionStore>(relaxed = true)
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        var privateDataJwe: String? = null
        every { keystore.isUnlocked } returns true
        every { sessionStore.privateDataJwe } answers { privateDataJwe }
        every { sessionStore.privateDataJwe = any() } answers { privateDataJwe = firstArg() }
        coEvery { keystore.exportEncryptedContainer() } returns """{"prfKeys":[],"jwe":"updated-jwe"}""".toByteArray()
        coEvery { apiClient.updatePrivateData(any()) } returns buildJsonObject {}
        val engine = mockEngineConstructor(flowComplete = completeFlow)
        every {
            engine.sendCredentialNotification(any(), any(), any(), any())
        } just runs
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.FlowActive(
                    userId = "user-1",
                    displayName = "Alice",
                    flowId = "flow-plain",
                    flowType = "issuance",
                    status = "in_progress",
                    credentials = emptyList(),
                )
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "keystore" to keystore,
            "sessionStore" to sessionStore,
            "apiClient" to apiClient,
            "eventListener" to listener,
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        completeFlow.emit(
            FlowCompleteMessage(
                flowId = "flow-plain",
                credentials = listOf(
                    CredentialResult(format = "dc+sd-jwt", credential = testCredential)
                ),
            )
        )
        advanceUntilIdle()

        verify(exactly = 0) {
            engine.sendCredentialNotification(any(), any(), any(), any())
        }
    }

    @Test
    fun connectEngine_flowError_notifies_listener_and_returns_ready() = runTest(dispatcher) {
        val errorFlow = MutableSharedFlow<FlowErrorMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val store = FakeCredentialStore(mutableListOf())
        mockEngineConstructor(flowErrors = errorFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.FlowActive(
                    userId = "user-1",
                    displayName = "Alice",
                    flowId = "flow-error",
                    flowType = "presentation",
                    status = "in_progress",
                    credentials = emptyList(),
                )
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "eventListener" to listener,
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        errorFlow.emit(
            FlowErrorMessage(
                flowId = "flow-error",
                error = FlowError(code = "bad_request", message = "presentation denied"),
            )
        )
        advanceUntilIdle()

        verify(exactly = 1) { listener.onFlowError("flow-error", "presentation denied") }
        assertEquals(
            WalletState.Ready(userId = "user-1", displayName = "Alice", credentials = emptyList()),
            wallet.state.value,
        )
    }

    @Test
    fun connectEngine_signRequest_generates_proof_and_sends_response() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val keystore = mockk<KeystoreManager>()
        coEvery { keystore.generateProof(audience = "aud-1", nonce = "nonce-1") } returns "proof-jwt"
        val engine = mockEngineConstructor(signRequests = signFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to keystore,
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(audience = "aud-1", nonce = "nonce-1"),
            )
        )
        advanceUntilIdle()

        coVerify(exactly = 1) { keystore.generateProof(audience = "aud-1", nonce = "nonce-1") }
        verify(exactly = 1) {
            engine.sendSignResponse(
                "flow-sign",
                proofs = listOf(ProofObject(proofType = "jwt", jwt = "proof-jwt")),
                messageId = null,
            )
        }
    }

    @Test
    fun connectEngine_signRequest_generates_attestation_proof_when_jwt_not_supported() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val keystore = mockk<KeystoreManager>()
        coEvery { keystore.generateKeyAttestation(nonce = "nonce-1", count = 5) } returns "attestation-jwt"
        val engine = mockEngineConstructor(signRequests = signFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to keystore,
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(
                    audience = "aud-1",
                    nonce = "nonce-1",
                    count = 5,
                    proofTypesSupported = buildJsonObject { putJsonObject("attestation") {} },
                ),
            )
        )
        advanceUntilIdle()

        // A real external mdoc issuer (this test's motivating case) lists
        // only "attestation" in proof_types_supported - the wallet MUST NOT
        // fall back to jwt (go-wallet-backend rejects with "unsupported
        // proof type" if it does), and must produce exactly ONE proof
        // covering the whole batch, not one per credential.
        coVerify(exactly = 1) { keystore.generateKeyAttestation(nonce = "nonce-1", count = 5) }
        coVerify(exactly = 0) { keystore.generateProof(any(), any(), any()) }
        verify(exactly = 1) {
            engine.sendSignResponse(
                "flow-sign",
                proofs = listOf(ProofObject(proofType = "attestation", attestation = "attestation-jwt")),
                messageId = null,
            )
        }
    }

    @Test
    fun connectEngine_signRequest_usesBackendKeyAttestation_whenAvailable() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val keystore = mockk<KeystoreManager>()
        val keypairs = listOf(
            KeypairInfo(keyId = "key-1", publicKeyJWK = buildJsonObject { put("kty", "EC") }),
            KeypairInfo(keyId = "key-2", publicKeyJWK = buildJsonObject { put("kty", "EC") }),
        )
        coEvery { keystore.generateKeypairs(2) } returns keypairs
        val securityProps = SignerSecurityProperties(keyStorage = listOf("iso_18045_high"))
        coEvery { keystore.securityProperties("key-1") } returns securityProps
        val apiClient = mockk<BackendApiClient>()
        coEvery {
            apiClient.requestKeyAttestation(
                jwks = keypairs.map { it.publicKeyJWK },
                nonce = "nonce-1",
                securityProperties = securityProps,
                credentialIssuer = "aud-1",
            )
        } returns "backend-signed-attestation-jwt"
        val engine = mockEngineConstructor(signRequests = signFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to keystore,
        )

        invokeConnectEngine(wallet, "app-token")
        // connectEngine builds its own real BackendApiClient - swap in the
        // mock afterward so the backend Key Attestation call is exercised
        // without an actual network round trip.
        setField(wallet, "apiClient", apiClient)
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(
                    audience = "aud-1",
                    nonce = "nonce-1",
                    count = 2,
                    proofTypesSupported = buildJsonObject { putJsonObject("attestation") {} },
                ),
            )
        )
        advanceUntilIdle()

        // Backend-signed attestation (real x5c trust anchor) must be
        // preferred over the self-signed fallback when a session is active
        // and the backend supports the endpoint.
        coVerify(exactly = 0) { keystore.generateKeyAttestation(any(), any()) }
        verify(exactly = 1) {
            engine.sendSignResponse(
                "flow-sign",
                proofs = listOf(ProofObject(proofType = "attestation", attestation = "backend-signed-attestation-jwt")),
                messageId = null,
            )
        }
    }

    @Test
    fun currentWalletInstanceId_returnsJkt_whenWiaIsNativeAttested() = runTest(dispatcher) {
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
        )
        setField(
            wallet,
            "cachedWia",
            fakeWiaJwt(System.currentTimeMillis() / 1000 + 3600, jkt = "test-jkt", attestationSource = "ios_app_attest"),
        )
        setField(wallet, "cachedWiaExpiresAt", System.currentTimeMillis() / 1000 + 3600)

        assertEquals("test-jkt", invokeCurrentWalletInstanceId(wallet))
    }

    @Test
    fun currentWalletInstanceId_returnsNull_whenWiaIsNotNativeAttested() = runTest(dispatcher) {
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
        )
        // WIA exists but was never verified as native platform attestation -
        // the backend's KA trust gate wouldn't lift the clamp for it anyway,
        // so walletInstanceId must stay omitted.
        setField(
            wallet,
            "cachedWia",
            fakeWiaJwt(System.currentTimeMillis() / 1000 + 3600, jkt = "test-jkt", attestationSource = "backend_attested"),
        )
        setField(wallet, "cachedWiaExpiresAt", System.currentTimeMillis() / 1000 + 3600)

        assertEquals(null, invokeCurrentWalletInstanceId(wallet))
    }

    @Test
    fun currentWalletInstanceId_returnsNull_whenNoWiaAvailable() = runTest(dispatcher) {
        // No cachedWia seeded - currentWalletInstanceId() peeks the cache
        // only (it must never trigger a WIA fetch of its own), so this must
        // resolve to null without any backend interaction at all.
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
        )

        assertEquals(null, invokeCurrentWalletInstanceId(wallet))
    }

    @Test
    fun requestBackendKeyAttestation_includesWalletInstanceId_whenWiaIsNativeAttested() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val keystore = mockk<KeystoreManager>()
        val keypairs = listOf(KeypairInfo(keyId = "key-1", publicKeyJWK = buildJsonObject { put("kty", "EC") }))
        coEvery { keystore.generateKeypairs(1) } returns keypairs
        val securityProps = SignerSecurityProperties(keyStorage = listOf("iso_18045_high"))
        coEvery { keystore.securityProperties("key-1") } returns securityProps
        val apiClient = mockk<BackendApiClient>()
        coEvery {
            apiClient.requestKeyAttestation(
                jwks = keypairs.map { it.publicKeyJWK },
                nonce = "nonce-1",
                securityProperties = securityProps,
                credentialIssuer = "aud-1",
                walletInstanceId = "test-jkt",
            )
        } returns "backend-signed-attestation-jwt"
        val engine = mockEngineConstructor(signRequests = signFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to keystore,
        )

        invokeConnectEngine(wallet, "app-token")
        setField(wallet, "apiClient", apiClient)
        setField(wallet, "cachedWia", fakeWiaJwt(System.currentTimeMillis() / 1000 + 3600, jkt = "test-jkt", attestationSource = "ios_app_attest"))
        setField(wallet, "cachedWiaExpiresAt", System.currentTimeMillis() / 1000 + 3600)
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(
                    audience = "aud-1",
                    nonce = "nonce-1",
                    count = 1,
                    proofTypesSupported = buildJsonObject { putJsonObject("attestation") {} },
                ),
            )
        )
        advanceUntilIdle()

        verify(exactly = 1) {
            engine.sendSignResponse(
                "flow-sign",
                proofs = listOf(ProofObject(proofType = "attestation", attestation = "backend-signed-attestation-jwt")),
                messageId = null,
            )
        }
    }

    @Test
    fun connectEngine_signRequest_fallsBackToSelfSignedAttestation_whenBackendCallFails() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val keystore = mockk<KeystoreManager>()
        coEvery { keystore.generateKeypairs(any()) } throws IllegalStateException("backend session expired")
        coEvery { keystore.generateKeyAttestation(nonce = "nonce-1", count = 3) } returns "self-signed-attestation-jwt"
        val engine = mockEngineConstructor(signRequests = signFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to keystore,
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(
                    audience = "aud-1",
                    nonce = "nonce-1",
                    count = 3,
                    proofTypesSupported = buildJsonObject { putJsonObject("attestation") {} },
                ),
            )
        )
        advanceUntilIdle()

        // A failed backend attempt (offline wallet-provider, older backend,
        // network error) must not surface as a hard failure - it degrades to
        // the self-signed path, same as every other backend-optional flow.
        verify(exactly = 1) {
            engine.sendSignResponse(
                "flow-sign",
                proofs = listOf(ProofObject(proofType = "attestation", attestation = "self-signed-attestation-jwt")),
                messageId = null,
            )
        }
    }

    @Test
    fun connectEngine_signRequest_prefers_jwt_when_both_proof_types_supported() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val keystore = mockk<KeystoreManager>()
        coEvery { keystore.generateProof(audience = "aud-1", nonce = "nonce-1") } returns "proof-jwt"
        val engine = mockEngineConstructor(signRequests = signFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to keystore,
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(
                    audience = "aud-1",
                    nonce = "nonce-1",
                    proofTypesSupported = buildJsonObject {
                        putJsonObject("jwt") {}
                        putJsonObject("attestation") {}
                    },
                ),
            )
        )
        advanceUntilIdle()

        // Existing issuers (ours included) that already support jwt must see
        // no behavior change from adding attestation support.
        coVerify(exactly = 1) { keystore.generateProof(audience = "aud-1", nonce = "nonce-1") }
        coVerify(exactly = 0) { keystore.generateKeyAttestation(any(), any()) }
    }

    @Test
    fun connectEngine_matchRequest_uses_listener_selection_tracks_history_and_sends_matches() = runTest(dispatcher) {
        val matchFlow = MutableSharedFlow<MatchRequestMessage>()
        val listener = mockk<WalletEventListener>()
        val store = FakeCredentialStore(
            mutableListOf(
                StoredCredential(
                    id = 1L,
                    format = "dc+sd-jwt",
                    raw = "raw-1",
                    metadata = CredentialMetadata(name = "Credential One", vct = "urn:example:vct"),
                    batchId = 1L,
                    instanceId = 0,
                ),
                StoredCredential(
                    id = 2L,
                    format = "dc+sd-jwt",
                    raw = "raw-2",
                    metadata = CredentialMetadata(name = "Credential Two", vct = "urn:example:vct"),
                    batchId = 2L,
                    instanceId = 0,
                ),
            )
        )
        val initialCredentials = store.getAll()
        coEvery { listener.onCredentialSelectionRequired(any()) } returns listOf(2L)
        val engine = mockEngineConstructor(matchRequests = matchFlow)
        val keystore = mockk<KeystoreManager>()
        every { keystore.isUnlocked } returns false
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.Ready(userId = "user-1", displayName = "Alice", credentials = initialCredentials)
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "keystore" to keystore,
            "eventListener" to listener,
            "_presentationHistory" to mutableListOf<PresentationRecord>(),
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        matchFlow.emit(MatchRequestMessage(flowId = "flow-match", dcqlQuery = null))
        advanceUntilIdle()

        coVerify(exactly = 1) {
            listener.onCredentialSelectionRequired(
                match<PresentationRequest> { request ->
                    request.candidates.map { it.id } == listOf(1L, 2L)
                },
            )
        }
        verify(exactly = 1) {
            engine.sendMatchResponse(
                "flow-match",
                match<List<CredentialMatch>> { matches ->
                    matches.size == 1 &&
                        matches.single().credentialQueryId == "_default" &&
                        matches.single().credentialId == "2" &&
                        matches.single().format == "dc+sd-jwt" &&
                        matches.single().vct == "urn:example:vct"
                },
            )
        }
        assertEquals(1, wallet.presentationHistory.size)
        assertEquals(listOf(2L), wallet.presentationHistory.single().credentialIds)
        assertEquals(listOf("Credential Two"), wallet.presentationHistory.single().credentialNames)
    }

    // ── DC API (Digital Credentials API) ─────────────────────────────

    @Test
    fun handleDCAPIRequest_unsignedRequest_signsSdJwtAndReturnsUnencryptedVpToken() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } returns buildJsonObject { put("decision", true) }
        val keystore = mockk<KeystoreManager>()
        every { keystore.isUnlocked } returns false
        coEvery { keystore.signVpToken(any(), any(), any(), any()) } returns "signed-vp-token"
        val store = FakeCredentialStore(mutableListOf(
            StoredCredential(
                id = 1L,
                format = "dc+sd-jwt",
                raw = "issuer.payload.sig~disclosure~",
                metadata = CredentialMetadata(name = "Diploma", vct = "urn:example:vct"),
                batchId = 1L,
                instanceId = 0,
            ),
        ))
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "keystore" to keystore,
            "credentialStore" to store,
            "trustCache" to TrustCache(),
            "_presentationHistory" to mutableListOf<PresentationRecord>(),
        )

        val requestJson = wrapDCAPIRequest("openid4vp-v1-unsigned", buildJsonObject {
            put("response_type", "vp_token")
            put("nonce", "dc-nonce-1")
            put("response_mode", "dc_api")
            putJsonObject("dcql_query") {
                putJsonArray("credentials") {
                    add(buildJsonObject {
                        put("id", "query1")
                        put("format", "dc+sd-jwt")
                    })
                }
            }
        })

        val result = wallet.handleDCAPIRequest(requestJson, origin = "https://relying-party.example")

        coVerify(exactly = 1) {
            keystore.signVpToken(
                credential = "issuer.payload.sig~disclosure~",
                disclosedClaims = any(),
                nonce = "dc-nonce-1",
                audience = "origin:https://relying-party.example",
            )
        }
        assertEquals(listOf(1L), result.credentialIds)
        val parsed = Json.parseToJsonElement(result.responseJson).jsonObject
        assertEquals("openid4vp-v1-unsigned", parsed["protocol"]?.jsonPrimitive?.content)
        val data = parsed["data"]?.jsonObject
        assertEquals("signed-vp-token", data?.get("vp_token")?.jsonObject?.get("query1")?.jsonPrimitive?.content)
        assertEquals(1, wallet.presentationHistory.size)
    }

    @Test
    fun handleDCAPIRequest_mdocCredential_usesSignMdocPresentationForDCAPI() = runTest(dispatcher) {
        // Production code decodes cred.raw via android.util.Base64 before
        // calling the keystore - the Android SDK stub jar throws on any real
        // call in a plain (non-Robolectric) JUnit test, so it must be
        // statically mocked here even though the decoded bytes themselves
        // are irrelevant (the keystore call itself is mocked below).
        io.mockk.mockkStatic(android.util.Base64::class)
        every { android.util.Base64.decode(any<String>(), any()) } returns "fake-cbor".toByteArray()
        every { android.util.Base64.encodeToString(any(), any()) } returns "ZGV2aWNlLXJlc3BvbnNl"
        try {
            val apiClient = mockk<BackendApiClient>()
            coEvery { apiClient.evaluateTrust(any()) } returns buildJsonObject { put("decision", true) }
            val keystore = mockk<KeystoreManager>()
            every { keystore.isUnlocked } returns false
            coEvery {
                keystore.signMdocPresentationForDCAPI(any(), any(), any(), any(), any())
            } returns "device-response".toByteArray()
            val store = FakeCredentialStore(mutableListOf(
                StoredCredential(
                    id = 1L,
                    format = "mso_mdoc",
                    raw = "ZmFrZS1jYm9y",
                    metadata = CredentialMetadata(name = "mDL", doctype = "org.iso.18013.5.1.mDL"),
                    batchId = 1L,
                    instanceId = 0,
                ),
            ))
            val wallet = newWallet(
                "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "Alice")),
                "scope" to CoroutineScope(dispatcher + SupervisorJob()),
                "apiClient" to apiClient,
                "keystore" to keystore,
                "credentialStore" to store,
                "trustCache" to TrustCache(),
                "_presentationHistory" to mutableListOf<PresentationRecord>(),
            )

            val requestJson = wrapDCAPIRequest("openid4vp-v1-unsigned", buildJsonObject {
                put("nonce", "dc-nonce-mdl")
                put("response_mode", "dc_api")
            })

            wallet.handleDCAPIRequest(requestJson, origin = "https://relying-party.example")

            coVerify(exactly = 1) {
                keystore.signMdocPresentationForDCAPI(
                    credentialBytes = any(),
                    disclosedClaims = any(),
                    nonce = "dc-nonce-mdl",
                    origin = "https://relying-party.example",
                    encryptionPublicJwkThumbprint = null,
                )
            }
        } finally {
            io.mockk.unmockkStatic(android.util.Base64::class)
        }
    }

    @Test
    fun handleDCAPIRequest_noMatchingCredential_throwsWalletException() = runTest(dispatcher) {
        // Selection/consent for DC API happens natively via the OS's own
        // credential picker before this Activity/call is ever reached - so
        // there's no in-app "decline" path to test here (see
        // handleDCAPIRequest's doc comment on why it no longer routes
        // through eventListener.onCredentialSelectionRequired). The
        // analogous failure is simply no matching credential in the wallet.
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } returns buildJsonObject { put("decision", true) }
        val store = FakeCredentialStore(mutableListOf())
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "keystore" to mockk<KeystoreManager>(relaxed = true),
            "credentialStore" to store,
            "trustCache" to TrustCache(),
            "_presentationHistory" to mutableListOf<PresentationRecord>(),
        )

        var thrown: Throwable? = null
        try {
            wallet.handleDCAPIRequest(
                wrapDCAPIRequest("openid4vp-v1-unsigned", buildJsonObject { put("nonce", "n") }),
                origin = "https://relying-party.example",
            )
        } catch (e: Throwable) {
            thrown = e
        }
        assertTrue(thrown is WalletException)
    }

    @Test
    fun handleDCAPIRequest_dcApiJwtResponseMode_encryptsResponse() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } returns buildJsonObject { put("decision", true) }
        val keystore = mockk<KeystoreManager>()
        every { keystore.isUnlocked } returns false
        coEvery { keystore.signVpToken(any(), any(), any(), any()) } returns "signed-vp-token"
        val store = FakeCredentialStore(mutableListOf(
            StoredCredential(id = 1L, format = "dc+sd-jwt", raw = "raw", metadata = CredentialMetadata(name = "X"), batchId = 1L, instanceId = 0),
        ))
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "keystore" to keystore,
            "credentialStore" to store,
            "trustCache" to TrustCache(),
            "_presentationHistory" to mutableListOf<PresentationRecord>(),
        )

        val verifierEncKey = ECKeyGenerator(Curve.P_256)
            .keyID("enc-1")
            .keyUse(com.nimbusds.jose.jwk.KeyUse.ENCRYPTION)
            .generate()
        val requestJson = wrapDCAPIRequest("openid4vp-v1-unsigned", buildJsonObject {
            put("nonce", "dc-nonce-2")
            put("state", "verifier-session-state")
            put("response_mode", "dc_api.jwt")
            putJsonObject("client_metadata") {
                putJsonObject("jwks") {
                    putJsonArray("keys") {
                        add(Json.parseToJsonElement(
                            verifierEncKey.toPublicJWK().toJSONString()
                        ))
                    }
                }
            }
        })

        val result = wallet.handleDCAPIRequest(requestJson, origin = "https://relying-party.example")

        val parsed = Json.parseToJsonElement(result.responseJson).jsonObject
        val jwe = parsed["data"]?.jsonObject?.get("response")?.jsonPrimitive?.content
        assertTrue("response must be a JWE, not a plain vp_token", jwe != null)
        val jweObject = JWEObject.parse(jwe)
        // The JWE header must carry the verifier's own kid so it can find
        // the matching ephemeral private key to decrypt with (a real bug:
        // this used to be omitted entirely).
        assertEquals("enc-1", jweObject.header.keyID)
        jweObject.decrypt(ECDHDecrypter(verifierEncKey))
        val decrypted = Json.parseToJsonElement(jweObject.payload.toString()).jsonObject
        assertEquals("signed-vp-token", decrypted["vp_token"]?.jsonObject?.get("_default")?.jsonPrimitive?.contentOrNull)
        // The verifier's ONLY means of correlating this response to a
        // session - omitting it was a real bug ("state: missing or empty").
        assertEquals("verifier-session-state", decrypted["state"]?.jsonPrimitive?.contentOrNull)
    }

    @Test
    fun handleDCAPIRequest_signedRequest_verifiesJwsAndUsesPayloadFields() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } returns buildJsonObject { put("decision", true) }
        val keystore = mockk<KeystoreManager>()
        every { keystore.isUnlocked } returns false
        coEvery { keystore.signVpToken(any(), any(), any(), any()) } returns "signed-vp-token"
        val store = FakeCredentialStore(mutableListOf(
            StoredCredential(id = 1L, format = "dc+sd-jwt", raw = "raw", metadata = CredentialMetadata(name = "X"), batchId = 1L, instanceId = 0),
        ))
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "keystore" to keystore,
            "credentialStore" to store,
            "trustCache" to TrustCache(),
            "_presentationHistory" to mutableListOf<PresentationRecord>(),
        )

        val verifierSigningKey = ECKeyGenerator(Curve.P_256).keyID("verifier-key-1").generate()
        val header = JWSHeader.Builder(JWSAlgorithm.ES256).jwk(verifierSigningKey.toPublicJWK()).build()
        val claims = JWTClaimsSet.Builder()
            .claim("client_id", "https://relying-party.example")
            .claim("nonce", "dc-nonce-signed")
            .claim("response_mode", "dc_api")
            .build()
        val signedJwt = SignedJWT(header, claims)
        signedJwt.sign(ECDSASigner(verifierSigningKey))

        val requestJson = wrapDCAPIRequest("openid4vp-v1-signed", buildJsonObject { put("request", signedJwt.serialize()) })

        wallet.handleDCAPIRequest(requestJson, origin = "https://relying-party.example")

        coVerify(exactly = 1) {
            keystore.signVpToken(any(), any(), nonce = "dc-nonce-signed", audience = "origin:https://relying-party.example")
        }
        // Trust evaluation must have used the JAR's own client_id (from its
        // verified payload), not the bare origin, since a signed request DOES
        // assert an explicit client_id.
        coVerify(exactly = 1) {
            apiClient.evaluateTrust(match { it["subject"]?.jsonObject?.get("id")?.jsonPrimitive?.content == "https://relying-party.example" })
        }
    }

    @Test
    fun handleDCAPIRequest_signedRequestWithTamperedSignature_throws() = runTest(dispatcher) {
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
        )

        val legitKey = ECKeyGenerator(Curve.P_256).keyID("legit").generate()
        val attackerKey = ECKeyGenerator(Curve.P_256).keyID("attacker").generate()
        // Header advertises the legitimate key, but the JWT is actually
        // signed by a different (attacker-controlled) key - signature
        // verification against the advertised key must fail.
        val header = JWSHeader.Builder(JWSAlgorithm.ES256).jwk(legitKey.toPublicJWK()).build()
        val claims = JWTClaimsSet.Builder().claim("nonce", "n").build()
        val signedJwt = SignedJWT(header, claims)
        signedJwt.sign(ECDSASigner(attackerKey))

        var thrown: Throwable? = null
        try {
            wallet.handleDCAPIRequest(
                wrapDCAPIRequest("openid4vp-v1-signed", buildJsonObject { put("request", signedJwt.serialize()) }),
                origin = "https://relying-party.example",
            )
        } catch (e: Throwable) {
            thrown = e
        }
        assertTrue(thrown is org.siros.sdk.wallet.dcapi.DCAPIRequestException)
    }

    /**
     * Wraps a request's `data` object in the envelope
     * [org.siros.sdk.wallet.dcapi.DCAPIRequestParser.parse] actually expects
     * from [androidx.credentials.GetDigitalCredentialOption.requestJson] -
     * `{"requests": [{"protocol": ..., "data": {...}}]}`, not the bare
     * `data` object on its own (see that parser's fix for why).
     */
    private fun wrapDCAPIRequest(protocol: String, data: JsonObject): String = buildJsonObject {
        putJsonArray("requests") {
            add(buildJsonObject {
                put("protocol", protocol)
                put("data", data)
            })
        }
    }.toString()

    private fun newWallet(vararg fields: Pair<String, Any?>): SirosWallet {
        val wallet = allocateInstance(SirosWallet::class.java) as SirosWallet
        val values = fields.toMap(mutableMapOf())
        val stateFlow = values["_state"] as? MutableStateFlow<WalletState>
        if (stateFlow != null && "state" !in values) {
            values["state"] = stateFlow.asStateFlow()
        }
        if ("terminatedFlowIds" !in values) {
            values["terminatedFlowIds"] = mutableSetOf<String>()
        }
        // allocateInstance bypasses property initializers entirely, so
        // credentialConsumptionPolicy's default (NEVER_CONSUME) never runs
        // unless set here explicitly - matches every existing test's
        // expectation of today's actual (pre-this-feature) behavior.
        if ("credentialConsumptionPolicy" !in values) {
            values["credentialConsumptionPolicy"] = CredentialConsumptionPolicy.NEVER_CONSUME
        }
        values.forEach { (name, value) -> setField(wallet, name, value) }
        return wallet
    }

    private fun setField(target: Any, fieldName: String, value: Any?) {
        val field = target.javaClass.getDeclaredField(fieldName)
        field.isAccessible = true
        field.set(target, value)
    }

    private fun getField(target: Any, fieldName: String): Any? {
        val field = target.javaClass.getDeclaredField(fieldName)
        field.isAccessible = true
        return field.get(target)
    }

    private fun invokeHandleTrustEvaluation(
        wallet: SirosWallet,
        engine: WalletEngineSession,
        flowId: String,
        payload: JsonObject,
    ) {
        val method = wallet.javaClass.getDeclaredMethod(
            "handleTrustEvaluation",
            WalletEngineSession::class.java,
            String::class.java,
            JsonObject::class.java,
        )
        method.isAccessible = true
        method.invoke(wallet, engine, flowId, payload)
    }

    private fun invokeCurrentWalletInstanceId(wallet: SirosWallet): String? {
        val method = wallet::class.declaredMemberFunctions.first { it.name == "currentWalletInstanceId" }
        method.isAccessible = true
        return method.call(wallet) as String?
    }

    private fun invokeConnectEngine(wallet: SirosWallet, appToken: String) {
        // connectEngine is a private suspend fun — use Kotlin reflection's callSuspend
        val method = wallet::class.declaredMemberFunctions.first { it.name == "connectEngine" }
        method.isAccessible = true
        kotlinx.coroutines.runBlocking {
            method.callSuspend(wallet, appToken)
        }
    }

    private fun mockEngineConstructor(
        signRequests: MutableSharedFlow<SignRequestMessage> = MutableSharedFlow(),
        matchRequests: MutableSharedFlow<MatchRequestMessage> = MutableSharedFlow(),
        progressFlow: MutableSharedFlow<FlowProgressMessage> = MutableSharedFlow(),
        flowComplete: MutableSharedFlow<FlowCompleteMessage> = MutableSharedFlow(),
        flowErrors: MutableSharedFlow<FlowErrorMessage> = MutableSharedFlow(),
    ): WalletEngineSession {
        val engine = mockk<WalletEngineSession>()
        every { engine.connect(any(), any()) } just runs
        coEvery { engine.awaitConnected(any()) } just runs
        coEvery { engine.forceReconnect() } just runs
        every { engine.state } returns MutableStateFlow(WalletEngineSession.State.CONNECTED)
        every { engine.sendSignResponse(any(), any(), any(), any()) } just runs
        every { engine.sendMatchResponse(any(), any()) } just runs
        every { engine.signRequests() } returns signRequests
        every { engine.matchRequests() } returns matchRequests
        every { engine.flowProgress() } returns progressFlow
        every { engine.flowComplete() } returns flowComplete
        every { engine.flowErrors() } returns flowErrors
        SirosWallet.createEngineSession = { _, _ -> engine }
        return engine
    }

    private fun allocateInstance(clazz: Class<*>): Any {
        val unsafeClass = Class.forName("sun.misc.Unsafe")
        val unsafeField = unsafeClass.getDeclaredField("theUnsafe")
        unsafeField.isAccessible = true
        val unsafe = unsafeField.get(null)
        val allocateInstance = unsafeClass.getMethod("allocateInstance", Class::class.java)
        return allocateInstance.invoke(unsafe, clazz)
    }

    private class FakeCredentialStore(
        private val credentials: MutableList<StoredCredential>,
    ) : CredentialStore {
        override suspend fun getAll(): List<StoredCredential> = credentials.toList()

        override suspend fun getById(id: Long): StoredCredential? = credentials.find { it.id == id }

        override suspend fun save(credential: StoredCredential) {
            credentials.removeAll { it.id == credential.id }
            credentials.add(credential)
        }

        override suspend fun update(credential: StoredCredential) {
            save(credential)
        }

        override suspend fun delete(id: Long) {
            credentials.removeAll { it.id == id }
        }

        override suspend fun clear() {
            credentials.clear()
        }
    }

    companion object
}
