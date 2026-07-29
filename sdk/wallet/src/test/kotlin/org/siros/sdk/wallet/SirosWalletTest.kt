package org.siros.sdk.wallet

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.runs
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
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.siros.sdk.auth.BackendApiClient
import org.siros.sdk.credentials.CredentialMetadata
import org.siros.sdk.credentials.CredentialStore
import org.siros.sdk.credentials.PresentationRecord
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.credentials.WalletException
import org.siros.sdk.keystore.KeystoreManager
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
            id = "cred-2",
            format = "dc+sd-jwt",
            raw = "raw-2",
            metadata = CredentialMetadata(name = "Credential Two"),
        )
        val store = FakeCredentialStore(
            mutableListOf(
                StoredCredential(id = "cred-1", format = "dc+sd-jwt", raw = "raw-1"),
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

        wallet.deleteCredential("cred-1")

        val state = wallet.state.value as WalletState.Ready
        assertEquals(listOf("cred-2"), state.credentials.map { it.id })
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

        wallet.deleteCredential("missing")

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
        verify(exactly = 1) { engine.connect("app-token") }
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
        every { engine.forceReconnect() } just runs
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

        verify(exactly = 1) { engine.forceReconnect() }
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

    @Test
    fun completeAuthorization_surfaces_error_via_onFlowError_when_reconnect_fails() = runTest(dispatcher) {
        // If forcing a fresh connection fails outright, the failure must be visible to
        // the app immediately (onFlowError) rather than leaving it stuck showing
        // whatever UI state was current when completeAuthorization was called.
        val progressFlow = MutableSharedFlow<FlowProgressMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val store = FakeCredentialStore(mutableListOf())
        val engine = mockEngineConstructor(progressFlow = progressFlow)
        every { engine.forceReconnect() } throws IllegalStateException("Engine WebSocket connection failed")
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
                    id = "cred-1",
                    format = "dc+sd-jwt",
                    raw = "raw-1",
                    metadata = CredentialMetadata(name = "Credential One", vct = "urn:example:vct"),
                ),
                StoredCredential(
                    id = "cred-2",
                    format = "dc+sd-jwt",
                    raw = "raw-2",
                    metadata = CredentialMetadata(name = "Credential Two", vct = "urn:example:vct"),
                ),
            )
        )
        val initialCredentials = store.getAll()
        coEvery { listener.onCredentialSelectionRequired(any()) } returns listOf("cred-2")
        val engine = mockEngineConstructor(matchRequests = matchFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.Ready(userId = "user-1", displayName = "Alice", credentials = initialCredentials)
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
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
                    request.candidates.map { it.id } == listOf("cred-1", "cred-2")
                },
            )
        }
        verify(exactly = 1) {
            engine.sendMatchResponse(
                "flow-match",
                match<List<CredentialMatch>> { matches ->
                    matches.size == 1 &&
                        matches.single().credentialQueryId == "_default" &&
                        matches.single().credentialId == "cred-2" &&
                        matches.single().format == "dc+sd-jwt" &&
                        matches.single().vct == "urn:example:vct"
                },
            )
        }
        assertEquals(1, wallet.presentationHistory.size)
        assertEquals(listOf("cred-2"), wallet.presentationHistory.single().credentialIds)
        assertEquals(listOf("Credential Two"), wallet.presentationHistory.single().credentialNames)
    }

    // ── DC API (Digital Credentials API) ─────────────────────────────

    @Test
    fun handleDCAPIRequest_unsignedRequest_signsSdJwtAndReturnsUnencryptedVpToken() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } returns buildJsonObject { put("decision", true) }
        val keystore = mockk<KeystoreManager>()
        coEvery { keystore.signVpToken(any(), any(), any(), any()) } returns "signed-vp-token"
        val listener = mockk<WalletEventListener>()
        coEvery { listener.onCredentialSelectionRequired(any()) } returns listOf("cred-1")
        val store = FakeCredentialStore(mutableListOf(
            StoredCredential(
                id = "cred-1",
                format = "dc+sd-jwt",
                raw = "issuer.payload.sig~disclosure~",
                metadata = CredentialMetadata(name = "Diploma", vct = "urn:example:vct"),
            ),
        ))
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "keystore" to keystore,
            "credentialStore" to store,
            "eventListener" to listener,
            "trustCache" to TrustCache(),
            "_presentationHistory" to mutableListOf<PresentationRecord>(),
        )

        val requestJson = buildJsonObject {
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
        }.toString()

        val result = wallet.handleDCAPIRequest(requestJson, origin = "https://relying-party.example")

        coVerify(exactly = 1) {
            keystore.signVpToken(
                credential = "issuer.payload.sig~disclosure~",
                disclosedClaims = any(),
                nonce = "dc-nonce-1",
                audience = "origin:https://relying-party.example",
            )
        }
        assertEquals(listOf("cred-1"), result.credentialIds)
        val parsed = Json.parseToJsonElement(result.responseJson).jsonObject
        assertEquals("signed-vp-token", parsed["vp_token"]?.jsonObject?.get("query1")?.jsonPrimitive?.content)
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
            coEvery {
                keystore.signMdocPresentationForDCAPI(any(), any(), any(), any(), any())
            } returns "device-response".toByteArray()
            val listener = mockk<WalletEventListener>()
            coEvery { listener.onCredentialSelectionRequired(any()) } returns listOf("cred-mdl")
            val store = FakeCredentialStore(mutableListOf(
                StoredCredential(
                    id = "cred-mdl",
                    format = "mso_mdoc",
                    raw = "ZmFrZS1jYm9y",
                    metadata = CredentialMetadata(name = "mDL", doctype = "org.iso.18013.5.1.mDL"),
                ),
            ))
            val wallet = newWallet(
                "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "Alice")),
                "scope" to CoroutineScope(dispatcher + SupervisorJob()),
                "apiClient" to apiClient,
                "keystore" to keystore,
                "credentialStore" to store,
                "eventListener" to listener,
                "trustCache" to TrustCache(),
                "_presentationHistory" to mutableListOf<PresentationRecord>(),
            )

            val requestJson = buildJsonObject {
                put("nonce", "dc-nonce-mdl")
                put("response_mode", "dc_api")
            }.toString()

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
    fun handleDCAPIRequest_userDeclines_throwsWalletException() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } returns buildJsonObject { put("decision", true) }
        val listener = mockk<WalletEventListener>()
        coEvery { listener.onCredentialSelectionRequired(any()) } returns emptyList()
        val store = FakeCredentialStore(mutableListOf(
            StoredCredential(id = "cred-1", format = "dc+sd-jwt", raw = "raw", metadata = CredentialMetadata(name = "X")),
        ))
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "keystore" to mockk<KeystoreManager>(relaxed = true),
            "credentialStore" to store,
            "eventListener" to listener,
            "trustCache" to TrustCache(),
            "_presentationHistory" to mutableListOf<PresentationRecord>(),
        )

        var thrown: Throwable? = null
        try {
            wallet.handleDCAPIRequest(
                buildJsonObject { put("nonce", "n") }.toString(),
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
        coEvery { keystore.signVpToken(any(), any(), any(), any()) } returns "signed-vp-token"
        val listener = mockk<WalletEventListener>()
        coEvery { listener.onCredentialSelectionRequired(any()) } returns listOf("cred-1")
        val store = FakeCredentialStore(mutableListOf(
            StoredCredential(id = "cred-1", format = "dc+sd-jwt", raw = "raw", metadata = CredentialMetadata(name = "X")),
        ))
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "keystore" to keystore,
            "credentialStore" to store,
            "eventListener" to listener,
            "trustCache" to TrustCache(),
            "_presentationHistory" to mutableListOf<PresentationRecord>(),
        )

        val verifierEncKey = ECKeyGenerator(Curve.P_256)
            .keyID("enc-1")
            .keyUse(com.nimbusds.jose.jwk.KeyUse.ENCRYPTION)
            .generate()
        val requestJson = buildJsonObject {
            put("nonce", "dc-nonce-2")
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
        }.toString()

        val result = wallet.handleDCAPIRequest(requestJson, origin = "https://relying-party.example")

        val parsed = Json.parseToJsonElement(result.responseJson).jsonObject
        val jwe = parsed["response"]?.jsonPrimitive?.content
        assertTrue("response must be a JWE, not a plain vp_token", jwe != null)
        val jweObject = JWEObject.parse(jwe)
        jweObject.decrypt(ECDHDecrypter(verifierEncKey))
        assertTrue(jweObject.payload.toString().contains("signed-vp-token"))
    }

    @Test
    fun handleDCAPIRequest_signedRequest_verifiesJwsAndUsesPayloadFields() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } returns buildJsonObject { put("decision", true) }
        val keystore = mockk<KeystoreManager>()
        coEvery { keystore.signVpToken(any(), any(), any(), any()) } returns "signed-vp-token"
        val listener = mockk<WalletEventListener>()
        coEvery { listener.onCredentialSelectionRequired(any()) } returns listOf("cred-1")
        val store = FakeCredentialStore(mutableListOf(
            StoredCredential(id = "cred-1", format = "dc+sd-jwt", raw = "raw", metadata = CredentialMetadata(name = "X")),
        ))
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "keystore" to keystore,
            "credentialStore" to store,
            "eventListener" to listener,
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

        val requestJson = buildJsonObject { put("request", signedJwt.serialize()) }.toString()

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
                buildJsonObject { put("request", signedJwt.serialize()) }.toString(),
                origin = "https://relying-party.example",
            )
        } catch (e: Throwable) {
            thrown = e
        }
        assertTrue(thrown is org.siros.sdk.wallet.dcapi.DCAPIRequestException)
    }

    private fun newWallet(vararg fields: Pair<String, Any?>): SirosWallet {
        val wallet = allocateInstance(SirosWallet::class.java) as SirosWallet
        val values = fields.toMap(mutableMapOf())
        val stateFlow = values["_state"] as? MutableStateFlow<WalletState>
        if (stateFlow != null && "state" !in values) {
            values["state"] = stateFlow.asStateFlow()
        }
        values.forEach { (name, value) -> setField(wallet, name, value) }
        return wallet
    }

    private fun setField(target: Any, fieldName: String, value: Any?) {
        val field = target.javaClass.getDeclaredField(fieldName)
        field.isAccessible = true
        field.set(target, value)
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
        every { engine.connect(any()) } just runs
        coEvery { engine.awaitConnected(any()) } just runs
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

        override suspend fun getById(id: String): StoredCredential? = credentials.find { it.id == id }

        override suspend fun save(credential: StoredCredential) {
            credentials.removeAll { it.id == credential.id }
            credentials.add(credential)
        }

        override suspend fun update(credential: StoredCredential) {
            save(credential)
        }

        override suspend fun delete(id: String) {
            credentials.removeAll { it.id == id }
        }

        override suspend fun clear() {
            credentials.clear()
        }
    }

    companion object
}
