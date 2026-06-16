// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.sirosfoundation.sdk.wallet

import android.app.Activity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.putJsonObject
import org.sirosfoundation.sdk.auth.AuthSession
import org.sirosfoundation.sdk.auth.BackendApiClient
import org.sirosfoundation.sdk.auth.AuthProvider
import org.sirosfoundation.sdk.auth.CredentialManagerAuthProvider
import org.sirosfoundation.sdk.auth.LocalAuthProvider
import org.sirosfoundation.sdk.auth.PrfOutput
import org.sirosfoundation.sdk.auth.WebAuthnAuthClient
import org.sirosfoundation.sdk.credentials.AuthException
import org.sirosfoundation.sdk.credentials.BackendApiException
import org.sirosfoundation.sdk.credentials.KeystoreException
import org.sirosfoundation.sdk.credentials.NetworkException
import org.sirosfoundation.sdk.credentials.SirosException
import org.sirosfoundation.sdk.credentials.WalletException
import org.sirosfoundation.sdk.credentials.CredentialStore
import org.sirosfoundation.sdk.credentials.InMemoryCredentialStore
import org.sirosfoundation.sdk.credentials.StoredCredential
import org.sirosfoundation.sdk.credentials.CredentialOffer
import org.sirosfoundation.sdk.credentials.CredentialMatcher
import org.sirosfoundation.sdk.credentials.PresentationRecord
import org.sirosfoundation.sdk.credentials.IssuerEntry
import org.sirosfoundation.sdk.credentials.IssuerMetadata
import org.sirosfoundation.sdk.credentials.CredentialConfiguration
import org.sirosfoundation.sdk.credentials.CredentialUtils
import org.sirosfoundation.sdk.credentials.Vctm
import org.sirosfoundation.sdk.credentials.VctmFetcher
import org.sirosfoundation.sdk.keystore.JweKeystore
import org.sirosfoundation.sdk.keystore.KeystoreManager
import org.sirosfoundation.sdk.transport.engine.CredentialMatch
import org.sirosfoundation.sdk.transport.engine.ProofObject
import org.sirosfoundation.sdk.transport.engine.WalletEngineSession
import okhttp3.OkHttpClient
import okhttp3.Request
import timber.log.Timber
import java.security.SecureRandom
import java.util.Base64

/**
 * Main entry point for the SIROS Wallet SDK.
 *
 * Provides a single, self-contained API for wallet apps:
 *
 * ```kotlin
 * val wallet = SirosWallet.create(activity, WalletConfig("https://wallet.sirosid.dev"))
 * wallet.login()               // WebAuthn + PRF + keystore + engine — all automatic
 * wallet.state.collect { ... }  // observe state to drive UI
 * ```
 *
 * The SDK handles WebAuthn authentication with PRF extension, HKDF key
 * derivation, JWE keystore unlock, encrypted private-data sync with the
 * backend, and the engine WebSocket session for issuance/presentation flows.
 *
 * The only things the host app is responsible for are:
 * 1. Providing an [Activity] context (for the passkey system UI).
 * 2. Observing [state] and rendering the appropriate screens.
 * 3. Implementing [WalletEventListener] for credential-selection UX.
 */
class SirosWallet private constructor(
    private val activity: Activity,
    private val config: WalletConfig,
) {
    // ── Public API ──────────────────────────────────────────────────

    private val _state = MutableStateFlow<WalletState>(WalletState.Disconnected)

    /** Observable wallet state. Collect this from your UI layer. */
    val state: StateFlow<WalletState> = _state.asStateFlow()

    /** Set a listener for events that require user interaction (credential picker, etc.). */
    fun setEventListener(listener: WalletEventListener) {
        eventListener = listener
    }

    /**
     * Register a new user with a passkey.
     *
     * This single call:
     * 1. Gets a registration challenge from the backend.
     * 2. Creates a passkey via the system UI (with PRF extension).
     * 3. Derives an encryption key from the PRF output.
     * 4. Initialises an empty encrypted keystore.
     * 5. Sends the encrypted keystore to the backend as `privateData`.
     * 6. Opens the engine WebSocket.
     *
     * @param displayName the user's display name for the passkey.
     * @throws WalletException if registration fails.
     * @throws IllegalArgumentException if displayName is blank or too long.
     */
    suspend fun register(displayName: String) {
        require(displayName.isNotBlank() && displayName.length <= 256) {
            "displayName must be 1-256 characters"
        }
        _state.value = WalletState.Connecting
        try {
            // Generate a fresh PRF salt for this registration
            val prfSalt = ByteArray(32).also { SecureRandom().nextBytes(it) }
            val hkdfSalt = ByteArray(32).also { SecureRandom().nextBytes(it) }
            val hkdfInfo = HKDF_INFO.toByteArray(Charsets.UTF_8)

            val authClient = WebAuthnAuthClient(
                baseUrl = config.backendUrl,
                tenantId = config.tenantId,
                authProvider = authProvider,
            )
            val session = authClient.register(displayName, prfSalt)
            Timber.i("Registration successful: ${session.uuid}")

            // Extract PRF output from the registration result (via AuthProvider)
            // The PRF output is returned inside the AuthSession.prfOutput field
            // which we'll need to propagate through the auth flow.
            // For now, re-evaluate PRF to get the output for key derivation.
            val credId = extractLastCredentialId()
                ?: throw WalletException("No credential ID after registration")
            val prfOutput = extractLastPrfOutput()
                ?: throw WalletException("PRF not supported by authenticator — cannot encrypt wallet data")

            // Derive key and initialise empty keystore
            keystore.unlock(prfOutput.first, ByteArray(0), hkdfSalt, hkdfInfo)

            // Set the credential ID on the container metadata
            (keystore as? JweKeystore)?.setCredentialId(credId)

            // Export the initial (empty) encrypted container
            val encryptedContainer = keystore.exportEncryptedContainer()

            // Persist session + key derivation params
            saveSession(session, credId, prfSalt, hkdfSalt, hkdfInfo)
            sessionStore.privateDataJwe = String(encryptedContainer, Charsets.UTF_8)

            // Sync the initial private data to the backend
            setupApiClient(session)

            syncPrivateDataToBackend()

            // Connect the engine
            connectEngine(session.appToken)

            _state.value = WalletState.Ready(
                userId = session.uuid,
                displayName = session.displayName,
                credentials = credentialStore.getAll(),
            )
        } catch (e: SirosException) {
            Timber.e(e, "Registration failed")
            _state.value = WalletState.Error(e.message ?: "Registration failed")
        } catch (e: Exception) {
            Timber.e(e, "Registration failed")
            _state.value = WalletState.Error(e.message ?: "Registration failed")
            throw WalletException("Registration failed", e)
        }
    }

    /**
     * Login with an existing passkey.
     *
     * This single call:
     * 1. Gets a login challenge from the backend.
     * 2. Authenticates via the system passkey UI (with PRF extension).
     * 3. Derives the encryption key from the PRF output.
     * 4. Downloads the encrypted keystore (`privateData`) from the backend.
     * 5. Unlocks the keystore.
     * 6. Opens the engine WebSocket.
     */
    suspend fun login() {
        _state.value = WalletState.Connecting
        try {
            // Retrieve stored PRF salt for the returning user (if available)
            val storedPrfSalt = sessionStore.prfSalt?.let { b64Decode(it) }

            val authClient = WebAuthnAuthClient(
                baseUrl = config.backendUrl,
                tenantId = config.tenantId,
                authProvider = authProvider,
            )
            val session = authClient.login(prfSalt = storedPrfSalt)
            Timber.i("Login successful: ${session.uuid}")

            val credId = extractLastCredentialId()
                ?: throw WalletException("No credential ID after login")
            val prfOutput = extractLastPrfOutput()
                ?: throw WalletException("PRF not supported by authenticator — cannot decrypt wallet data")

            // Retrieve private data from the backend
            setupApiClient(session)
            val privateData = fetchPrivateData()

            // Retrieve HKDF params from session store (if returning user)
            // or from the private data container metadata
            val hkdfSalt = sessionStore.hkdfSalt?.let { b64Decode(it) }
                ?: ByteArray(32).also { SecureRandom().nextBytes(it) }
            val hkdfInfo = sessionStore.hkdfInfo?.let { b64Decode(it) }
                ?: HKDF_INFO.toByteArray(Charsets.UTF_8)
            val prfSaltBytes = sessionStore.prfSalt?.let { b64Decode(it) }
                ?: ByteArray(32).also { SecureRandom().nextBytes(it) }

            // Unlock keystore with PRF-derived key
            keystore.unlock(prfOutput.first, privateData, hkdfSalt, hkdfInfo)

            // Persist session
            saveSession(session, credId, prfSaltBytes, hkdfSalt, hkdfInfo)

            // Connect the engine
            connectEngine(session.appToken)

            _state.value = WalletState.Ready(
                userId = session.uuid,
                displayName = session.displayName,
                credentials = credentialStore.getAll(),
            )
        } catch (e: SirosException) {
            Timber.e(e, "Login failed")
            _state.value = WalletState.Error(e.message ?: "Login failed")
        } catch (e: Exception) {
            Timber.e(e, "Login failed")
            _state.value = WalletState.Error(e.message ?: "Login failed")
            throw WalletException("Login failed", e)
        }
    }

    /**
     * Disconnect from the wallet backend, lock the keystore,
     * and clear session data.
     */
    fun logout() {
        engineSession?.disconnect()
        engineSession = null
        keystore.lock()
        sessionStore.clear()
        apiClient = null
        _state.value = WalletState.Disconnected
        Timber.i("Logged out")
    }

    /**
     * Resume a previous session without requiring a new WebAuthn assertion.
     *
     * Uses stored `appToken` + `refreshToken` from the previous login.
     * If the stored token is expired, it will be refreshed automatically.
     * Falls back to [WalletState.Disconnected] if no session is stored.
     *
     * Call this on app startup before showing the login screen.
     */
    suspend fun resumeSession() {
        if (!sessionStore.hasSession) {
            Timber.d("No stored session to resume")
            return
        }
        _state.value = WalletState.Connecting
        try {
            val token = sessionStore.appToken!!
            val userId = sessionStore.userId ?: ""
            val displayName = sessionStore.displayName

            // Set up the API client with the stored token
            apiClient = BackendApiClient(config.backendUrl, config.tenantId, httpClient = httpClient).apply {
                setAppToken(token)
            }

            // Verify the token is still valid by calling a lightweight endpoint
            try {
                apiClient!!.healthCheck()
            } catch (e: BackendApiException) {
                if (e.code == 401) {
                    // Token expired — try refreshing
                    val refreshed = refreshToken()
                    if (!refreshed) {
                        Timber.i("Token refresh failed, session expired")
                        sessionStore.clear()
                        apiClient = null
                        _state.value = WalletState.Disconnected
                        return
                    }
                } else {
                    throw e
                }
            }

            // Unlock keystore from stored private data if available
            val storedJwe = sessionStore.privateDataJwe
            val hkdfSalt = sessionStore.hkdfSalt?.let { b64Decode(it) }
            val hkdfInfo = sessionStore.hkdfInfo?.let { b64Decode(it) }

            // Connect the engine (works with token alone, no keystore needed)
            connectEngine(sessionStore.appToken!!)

            if (storedJwe != null && hkdfSalt != null && hkdfInfo != null) {
                // Keystore cannot be unlocked without PRF output.
                // Emit KeystoreLocked so the UI can prompt the user.
                _state.value = WalletState.KeystoreLocked(
                    userId = userId,
                    displayName = displayName,
                )
                Timber.i("Session resumed for user $userId (keystore locked — call unlockKeystore())")
            } else {
                // No private data stored — fresh session, no unlock needed
                _state.value = WalletState.Ready(
                    userId = userId,
                    displayName = displayName,
                    credentials = emptyList(),
                )
                Timber.i("Session resumed for user $userId (no private data)")
            }
        } catch (e: SirosException) {
            Timber.e(e, "Session resume failed")
            _state.value = WalletState.Disconnected
        } catch (e: Exception) {
            Timber.e(e, "Session resume failed")
            _state.value = WalletState.Disconnected
        }
    }

    /**
     * Unlock the keystore after a session resume.
     *
     * Call this when the wallet is in [WalletState.KeystoreLocked].
     * Triggers a WebAuthn assertion (biometric prompt) to obtain the PRF
     * output needed to decrypt the keystore and credentials.
     *
     * After a successful unlock the state transitions to [WalletState.Ready].
     */
    suspend fun unlockKeystore() {
        val current = _state.value
        if (current !is WalletState.KeystoreLocked) {
            Timber.w("unlockKeystore called but state is $current")
            return
        }
        try {
            val storedPrfSalt = sessionStore.prfSalt?.let { b64Decode(it) }
            val authClient = WebAuthnAuthClient(
                baseUrl = config.backendUrl,
                tenantId = config.tenantId,
                authProvider = authProvider,
            )
            // Silent assertion — triggers biometric to get PRF output
            authClient.login(prfSalt = storedPrfSalt)

            val prfOutput = extractLastPrfOutput()
                ?: throw WalletException("PRF not available from authenticator")

            val storedJwe = sessionStore.privateDataJwe
            val hkdfSalt = sessionStore.hkdfSalt?.let { b64Decode(it) }
                ?: throw WalletException("Missing HKDF salt")
            val hkdfInfo = sessionStore.hkdfInfo?.let { b64Decode(it) }
                ?: HKDF_INFO.toByteArray(Charsets.UTF_8)

            val privateData = storedJwe?.toByteArray(Charsets.UTF_8) ?: ByteArray(0)
            keystore.unlock(prfOutput.first, privateData, hkdfSalt, hkdfInfo)

            _state.value = WalletState.Ready(
                userId = current.userId,
                displayName = current.displayName,
                credentials = credentialStore.getAll(),
            )
            Timber.i("Keystore unlocked after session resume")
        } catch (e: KeystoreException) {
            Timber.e(e, "Keystore unlock failed: corrupt container")
            _state.value = WalletState.Error(e.message ?: "Keystore unlock failed")
        } catch (e: AuthException) {
            Timber.e(e, "Keystore unlock failed: authentication error")
            _state.value = WalletState.Error(e.message ?: "Authentication failed")
        } catch (e: SirosException) {
            Timber.e(e, "Keystore unlock failed")
            _state.value = WalletState.Error(e.message ?: "Keystore unlock failed")
        } catch (e: Exception) {
            Timber.e(e, "Keystore unlock failed")
            _state.value = WalletState.Error(e.message ?: "Keystore unlock failed")
        }
    }

    /**
     * Attempt to refresh the appToken using the stored refreshToken.
     * @return true if refresh succeeded, false otherwise.
     */
    private suspend fun refreshToken(): Boolean {
        val refreshTok = sessionStore.refreshToken ?: return false
        return try {
            val client = apiClient ?: return false
            val response = client.refreshSession(refreshTok)
            val newToken = response["appToken"]?.jsonPrimitive?.content ?: return false
            sessionStore.appToken = newToken
            client.setAppToken(newToken)
            // Update refresh token if a new one was issued
            response["refreshToken"]?.jsonPrimitive?.content?.let {
                sessionStore.refreshToken = it
            }
            Timber.i("Token refreshed successfully")
            true
        } catch (e: Exception) {
            Timber.w(e, "Token refresh failed")
            false
        }
    }

    /**
     * Release all resources held by this wallet instance.
     *
     * Call this when the host Activity is destroyed or the wallet is
     * no longer needed. After calling [destroy], this instance must
     * not be used again — create a new one with [create].
     */
    fun destroy() {
        engineSession?.disconnect()
        engineSession = null
        keystore.lock()
        apiClient = null
        supervisorJob.cancel()
        Timber.i("Wallet instance destroyed")
    }

    /**
     * Get credentials, excluding expired ones.
     *
     * @param includeExpired when true, returns all credentials including expired.
     */
    suspend fun getCredentials(includeExpired: Boolean = false): List<StoredCredential> {
        val all = credentialStore.getAll()
        if (includeExpired) return all
        val now = System.currentTimeMillis() / 1000
        return all.filter { cred ->
            val exp = cred.expiresAt
            exp == null || exp > now
        }
    }

    /**
     * Fetch the list of available credential issuers from the backend.
     *
     * Requires an active session (call after [login] or [register]).
     * Each [IssuerEntry] contains the issuer URL; call [getAvailableCredentials]
     * to discover what credentials each issuer offers.
     */
    suspend fun getIssuers(): List<IssuerEntry> = withContext(Dispatchers.IO) {
        val client = apiClient ?: throw WalletException("Not connected")
        val response = client.getIssuers()
        // Backend user API returns a plain JSON array, admin API wraps in {"issuers": [...]}
        val arr = when (response) {
            is kotlinx.serialization.json.JsonArray -> response
            is kotlinx.serialization.json.JsonObject ->
                response["issuers"]?.jsonArray
                    ?: response["data"]?.jsonArray
                    ?: throw WalletException("Unexpected issuer list format")
            else -> throw WalletException("Unexpected issuer response type")
        }
        arr.map { json.decodeFromJsonElement(IssuerEntry.serializer(), it) }
            .filter { it.visible }
    }

    /**
     * Fetch OpenID4VCI credential issuer metadata for a given issuer URL.
     *
     * Prefers the backend proxy (which caches metadata and handles
     * internal network access). Falls back to a direct HTTP call if
     * no authenticated session is available.
     */
    suspend fun getIssuerMetadata(issuerUrl: String): IssuerMetadata = withContext(Dispatchers.IO) {
        val url = issuerUrl.trimEnd('/') + "/.well-known/openid-credential-issuer"
        val request = Request.Builder().url(url).get().build()
        val response = httpClient.newCall(request).execute()
        val body = response.body?.string()
            ?: throw WalletException("Empty metadata response from $issuerUrl")
        if (!response.isSuccessful) {
            throw WalletException("Metadata fetch failed: ${response.code}")
        }
        json.decodeFromString(IssuerMetadata.serializer(), body)
    }

    /**
     * Discover all available credentials across all visible issuers.
     *
     * Returns a flat list of [CredentialOffer] items ready for display in a
     * picker UI. Each item can be passed to [startIssuanceByOffer].
     */
    suspend fun getAvailableCredentials(): List<CredentialOffer> = withContext(Dispatchers.IO) {
        val issuers = getIssuers()
        Timber.d("getAvailableCredentials: ${issuers.size} issuers")
        val client = apiClient ?: throw WalletException("Not connected")
        val offers = mutableListOf<CredentialOffer>()

        for (issuer in issuers) {
            try {
                val metadataJson = client.getIssuerMetadata(issuer.id)
                val metadata = json.decodeFromJsonElement(IssuerMetadata.serializer(), metadataJson)
                val issuerDisplay = metadata.display?.firstOrNull()
                val issuerName = issuerDisplay?.name
                    ?: java.net.URI(issuer.credentialIssuerIdentifier).host
                    ?: issuer.credentialIssuerIdentifier

                for ((configId, config) in metadata.credentialConfigurationsSupported) {
                    val credDisplay = config.credentialMetadata?.display?.firstOrNull()
                    val credName = credDisplay?.name ?: configId
                    offers.add(CredentialOffer(
                        credentialConfigurationId = configId,
                        credentialIssuerIdentifier = issuer.credentialIssuerIdentifier,
                        credentialName = credName,
                        credentialDescription = credDisplay?.description,
                        issuerName = issuerName,
                        backgroundColor = credDisplay?.backgroundColor
                            ?: issuerDisplay?.backgroundColor,
                        textColor = credDisplay?.textColor
                            ?: issuerDisplay?.textColor,
                        logoUri = credDisplay?.logo?.uri,
                        issuerLogoUri = issuerDisplay?.logo?.uri,
                    ))
                }
            } catch (e: Exception) {
                Timber.w(e, "Failed to fetch metadata for ${issuer.credentialIssuerIdentifier}")
            }
        }
        offers
    }

    /**
     * Start an issuance flow for a specific credential offer.
     *
     * Constructs the OID4VCI credential_offer and sends it to the engine.
     */
    suspend fun startIssuanceByOffer(offer: CredentialOffer) {
        val engine = engineSession ?: throw WalletException("Not connected")
        activeOffer = offer
        activeVctm = try {
            vctmFetcher.fetch(
                issuerUrl = offer.credentialIssuerIdentifier,
                scope = offer.credentialConfigurationId,
            )
        } catch (e: Exception) {
            Timber.w(e, "Failed to fetch VCTM for ${offer.credentialConfigurationId}")
            null
        }
        val credentialOffer = kotlinx.serialization.json.buildJsonObject {
            put("credential_issuer", kotlinx.serialization.json.JsonPrimitive(
                offer.credentialIssuerIdentifier
            ))
            put("credential_configuration_ids", kotlinx.serialization.json.buildJsonArray {
                add(kotlinx.serialization.json.JsonPrimitive(offer.credentialConfigurationId))
            })
            put("grants", kotlinx.serialization.json.buildJsonObject {
                if (offer.preAuthorizedCode != null) {
                    put("urn:ietf:params:oauth:grant-type:pre-authorized_code",
                        kotlinx.serialization.json.buildJsonObject {
                            put("pre-authorized_code", kotlinx.serialization.json.JsonPrimitive(
                                offer.preAuthorizedCode
                            ))
                            if (offer.txCode != null) {
                                put("tx_code", kotlinx.serialization.json.buildJsonObject {
                                    put("input_mode", kotlinx.serialization.json.JsonPrimitive("text"))
                                })
                            }
                        })
                } else {
                    put("authorization_code", kotlinx.serialization.json.buildJsonObject {})
                }
            })
        }
        engine.startIssuance(
            offer = credentialOffer.toString(),
            redirectUri = config.redirectUri.ifBlank { null },
        )
    }

    /**
     * Start a credential issuance flow with a raw offer or URI.
     *
     * @param offerUri a credential_offer_uri or raw JSON credential_offer string.
     */
    suspend fun startIssuance(offerUri: String) {
        val engine = engineSession ?: throw WalletException("Not connected")
        if (offerUri.startsWith("openid-credential-offer://")) {
            // Deep-link URI with inline offer — send as "offer" so the engine
            // extracts the credential_offer query parameter instead of HTTP-fetching.
            engine.startIssuance(offer = offerUri)
        } else if (offerUri.startsWith("http")) {
            engine.startIssuance(credentialOfferUri = offerUri)
        } else {
            engine.startIssuance(offer = offerUri)
        }
    }

    /**
     * Start a credential presentation flow.
     *
     * @param requestUri the OID4VP request URI.
     */
    suspend fun startPresentation(requestUri: String) {
        val engine = engineSession ?: throw WalletException("Not connected")
        engine.startPresentation(requestUri = requestUri)
    }

    /**
     * Perform identity verification via a plugin provider and automatically start
     * credential issuance with the resulting offer.
     *
     * This is the primary integration point for IDV flows (FaceTec, iProov, etc.).
     * The provider handles all capture UI and backend communication; this method
     * bridges the IDV result into the standard OID4VCI issuance flow.
     *
     * @param provider An [IdentityVerificationProvider] implementation.
     * @param activity The hosting Activity for presenting the IDV UI.
     * @throws IDVException if verification fails.
     * @throws WalletException if issuance fails.
     */
    suspend fun verifyIdentityAndIssue(
        provider: org.sirosfoundation.sdk.idv.IdentityVerificationProvider,
        activity: android.app.Activity,
    ) {
        if (!provider.isAvailable()) {
            throw org.sirosfoundation.sdk.idv.IDVException.Unavailable(
                "${provider.name} is not available on this device"
            )
        }
        val result = provider.startVerification(activity)
        startIssuance(result.credentialOfferURI)
    }

    /**
     * Cancel an in-progress flow and return the wallet to the Ready state.
     *
     * If there is an active flow, sends a decline message to the backend.
     * If no flow is active, simply resets to Ready state.
     */
    fun cancelCurrentFlow() {
        val current = _state.value
        if (current is WalletState.FlowActive) {
            try {
                engineSession?.cancelFlow(current.flowId)
            } catch (e: Exception) {
                Timber.w(e, "Failed to send cancel to backend")
            }
            _state.value = WalletState.Ready(
                userId = current.userId,
                displayName = current.displayName,
                credentials = current.credentials,
            )
        }
    }

    /**
     * Complete an OAuth authorization flow after the user has approved in the browser.
     *
     * Call this from your app's deep link handler when the browser redirects
     * back with `code` and `state` query parameters.
     *
     * @param flowId The flow ID from [WalletEventListener.onAuthorizationRequired].
     * @param code The authorization code from the redirect.
     * @param state The state parameter from the redirect (for CSRF validation).
     */
    fun completeAuthorization(flowId: String, code: String, state: String) {
        val engine = engineSession ?: throw WalletException("Not connected")
        val payload = buildJsonObject {
            put("code", kotlinx.serialization.json.JsonPrimitive(code))
            put("state", kotlinx.serialization.json.JsonPrimitive(state))
        }
        engine.sendFlowAction(flowId, "authorization_complete", payload)
    }

    /**
     * Delete a credential by ID.
     * Also syncs the updated keystore to the backend.
     */
    suspend fun deleteCredential(credentialId: String) {
        credentialStore.delete(credentialId)
        val current = _state.value
        if (current is WalletState.Ready) {
            _state.value = current.copy(credentials = credentialStore.getAll())
        }
        persistAndSyncKeystore()
    }

    // ── Internal wiring ─────────────────────────────────────────────

    private val supervisorJob = SupervisorJob()
    private val scope = CoroutineScope(Dispatchers.Main + supervisorJob)
    private val sessionStore = SessionStore(activity)
    private val authProvider = createAuthProvider(activity, config)
    private val keystore: KeystoreManager = JweKeystore()
    private val credentialStore: CredentialStore =
        config.credentialStore ?: KeystoreBackedCredentialStore(keystore)
    private val json = Json { ignoreUnknownKeys = true }
    private val httpClient = config.httpClient ?: OkHttpClient()
    private val vctmFetcher = VctmFetcher(httpGet = { url ->
        val request = Request.Builder().url(url).get().build()
        val response = httpClient.newCall(request).execute()
        if (response.isSuccessful) response.body?.string() else null
    })

    private val _presentationHistory = mutableListOf<PresentationRecord>()

    /** Presentation history — most recent first. */
    val presentationHistory: List<PresentationRecord> get() = _presentationHistory.toList()

    private var apiClient: BackendApiClient? = null
    private var engineSession: WalletEngineSession? = null
    private var eventListener: WalletEventListener? = null
    private var activeOffer: CredentialOffer? = null
    private var activeVctm: Vctm? = null

    /**
     * Extract the last credential ID from the auth provider, regardless of type.
     */
    private fun extractLastCredentialId(): ByteArray? = when (authProvider) {
        is LocalAuthProvider -> authProvider.lastCredentialId
        is CredentialManagerAuthProvider -> authProvider.lastCredentialId
        else -> null
    }

    /**
     * Extract the last PRF output from the auth provider, regardless of type.
     */
    private fun extractLastPrfOutput(): PrfOutput? = when (authProvider) {
        is LocalAuthProvider -> authProvider.lastPrfOutput
        is CredentialManagerAuthProvider -> authProvider.lastPrfOutput
        else -> null
    }

    private fun setupApiClient(session: AuthSession) {
        Timber.d("setupApiClient: authenticated session established")
        apiClient = BackendApiClient(config.backendUrl, config.tenantId, httpClient = httpClient).apply {
            setAppToken(session.appToken)
        }
    }

    private suspend fun fetchPrivateData(): ByteArray {
        val client = apiClient ?: throw WalletException("Not authenticated")
        return try {
            val response = client.getPrivateData()
            val pdElement = response["privateData"]
            if (pdElement != null) {
                // Backend returns {"privateData": {"$b64u": "base64url-encoded-container"}}
                val containerBytes = when (pdElement) {
                    is kotlinx.serialization.json.JsonObject -> {
                        val b64u = pdElement["\$b64u"]?.jsonPrimitive?.content
                        if (b64u != null) {
                            b64UrlDecode(b64u)
                        } else {
                            // Container is inline JSON
                            pdElement.toString().toByteArray(Charsets.UTF_8)
                        }
                    }
                    is kotlinx.serialization.json.JsonPrimitive -> {
                        // Plain string (legacy or direct JWE)
                        pdElement.content.toByteArray(Charsets.UTF_8)
                    }
                    else -> ByteArray(0)
                }
                if (containerBytes.isNotEmpty()) {
                    sessionStore.privateDataJwe = String(containerBytes, Charsets.UTF_8)
                }
                containerBytes
            } else {
                ByteArray(0)
            }
        } catch (e: NetworkException) {
            Timber.w(e, "Could not fetch privateData (network), starting with empty keystore")
            ByteArray(0)
        } catch (e: BackendApiException) {
            Timber.w(e, "Could not fetch privateData (HTTP ${e.code}), starting with empty keystore")
            ByteArray(0)
        } catch (e: Exception) {
            Timber.w(e, "Could not fetch privateData, starting with empty keystore")
            ByteArray(0)
        }
    }

    private suspend fun syncPrivateDataToBackend() {
        val client = apiClient ?: return
        val containerJson = sessionStore.privateDataJwe ?: return
        try {
            // Send the full container JSON as the POST body,
            // matching the wallet-frontend's format.
            val body = Json.parseToJsonElement(containerJson).jsonObject
            client.updatePrivateData(body)
            Timber.d("Private data synced to backend")
        } catch (e: Exception) {
            Timber.e(e, "Failed to sync private data to backend")
            eventListener?.onFlowError("sync", "Private data sync failed: ${e.message}")
        }
    }

    /**
     * Persist the current keystore state to local storage and sync to backend.
     *
     * Called after any credential mutation to minimise the data-loss window.
     */
    private suspend fun persistAndSyncKeystore() {
        if (!keystore.isUnlocked) return
        try {
            val container = keystore.exportEncryptedContainer()
            sessionStore.privateDataJwe = String(container, Charsets.UTF_8)
            syncPrivateDataToBackend()
        } catch (e: Exception) {
            Timber.e(e, "Failed to persist keystore")
        }
    }

    private suspend fun connectEngine(appToken: String) {
        val engine = createEngineSession(config.backendUrl, config.tenantId)
        engineSession = engine
        engine.connect(appToken)
        engine.awaitConnected()

        // Observe sign requests → auto-sign with keystore
        scope.launch {
            engine.signRequests().collect { msg ->
                try {
                    Timber.d("Sign request: ${msg.action} for flow ${msg.flowId}")
                    when (msg.action) {
                        "generate_proof" -> {
                            val params = msg.params
                            val proofJwt = keystore.generateProof(
                                audience = params?.audience ?: "",
                                nonce = params?.nonce ?: "",
                            )
                            val count = params?.count ?: 1
                            val proofs = (1..count).map {
                                ProofObject(proofType = "jwt", jwt = proofJwt)
                            }
                            Timber.d("Sending sign response with ${proofs.size} proofs for flow ${msg.flowId}, messageId=${msg.messageId}")
                            engine.sendSignResponse(msg.flowId, proofs = proofs, messageId = msg.messageId)
                            Timber.d("Sign response sent successfully for flow ${msg.flowId}")
                        }
                        "sign_presentation" -> {
                            val params = msg.params
                            val nonce = params?.nonce ?: ""
                            val audience = params?.audience ?: ""
                            val credsToInclude = params?.credentialsToInclude

                            val vpToken = if (!credsToInclude.isNullOrEmpty()) {
                                // SD-JWT VP: build proper VP token with KB-JWT for each credential
                                val allCreds = credentialStore.getAll()
                                val vpParts = credsToInclude.mapNotNull { ref ->
                                    val cred = allCreds.find { it.id == ref.credentialId }
                                    if (cred == null) {
                                        Timber.w("Credential ...${ref.credentialId.takeLast(4)} not found in store for VP signing")
                                        return@mapNotNull null
                                    }
                                    keystore.signVpToken(
                                        credential = cred.raw,
                                        disclosedClaims = ref.disclosedClaims,
                                        nonce = nonce,
                                        audience = audience,
                                    )
                                }
                                // For single credential presentations (most common), return the token directly.
                                // For multiple credentials, join with newline for WMP transport.
                                // Note: The backend assembles the OID4VP-compliant vp_token JSON
                                // object (keyed by credential query ID, §8.1) before submission
                                // to the verifier.
                                vpParts.joinToString("\n")
                            } else {
                                // Fallback: legacy plain VP JWT (no credential data)
                                keystore.signPresentation(
                                    nonce = nonce,
                                    audience = audience,
                                    credentialIds = emptyList(),
                                )
                            }
                            Timber.d("Sending VP sign response for flow ${msg.flowId}, messageId=${msg.messageId}")
                            engine.sendSignResponse(msg.flowId, vpToken = vpToken, messageId = msg.messageId)
                            Timber.d("VP sign response sent successfully for flow ${msg.flowId}")
                        }
                        else -> {
                            Timber.w("Unknown sign action: ${msg.action}")
                        }
                    }
                } catch (e: KeystoreException) {
                    Timber.e(e, "Error handling sign request: keystore error")
                } catch (e: Exception) {
                    Timber.e(e, "Error handling sign request")
                }
            }
        }

        // Observe match requests → DCQL-filtered credential matching
        scope.launch {
            engine.matchRequests().collect { msg ->
                try {
                    Timber.d("Match request for flow ${msg.flowId}")
                    val allCreds = credentialStore.getAll()
                    val listener = eventListener

                    // Filter credentials using DCQL query from the verifier
                    val dcqlQuery = msg.dcqlQuery?.jsonObject
                    val dcqlOutput = if (dcqlQuery != null) {
                        CredentialMatcher.matchDcql(dcqlQuery, allCreds)
                    } else {
                        // No DCQL query — fall back to all credentials
                        CredentialMatcher.DcqlMatchOutput(
                            queryResults = listOf(CredentialMatcher.MatchResult(
                                queryId = "_default",
                                format = null,
                                candidates = allCreds,
                                requestedClaims = emptyList(),
                            )),
                            credentialSets = null,
                            satisfiableOptions = emptyList(),
                        )
                    }

                    val matchResults = dcqlOutput.queryResults
                    val candidates = matchResults.flatMap { it.candidates }.distinctBy { it.id }

                    // Let the app filter further via user selection
                    val selectedIds = if (listener != null && candidates.isNotEmpty()) {
                        listener.onCredentialSelectionRequired(
                            PresentationRequest(
                                verifierName = null,
                                matchResults = matchResults,
                                candidates = candidates,
                                credentialSets = dcqlOutput.credentialSets,
                                satisfiableOptions = dcqlOutput.satisfiableOptions,
                            )
                        )
                    } else {
                        candidates.map { it.id }
                    }

                    // Track this presentation
                    _presentationHistory.add(0, PresentationRecord(
                        id = java.util.UUID.randomUUID().toString(),
                        flowId = msg.flowId,
                        credentialIds = selectedIds,
                        credentialNames = selectedIds.mapNotNull { id ->
                            allCreds.find { it.id == id }?.metadata?.name
                        },
                        requestedClaims = matchResults.flatMap { it.requestedClaims.flatten() }.distinct(),
                        timestamp = System.currentTimeMillis(),
                    ))

                    val matches = selectedIds.mapNotNull { id ->
                        allCreds.find { it.id == id }?.let { cred ->
                            val queryId = matchResults.firstOrNull { r ->
                                r.candidates.any { it.id == id }
                            }?.queryId
                            CredentialMatch(
                                credentialQueryId = queryId,
                                credentialId = cred.id,
                                format = cred.format,
                                vct = cred.metadata?.vct,
                                availableClaims = extractAvailableClaims(cred),
                            )
                        }
                    }
                    engine.sendMatchResponse(msg.flowId, matches)
                } catch (e: SirosException) {
                    Timber.e(e, "Error handling match request")
                } catch (e: Exception) {
                    Timber.e(e, "Error handling match request")
                }
            }
        }

        // Observe flow progress
        scope.launch {
            engine.flowProgress().collect { msg ->
                Timber.d("Flow ${msg.flowId} progress: ${msg.step}")

                // Handle trust evaluation — matching wallet-frontend reference implementation
                if ((msg.step == "evaluating_trust" || msg.step == "evaluating_verifier_trust") &&
                    msg.payload?.jsonObject?.get("trust_evaluation_required")?.jsonPrimitive?.boolean == true
                ) {
                    handleTrustEvaluation(engine, msg.flowId, msg.payload!!.jsonObject)
                }

                // Handle credential selection — verifier wants credentials, user must consent
                if (msg.step == "credential_selection") {
                    handleCredentialSelection(engine, msg.flowId, msg.payload?.jsonObject)
                }

                // Handle authorization required — user must approve in browser
                if (msg.step == "authorization_required") {
                    val payload = msg.payload?.jsonObject
                    Timber.d("Authorization required payload: $payload")

                    // Handle tx_code (PIN input) for pre-authorized code flow
                    val payloadType = payload?.get("type")?.jsonPrimitive?.contentOrNull
                    if (payloadType == "tx_code") {
                        val txCode = eventListener?.onTxCodeRequired(
                            flowId = msg.flowId,
                            description = payload?.get("message")?.jsonPrimitive?.contentOrNull,
                        )
                        if (txCode != null) {
                            Timber.i("Providing tx_code for flow ${msg.flowId}")
                            engine.sendFlowAction(msg.flowId, "provide_pin",
                                kotlinx.serialization.json.buildJsonObject {
                                    put("tx_code", kotlinx.serialization.json.JsonPrimitive(txCode))
                                })
                        } else {
                            Timber.w("No tx_code provided for flow ${msg.flowId}")
                        }
                    } else {
                        val authUrl = payload?.get("authorization_url")?.jsonPrimitive?.contentOrNull
                        val redirectUri = payload?.get("expected_redirect_uri")?.jsonPrimitive?.contentOrNull
                        val state = payload?.get("state")?.jsonPrimitive?.contentOrNull
                        if (authUrl != null) {
                            // Apply URL rewriter if configured
                            val rewrittenUrl = config.urlRewriter?.invoke(authUrl) ?: authUrl
                            // Extract state from URL query params if not in payload
                            val effectiveState = state ?: android.net.Uri.parse(rewrittenUrl).getQueryParameter("state") ?: ""
                            Timber.d("Authorization required: url=$rewrittenUrl state=$effectiveState")
                            eventListener?.onAuthorizationRequired(
                                flowId = msg.flowId,
                                authorizationUrl = rewrittenUrl,
                                redirectUri = redirectUri ?: "",
                                state = effectiveState,
                            )
                        }
                    }
                }

                val current = _state.value
                if (current is WalletState.Ready || current is WalletState.FlowActive) {
                    val userId = (current as? WalletState.Ready)?.userId
                        ?: (current as? WalletState.FlowActive)?.userId ?: ""
                    val displayName = (current as? WalletState.Ready)?.displayName
                        ?: (current as? WalletState.FlowActive)?.displayName
                    _state.value = WalletState.FlowActive(
                        userId = userId,
                        displayName = displayName,
                        flowId = msg.flowId,
                        flowType = msg.step ?: "unknown",
                        status = msg.step ?: "in_progress",
                        credentials = credentialStore.getAll(),
                    )
                }
            }
        }

        // Observe flow completion → sync new credentials
        scope.launch {
            engine.flowComplete().collect { msg ->
                Timber.i("Flow ${msg.flowId} complete")

                // Store any new credentials from the flow result
                msg.credentials?.forEach { cred ->
                    // Basic validation: ensure credential is parseable
                    val payload = CredentialUtils.parseJwtPayload(cred.credential)
                    if (payload == null) {
                        Timber.w("Skipping unparseable credential in flow ${msg.flowId}")
                        return@forEach
                    }
                    // Check expiry — don't store already-expired credentials
                    val exp = payload["exp"]?.jsonPrimitive?.longOrNull
                    val now = System.currentTimeMillis() / 1000
                    if (exp != null && exp < now) {
                        Timber.w("Skipping expired credential (exp=$exp, now=$now)")
                        return@forEach
                    }
                    val metadata = activeOffer?.let { offer ->
                        CredentialUtils.buildMetadata(
                            offer = offer,
                            vctm = activeVctm,
                            rawCredential = cred.credential,
                        )
                    }
                    val stored = StoredCredential(
                        id = java.util.UUID.randomUUID().toString(),
                        format = cred.format,
                        raw = cred.credential,
                        metadata = metadata,
                        issuedAt = payload["iat"]?.jsonPrimitive?.longOrNull,
                        expiresAt = exp,
                    )
                    credentialStore.save(stored)
                    eventListener?.onCredentialReceived(stored)
                }
                activeOffer = null
                activeVctm = null

                // Persist locally + sync to backend immediately
                persistAndSyncKeystore()

                eventListener?.onFlowComplete(msg.flowId)

                val current = _state.value
                val userId = (current as? WalletState.FlowActive)?.userId
                    ?: (current as? WalletState.Ready)?.userId ?: ""
                val displayName = (current as? WalletState.FlowActive)?.displayName
                    ?: (current as? WalletState.Ready)?.displayName
                _state.value = WalletState.Ready(
                    userId = userId,
                    displayName = displayName,
                    credentials = credentialStore.getAll(),
                )
            }
        }

        // Observe flow errors
        scope.launch {
            engine.flowErrors().collect { msg ->
                Timber.e("Flow ${msg.flowId} error: ${msg.error.code} — ${msg.error.message}")
                val fid = msg.flowId ?: "unknown"
                eventListener?.onFlowError(fid, msg.error.message)

                val current = _state.value
                val userId = (current as? WalletState.FlowActive)?.userId
                    ?: (current as? WalletState.Ready)?.userId ?: ""
                val displayName = (current as? WalletState.FlowActive)?.displayName
                    ?: (current as? WalletState.Ready)?.displayName
                _state.value = WalletState.Ready(
                    userId = userId,
                    displayName = displayName,
                    credentials = credentialStore.getAll(),
                )
            }
        }
    }

    /**
     * Handle trust evaluation step from the engine.
     *
     * Matches the wallet-frontend reference implementation (release/sirosid):
     * 1. Extract the trust request from the flow_progress payload
     * 2. Build an AuthZEN evaluation request
     * 3. Call POST /v1/evaluate on the backend
     * 4. Send back a trust_result flow action
     */
    private fun handleTrustEvaluation(
        engine: WalletEngineSession,
        flowId: String,
        payload: kotlinx.serialization.json.JsonObject,
    ) {
        scope.launch {
            try {
                val request = payload["request"]?.jsonObject
                val subjectId = request?.get("subject_id")?.jsonPrimitive?.contentOrNull
                val subjectType = request?.get("subject_type")?.jsonPrimitive?.contentOrNull

                if (subjectId.isNullOrBlank()) {
                    Timber.e("Trust evaluation request missing subject_id")
                    engine.sendTrustResult(flowId, false, "Missing subject_id")
                    return@launch
                }

                Timber.d("Trust evaluation: subject=$subjectId type=$subjectType")

                // Build AuthZEN evaluation request matching the reference implementation
                val keyMaterial = request?.get("key_material")?.jsonObject
                val evaluationRequest = kotlinx.serialization.json.buildJsonObject {
                    putJsonObject("subject") {
                        put("type", kotlinx.serialization.json.JsonPrimitive("key"))
                        put("id", kotlinx.serialization.json.JsonPrimitive(subjectId))
                    }
                    putJsonObject("resource") {
                        val kmType = keyMaterial?.get("type")?.jsonPrimitive?.contentOrNull ?: "x5c"
                        put("type", kotlinx.serialization.json.JsonPrimitive(kmType))
                        put("id", kotlinx.serialization.json.JsonPrimitive(subjectId))
                        // Copy key material arrays (x5c or jwk)
                        val x5c = keyMaterial?.get("x5c")
                        val jwk = keyMaterial?.get("jwk")
                        if (x5c != null) {
                            put("key", x5c)
                        } else if (jwk != null) {
                            put("key", kotlinx.serialization.json.buildJsonArray {
                                add(jwk)
                            })
                        }
                    }
                    putJsonObject("action") {
                        put("name", kotlinx.serialization.json.JsonPrimitive(
                            if (subjectType == "credential_verifier") "credential-verifier"
                            else "credential-issuer"
                        ))
                    }
                    // Pass through context from the engine request
                    request?.get("context")?.let { ctx ->
                        put("context", ctx)
                    }
                }

                Timber.d("Calling /v1/evaluate for $subjectId")
                val response = apiClient!!.evaluateTrust(evaluationRequest)

                val decision = response["decision"]?.jsonPrimitive?.boolean ?: false
                Timber.i("Trust evaluation result: decision=$decision for $subjectId")

                engine.sendTrustResult(flowId, decision)
            } catch (e: Exception) {
                Timber.e(e, "Trust evaluation failed")
                engine.sendTrustResult(flowId, false, e.message ?: "Trust evaluation failed")
            }
        }
    }

    /**
     * Handle credential_selection step from the engine.
     *
     * The backend sends DCQL query + verifier info in a flow_progress message.
     * We match credentials locally, show a consent UI via the event listener,
     * and respond with a consent or decline action.
     */
    private fun handleCredentialSelection(
        engine: WalletEngineSession,
        flowId: String,
        payload: kotlinx.serialization.json.JsonObject?,
    ) {
        scope.launch {
            try {
                val dcqlQuery = payload?.get("dcql_query")?.jsonObject
                val verifierInfo = payload?.get("verifier")?.jsonObject
                val verifierName = verifierInfo?.get("name")?.jsonPrimitive?.contentOrNull
                    ?: verifierInfo?.get("client_id")?.jsonPrimitive?.contentOrNull

                val allCreds = credentialStore.getAll()
                val matchResults = if (dcqlQuery != null) {
                    CredentialMatcher.match(dcqlQuery, allCreds)
                } else {
                    listOf(CredentialMatcher.MatchResult(
                        queryId = "_default",
                        format = null,
                        candidates = allCreds,
                        requestedClaims = emptyList(),
                    ))
                }
                val candidates = matchResults.flatMap { it.candidates }.distinctBy { it.id }

                val listener = eventListener
                val selectedIds = if (listener != null && candidates.isNotEmpty()) {
                    listener.onCredentialSelectionRequired(
                        PresentationRequest(
                            verifierName = verifierName,
                            matchResults = matchResults,
                            candidates = candidates,
                        )
                    )
                } else {
                    candidates.map { it.id }
                }

                if (selectedIds.isEmpty()) {
                    // User declined
                    val declinePayload = kotlinx.serialization.json.buildJsonObject {
                        put("reason", kotlinx.serialization.json.JsonPrimitive("user_declined"))
                    }
                    engine.sendFlowAction(flowId, "decline", declinePayload)
                    return@launch
                }

                // Record presentation history
                _presentationHistory.add(0, PresentationRecord(
                    id = java.util.UUID.randomUUID().toString(),
                    flowId = flowId,
                    verifierName = verifierName,
                    credentialIds = selectedIds,
                    credentialNames = selectedIds.mapNotNull { id ->
                        allCreds.find { it.id == id }?.metadata?.name
                    },
                    requestedClaims = matchResults.flatMap { it.requestedClaims.flatten() }.distinct(),
                    timestamp = System.currentTimeMillis(),
                ))

                // Build consent payload with selected credentials
                // Must match backend ConsentSelection: credential_query_id, credential_id, disclosed_claims
                val consentPayload = kotlinx.serialization.json.buildJsonObject {
                    put("selected_credentials", kotlinx.serialization.json.buildJsonArray {
                        for (id in selectedIds) {
                            allCreds.find { it.id == id } ?: continue
                            val matchResult = matchResults.firstOrNull { r ->
                                r.candidates.any { it.id == id }
                            }
                            add(kotlinx.serialization.json.buildJsonObject {
                                matchResult?.queryId?.let {
                                    put("credential_query_id", kotlinx.serialization.json.JsonPrimitive(it))
                                }
                                put("credential_id", kotlinx.serialization.json.JsonPrimitive(id))
                                // Include disclosed_claims from DCQL match so backend can
                                // round-trip them into sign_request's credentials_to_include
                                val requestedClaims = matchResult?.requestedClaims
                                    ?.flatten()
                                    ?.distinct()
                                    ?: emptyList()
                                put("disclosed_claims", kotlinx.serialization.json.buildJsonArray {
                                    for (claim in requestedClaims) {
                                        add(kotlinx.serialization.json.JsonPrimitive(claim))
                                    }
                                })
                            })
                        }
                    })
                }
                engine.sendFlowAction(flowId, "consent", consentPayload)
            } catch (e: Exception) {
                Timber.e(e, "Error handling credential selection")
                val declinePayload = kotlinx.serialization.json.buildJsonObject {
                    put("reason", kotlinx.serialization.json.JsonPrimitive("error: ${e.message}"))
                }
                engine.sendFlowAction(flowId, "decline", declinePayload)
            }
        }
    }

    private fun saveSession(
        session: AuthSession,
        credentialId: ByteArray,
        prfSalt: ByteArray,
        hkdfSalt: ByteArray,
        hkdfInfo: ByteArray,
    ) {
        sessionStore.appToken = session.appToken
        sessionStore.refreshToken = session.refreshToken
        sessionStore.userId = session.uuid
        sessionStore.displayName = session.displayName
        sessionStore.tenantId = config.tenantId
        sessionStore.credentialId = b64UrlEncode(credentialId)
        sessionStore.prfSalt = b64Encode(prfSalt)
        sessionStore.hkdfSalt = b64Encode(hkdfSalt)
        sessionStore.hkdfInfo = b64Encode(hkdfInfo)
    }

    /**
     * Extract available claim names from a stored credential.
     *
     * For SD-JWT credentials, parses disclosures to get claim names.
     * Falls back to credential metadata claims if available.
     */
    private fun extractAvailableClaims(cred: StoredCredential): List<String> {
        val claims = mutableSetOf<String>()

        // Extract from SD-JWT disclosures: each is base64url(["salt","claim_name","value"])
        if (cred.raw.contains("~")) {
            val parts = cred.raw.split("~")
            for (disclosure in parts.drop(1).filter { it.isNotEmpty() }) {
                try {
                    val decoded = java.util.Base64.getUrlDecoder().decode(disclosure)
                    val arr = json.parseToJsonElement(String(decoded, Charsets.UTF_8))
                    val claimName = arr.jsonArray.getOrNull(1)?.jsonPrimitive?.contentOrNull
                    if (claimName != null) {
                        claims.add(claimName)
                    }
                } catch (_: Exception) {
                    // Skip unparseable disclosures
                }
            }
        }

        // Supplement from metadata claims if available
        cred.metadata?.claims?.forEach { claimMeta ->
            val name = claimMeta.path.lastOrNull()
            if (name != null) {
                claims.add(name)
            }
        }

        return claims.toList()
    }

    companion object {
        internal const val HKDF_INFO = "eDiplomas PRF"
        internal var createEngineSession: (String, String) -> WalletEngineSession =
            { baseUrl, tenantId -> WalletEngineSession(baseUrl, tenantId) }

        private val b64 = Base64.getEncoder()
        private val b64Dec = Base64.getDecoder()
        private val b64Url = Base64.getUrlEncoder().withoutPadding()

        private fun b64Encode(data: ByteArray): String = b64.encodeToString(data)
        private fun b64Decode(data: String): ByteArray = b64Dec.decode(data)
        private fun b64UrlEncode(data: ByteArray): String = b64Url.encodeToString(data)
        private fun b64UrlDecode(data: String): ByteArray = Base64.getUrlDecoder().decode(data)

        /**
         * Create the appropriate [AuthProvider] based on config.
         *
         * Defaults to [LocalAuthProvider] which works on API 28+ without
         * requiring a system credential provider or Google Play Services.
         * Set [WalletConfig.useSystemCredentialManager] to `true` to use
         * the system Credential Manager picker instead (requires API 34+
         * or a compatible credential provider on the device).
         */
        private fun createAuthProvider(activity: Activity, config: WalletConfig): AuthProvider {
            return if (config.useSystemCredentialManager) {
                Timber.i("Using system CredentialManager for passkeys")
                CredentialManagerAuthProvider(activity)
            } else {
                Timber.i("Using local KeyStore-backed passkey provider")
                LocalAuthProvider(activity, requireUserAuth = config.requireUserAuth)
            }
        }

        /**
         * Create a new [SirosWallet] instance.
         *
         * @param activity The host Activity (required for passkey UI).
         * @param config   Backend URL and tenant ID.
         */
        fun create(activity: Activity, config: WalletConfig): SirosWallet {
            return SirosWallet(activity, config)
        }
    }
}

