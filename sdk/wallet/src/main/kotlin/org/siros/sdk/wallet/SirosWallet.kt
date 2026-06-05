// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

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
import org.siros.sdk.auth.AuthSession
import org.siros.sdk.auth.BackendApiClient
import org.siros.sdk.auth.CredentialManagerAuthProvider
import org.siros.sdk.auth.WebAuthnAuthClient
import org.siros.sdk.credentials.CredentialStore
import org.siros.sdk.credentials.InMemoryCredentialStore
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.credentials.CredentialOffer
import org.siros.sdk.credentials.IssuerEntry
import org.siros.sdk.credentials.IssuerMetadata
import org.siros.sdk.credentials.CredentialConfiguration
import org.siros.sdk.keystore.JweKeystore
import org.siros.sdk.keystore.KeystoreManager
import org.siros.sdk.transport.engine.CredentialMatch
import org.siros.sdk.transport.engine.WalletEngineSession
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
     */
    suspend fun register(displayName: String) {
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
            val credId = authProvider.lastCredentialId
                ?: throw WalletException("No credential ID after registration")
            val prfOutput = authProvider.lastPrfOutput
                ?: throw WalletException("PRF not supported by authenticator — cannot encrypt wallet data")

            // Derive key and initialise empty keystore
            keystore.unlock(prfOutput.first, ByteArray(0), hkdfSalt, hkdfInfo)

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
        } catch (e: Exception) {
            Timber.e(e, "Registration failed")
            _state.value = WalletState.Error(e.message ?: "Registration failed")
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

            val credId = authProvider.lastCredentialId
                ?: throw WalletException("No credential ID after login")
            val prfOutput = authProvider.lastPrfOutput
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
        } catch (e: Exception) {
            Timber.e(e, "Login failed")
            _state.value = WalletState.Error(e.message ?: "Login failed")
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
     * Fetch the list of available credential issuers from the backend.
     *
     * Requires an active session (call after [login] or [register]).
     * Each [IssuerEntry] contains the issuer URL; call [getAvailableCredentials]
     * to discover what credentials each issuer offers.
     */
    suspend fun getIssuers(): List<IssuerEntry> = withContext(Dispatchers.IO) {
        val client = apiClient ?: throw WalletException("Not connected")
        val response = client.getIssuers()
        // Backend returns either a JSON array or { "issuers": [...] }
        val arr = response["issuers"]?.jsonArray
            ?: response["data"]?.jsonArray
            ?: throw WalletException("Unexpected issuer list format")
        arr.map { json.decodeFromJsonElement(IssuerEntry.serializer(), it) }
            .filter { it.visible }
    }

    /**
     * Fetch OpenID4VCI credential issuer metadata for a given issuer URL.
     *
     * This calls `<issuerUrl>/.well-known/openid-credential-issuer` directly.
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
        val offers = mutableListOf<CredentialOffer>()

        for (issuer in issuers) {
            try {
                val metadata = getIssuerMetadata(issuer.credentialIssuerIdentifier)
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
        val credentialOffer = kotlinx.serialization.json.buildJsonObject {
            put("credential_issuer", kotlinx.serialization.json.JsonPrimitive(
                offer.credentialIssuerIdentifier
            ))
            put("credential_configuration_ids", kotlinx.serialization.json.buildJsonArray {
                add(kotlinx.serialization.json.JsonPrimitive(offer.credentialConfigurationId))
            })
            put("grants", kotlinx.serialization.json.buildJsonObject {
                put("authorization_code", kotlinx.serialization.json.buildJsonObject {})
            })
        }
        engine.startIssuance(offer = credentialOffer.toString())
    }

    /**
     * Start a credential issuance flow with a raw offer or URI.
     *
     * @param offerUri a credential_offer_uri or raw JSON credential_offer string.
     */
    suspend fun startIssuance(offerUri: String) {
        val engine = engineSession ?: throw WalletException("Not connected")
        if (offerUri.startsWith("openid-credential-offer://") || offerUri.startsWith("http")) {
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

    // ── Internal wiring ─────────────────────────────────────────────

    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private val sessionStore = SessionStore(activity)
    private val authProvider = CredentialManagerAuthProvider(activity)
    private val keystore: KeystoreManager = JweKeystore()
    private val credentialStore: CredentialStore = InMemoryCredentialStore()
    private val json = Json { ignoreUnknownKeys = true }
    private val httpClient = OkHttpClient()

    private var apiClient: BackendApiClient? = null
    private var engineSession: WalletEngineSession? = null
    private var eventListener: WalletEventListener? = null

    private fun setupApiClient(session: AuthSession) {
        apiClient = BackendApiClient(config.backendUrl, config.tenantId).apply {
            setAppToken(session.appToken)
        }
    }

    private suspend fun fetchPrivateData(): ByteArray {
        val client = apiClient ?: throw WalletException("Not authenticated")
        return try {
            val response = client.getPrivateData()
            val pd = response["privateData"]?.jsonPrimitive?.content
            if (pd != null) {
                sessionStore.privateDataJwe = pd
                pd.toByteArray(Charsets.UTF_8)
            } else {
                ByteArray(0)
            }
        } catch (e: Exception) {
            Timber.w(e, "Could not fetch privateData, starting with empty keystore")
            ByteArray(0)
        }
    }

    private suspend fun syncPrivateDataToBackend() {
        val client = apiClient ?: return
        val jwe = sessionStore.privateDataJwe ?: return
        try {
            val body = kotlinx.serialization.json.buildJsonObject {
                put("\$b64u", kotlinx.serialization.json.JsonPrimitive(
                    b64UrlEncode(jwe.toByteArray(Charsets.UTF_8))
                ))
            }
            client.updatePrivateData(body)
            Timber.d("Private data synced to backend")
        } catch (e: Exception) {
            Timber.e(e, "Failed to sync private data")
        }
    }

    private fun connectEngine(appToken: String) {
        val engine = WalletEngineSession(config.backendUrl, config.tenantId)
        engineSession = engine
        engine.connect(appToken)

        // Observe sign requests → auto-sign with keystore
        scope.launch {
            engine.signRequests().collect { msg ->
                try {
                    Timber.d("Sign request: ${msg.action} for flow ${msg.flowId}")
                    val proof = when (msg.action) {
                        "generateOpenid4vciProof" -> {
                            val params = msg.params
                            keystore.generateProof(
                                audience = params?.audience ?: "",
                                nonce = params?.nonce ?: "",
                            )
                        }
                        "signJwtPresentation" -> {
                            val params = msg.params
                            keystore.signPresentation(
                                nonce = params?.nonce ?: "",
                                audience = params?.audience ?: "",
                                credentialIds = emptyList(),
                            )
                        }
                        else -> {
                            Timber.w("Unknown sign action: ${msg.action}")
                            null
                        }
                    }
                    if (proof != null) {
                        engine.sendSignResponse(msg.flowId, proof)
                    }
                } catch (e: Exception) {
                    Timber.e(e, "Error handling sign request")
                }
            }
        }

        // Observe match requests → credential matching
        scope.launch {
            engine.matchRequests().collect { msg ->
                try {
                    Timber.d("Match request for flow ${msg.flowId}")
                    val allCreds = credentialStore.getAll()
                    val listener = eventListener

                    val selectedIds = if (listener != null && allCreds.isNotEmpty()) {
                        listener.onCredentialSelectionRequired(null, allCreds)
                    } else {
                        allCreds.map { it.id }
                    }

                    val matches = selectedIds.mapNotNull { id ->
                        allCreds.find { it.id == id }?.let { cred ->
                            CredentialMatch(credentialId = cred.id, format = cred.format)
                        }
                    }
                    engine.sendMatchResponse(msg.flowId, matches)
                } catch (e: Exception) {
                    Timber.e(e, "Error handling match request")
                }
            }
        }

        // Observe flow progress
        scope.launch {
            engine.flowProgress().collect { msg ->
                Timber.d("Flow ${msg.flowId} progress: ${msg.step}")
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
                    val stored = StoredCredential(
                        id = java.util.UUID.randomUUID().toString(),
                        format = cred.format,
                        raw = cred.credential,
                    )
                    credentialStore.save(stored)
                    eventListener?.onCredentialReceived(stored)
                }

                // Re-export and sync the updated keystore
                if (keystore.isUnlocked) {
                    try {
                        val container = keystore.exportEncryptedContainer()
                        sessionStore.privateDataJwe = String(container, Charsets.UTF_8)
                        syncPrivateDataToBackend()
                    } catch (e: Exception) {
                        Timber.e(e, "Failed to sync keystore after flow")
                    }
                }

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

    companion object {
        internal const val HKDF_INFO = "SIROS Wallet PRF"

        private val b64 = Base64.getEncoder()
        private val b64Dec = Base64.getDecoder()
        private val b64Url = Base64.getUrlEncoder().withoutPadding()

        private fun b64Encode(data: ByteArray): String = b64.encodeToString(data)
        private fun b64Decode(data: String): ByteArray = b64Dec.decode(data)
        private fun b64UrlEncode(data: ByteArray): String = b64Url.encodeToString(data)

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

class WalletException(message: String, cause: Throwable? = null) : Exception(message, cause)
