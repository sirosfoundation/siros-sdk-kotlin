package org.sirosfoundation.sdk.sample

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import org.sirosfoundation.sdk.credentials.CredentialOffer
import org.sirosfoundation.sdk.credentials.PresentationRecord
import org.sirosfoundation.sdk.credentials.SirosException
import org.sirosfoundation.sdk.credentials.SignerSecurityProperties
import org.sirosfoundation.sdk.credentials.StoredCredential
import org.sirosfoundation.sdk.keystore.ActivateLifecycleRequest
import org.sirosfoundation.sdk.keystore.AuthProvider
import org.sirosfoundation.sdk.keystore.DestroyLifecycleRequest
import org.sirosfoundation.sdk.keystore.DestroyMode
import org.sirosfoundation.sdk.keystore.DetailedKeyInfo
import org.sirosfoundation.sdk.keystore.FactorKind
import org.sirosfoundation.sdk.keystore.LifecycleState
import org.sirosfoundation.sdk.keystore.LifecycleStatus
import org.sirosfoundation.sdk.keystore.RegisterLifecycleRequest
import org.sirosfoundation.sdk.keystore.RotateLifecycleRequest
import org.sirosfoundation.sdk.keystore.UniFFISigner
import org.sirosfoundation.sdk.keystore.WscdKeystoreAdapter
import org.sirosfoundation.sdk.wallet.SirosWallet
import org.sirosfoundation.sdk.wallet.WalletConfig
import org.sirosfoundation.sdk.wallet.WalletEventListener
import org.sirosfoundation.sdk.wallet.WalletState
import org.sirosfoundation.sdk.wallet.PresentationRequest
import org.sirosfoundation.sdk.wallet.DeepLinkType
import org.sirosfoundation.sdk.wallet.classifyDeepLink
import uniffi.siros_wscd_manager.FfiR2psConfig
import uniffi.siros_wscd_manager.FfiWscdConfig

/**
 * Sample app ViewModel.
 *
 * The entire wallet lifecycle — auth, key management, engine protocol,
 * credential storage — is handled by [SirosWallet]. This ViewModel only
 * needs to expose UI-level state and forward user actions.
 */
class WalletViewModel(private val activity: Activity) : ViewModel() {

    class Factory(private val activity: Activity) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return WalletViewModel(activity) as T
        }
    }

    // ── Configuration ──────────────────────────────────────────────

    private val prefs = activity.getSharedPreferences("siros_settings", android.content.Context.MODE_PRIVATE)

    /** Backend URL — editable from settings, persisted across restarts. */
    private val _backendUrl = MutableStateFlow(
        prefs.getString("backend_url", null) ?: DEFAULT_BACKEND_URL
    )
    val backendUrl: String get() = _backendUrl.value
    val backendUrlFlow: StateFlow<String> = _backendUrl

    /** Tenant ID — editable from settings, persisted across restarts. */
    private val _tenantId = MutableStateFlow(
        prefs.getString("tenant_id", null) ?: DEFAULT_TENANT_ID
    )
    val tenantId: String get() = _tenantId.value
    val tenantIdFlow: StateFlow<String> = _tenantId

    /** Engine URL override — blank means derive from backendUrl. */
    private val _engineUrl = MutableStateFlow(
        prefs.getString("engine_url", null) ?: BuildConfig.ENGINE_URL
    )
    val engineUrl: String get() = _engineUrl.value
    val engineUrlFlow: StateFlow<String> = _engineUrl

    /** Use WMP JSON-RPC 2.0 protocol instead of legacy engine protocol. */
    private val _useWmpProtocol = MutableStateFlow(
        prefs.getBoolean("use_wmp_protocol", false)
    )
    val useWmpProtocol: StateFlow<Boolean> = _useWmpProtocol

    fun updateBackendUrl(url: String) {
        _backendUrl.value = url
        prefs.edit().putString("backend_url", url).apply()
    }

    fun updateTenantId(id: String) {
        _tenantId.value = id
        prefs.edit().putString("tenant_id", id).apply()
    }

    fun updateEngineUrl(url: String) {
        _engineUrl.value = url
        prefs.edit().putString("engine_url", url).apply()
    }

    fun updateUseWmpProtocol(enabled: Boolean) {
        _useWmpProtocol.value = enabled
        prefs.edit().putBoolean("use_wmp_protocol", enabled).apply()
    }

    // ── Plugin / R2PS configuration ──────────────────────────────────

    /** Active plugin ID: "softkey", "r2ps", or "fido2". */
    private val _selectedPluginId = MutableStateFlow(
        if (BuildConfig.R2PS_ENABLED) "r2ps" else "softkey",
    )
    val selectedPluginId: StateFlow<String> = _selectedPluginId

    private val _r2psEnabled = MutableStateFlow(BuildConfig.R2PS_ENABLED)
    val r2psEnabled: StateFlow<Boolean> = _r2psEnabled

    private val _r2psServerUrl = MutableStateFlow(DEFAULT_R2PS_URL)
    val r2psServerUrl: StateFlow<String> = _r2psServerUrl

    fun selectPlugin(pluginId: String) {
        _selectedPluginId.value = pluginId
        _r2psEnabled.value = pluginId == "r2ps"
    }
    fun updateR2psEnabled(enabled: Boolean) {
        _r2psEnabled.value = enabled
        if (enabled) _selectedPluginId.value = "r2ps"
        else if (_selectedPluginId.value == "r2ps") _selectedPluginId.value = "softkey"
    }
    fun updateR2psServerUrl(url: String) { _r2psServerUrl.value = url }

    // ── Add-credential state ────────────────────────────────────────

    private val _availableCredentials = MutableStateFlow<List<CredentialOffer>>(emptyList())
    val availableCredentials: StateFlow<List<CredentialOffer>> = _availableCredentials

    private val _isLoadingOffers = MutableStateFlow(false)
    val isLoadingOffers: StateFlow<Boolean> = _isLoadingOffers

    private val _showAddCredential = MutableStateFlow(false)
    val showAddCredential: StateFlow<Boolean> = _showAddCredential

    // ── Credential detail state ─────────────────────────────────────

    private val _selectedCredential = MutableStateFlow<StoredCredential?>(null)
    val selectedCredential: StateFlow<StoredCredential?> = _selectedCredential

    // ── Presentation history ────────────────────────────────────────

    private val _presentationHistory = MutableStateFlow<List<PresentationRecord>>(emptyList())
    val presentationHistory: StateFlow<List<PresentationRecord>> = _presentationHistory

    private val _showHistory = MutableStateFlow(false)
    val showHistory: StateFlow<Boolean> = _showHistory

    // ── QR scanner state ────────────────────────────────────────────

    private val _showQrScanner = MutableStateFlow(false)
    val showQrScanner: StateFlow<Boolean> = _showQrScanner

    // ── Loading / error feedback ────────────────────────────────────

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading

    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage

    fun clearError() { _errorMessage.value = null }

    // ── Wallet ──────────────────────────────────────────────────────

    private var wallet: SirosWallet = SirosWallet.create(
        activity,
        buildWalletConfig(),
    )

    /**
     * Observable wallet state — collect this from your Composable.
     * Exposed via an indirection so that rebuilding the wallet (which
     * replaces the [SirosWallet] instance) does not leave Compose
     * subscribed to the old, destroyed instance's state flow.
     */
    private val _walletState = MutableStateFlow<WalletState>(wallet.state.value)
    val state: StateFlow<WalletState> = _walletState
    private var walletStateJob: Job? = null

    private fun observeWalletState() {
        walletStateJob?.cancel()
        walletStateJob = viewModelScope.launch {
            wallet.state.collect { _walletState.value = it }
        }
    }

    /** Pending authorization flow ID (set when browser opens, consumed on redirect). */
    private var pendingAuthFlowId: String? = null

    // ── Presentation consent state ─────────────────────────────────

    private val _pendingPresentationRequest = MutableStateFlow<PresentationRequest?>(null)
    val pendingPresentationRequest: StateFlow<PresentationRequest?> = _pendingPresentationRequest

    private var presentationContinuation: kotlinx.coroutines.CancellableContinuation<List<String>>? = null

    init {
        observeWalletState()
        setupEventListener()
    }

    private fun setupEventListener() {
        wallet.setEventListener(object : WalletEventListener {
            override suspend fun onCredentialSelectionRequired(
                request: PresentationRequest,
            ): List<String> {
                // Show consent UI and suspend until user responds
                return kotlinx.coroutines.suspendCancellableCoroutine { cont ->
                    presentationContinuation = cont
                    _pendingPresentationRequest.value = request
                }
            }

            override fun onAuthorizationRequired(
                flowId: String,
                authorizationUrl: String,
                redirectUri: String,
                state: String,
            ) {
                Log.d(TAG, "Authorization required for flow $flowId")
                pendingAuthFlowId = flowId

                // The SDK already applies the urlRewriter from WalletConfig,
                // so authorizationUrl is the external URL ready for the browser.
                Log.d(TAG, "Opening browser: $authorizationUrl")
                val intent = Intent(Intent.ACTION_VIEW, Uri.parse(authorizationUrl))
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                activity.startActivity(intent)
            }

            override fun onTxCodeRequired(
                flowId: String,
                description: String?,
            ): String? {
                Log.i(TAG, "tx_code required for flow $flowId: $description")
                // Extract PIN from description (e.g. "Input the one-time code: <123456> for testing purposes")
                val match = Regex("<(\\d+)>").find(description ?: "")
                val pin = match?.groupValues?.get(1)
                if (pin != null) {
                    Log.i(TAG, "Auto-providing tx_code from description: $pin")
                    return pin
                }
                Log.w(TAG, "No tx_code found in description, cannot auto-respond")
                return null
            }
        })
    }

    /** User consented to share selected credentials. */
    fun acceptPresentation(selectedIds: List<String>) {
        _pendingPresentationRequest.value = null
        presentationContinuation?.resume(selectedIds, null)
        presentationContinuation = null
    }

    /** User declined the presentation request. */
    fun declinePresentation() {
        _pendingPresentationRequest.value = null
        presentationContinuation?.resume(emptyList(), null)
        presentationContinuation = null
    }

    /**
     * Handle an OAuth redirect from the browser.
     * Called by MainActivity when the deep-link classifier returns [DeepLinkType.AuthCallback].
     */
    fun handleAuthRedirect(code: String, state: String) {
        val flowId = pendingAuthFlowId

        if (flowId != null) {
            Log.i(TAG, "Auth redirect: code=${code.take(8)}..., state=${state.take(8)}...")
            pendingAuthFlowId = null
            wallet.completeAuthorization(flowId, code, state)
        } else {
            Log.e(TAG, "Auth redirect but no pending flow")
            _errorMessage.value = activity.getString(R.string.error_auth_failed)
        }
    }

    fun login() {
        rebuildWalletIfNeeded()
        _isLoading.value = true
        viewModelScope.launch {
            try {
                wallet.login()
            } catch (e: Exception) {
                _errorMessage.value = localizedErrorMessage(e)
            } finally {
                _isLoading.value = false
            }
        }
    }

    fun register(displayName: String) {
        rebuildWalletIfNeeded()
        _isLoading.value = true
        viewModelScope.launch {
            try {
                wallet.register(displayName)
            } catch (e: Exception) {
                _errorMessage.value = localizedErrorMessage(e)
            } finally {
                _isLoading.value = false
            }
        }
    }

    /** Forget a cached account (remove from login screen). */
    fun forgetAccount(accountId: String) {
        wallet.forgetAccount(accountId)
    }

    // ── Passkey Management ──────────────────────────────────────────

    /** Passkeys for the active account. */
    fun listPasskeys(): List<org.sirosfoundation.sdk.wallet.CachedPasskey> = wallet.listPasskeys()

    /** Rename a passkey. */
    fun renamePasskey(credentialId: String, nickname: String) {
        wallet.renamePasskey(credentialId, nickname)
    }

    fun startIssuance(credentialOfferUri: String) {
        viewModelScope.launch {
            try {
                wallet.startIssuance(credentialOfferUri)
            } catch (e: Exception) {
                Log.e(TAG, "startIssuance failed", e)
                _errorMessage.value = localizedErrorMessage(e)
            }
        }
    }

    fun startPresentation(requestUri: String) {
        viewModelScope.launch {
            try {
                wallet.startPresentation(requestUri)
            } catch (e: Exception) {
                Log.e(TAG, "startPresentation failed", e)
                _errorMessage.value = localizedErrorMessage(e)
            }
        }
    }

    /**
     * Auto-authenticate for testing/conformance only.
     * Only active in debug builds — production apps must require explicit user login.
     */
    private suspend fun ensureAuthenticatedForTesting() {
        if (!BuildConfig.DEBUG) return // No-op in release builds
        fun isConnectedState(state: WalletState): Boolean {
            return state is WalletState.Ready || state is WalletState.FlowActive
        }

        suspend fun waitForConnected(timeoutMs: Long = 15000): Boolean {
            val started = System.currentTimeMillis()
            while (System.currentTimeMillis() - started < timeoutMs) {
                if (isConnectedState(wallet.state.value)) return true
                delay(200)
            }
            return isConnectedState(wallet.state.value)
        }

        // Already connected? Done.
        if (isConnectedState(wallet.state.value)) return

        // If state is Connecting, wait briefly for it to finish.
        if (wallet.state.value is WalletState.Connecting) {
            if (waitForConnected()) return
        }

        // Rebuild wallet if in Error state so login/register start fresh.
        if (wallet.state.value is WalletState.Error) {
            rebuildWalletIfNeeded()
        }

        try {
            Log.i(TAG, "Automation auth: attempting login")
            wallet.login()
            if (waitForConnected()) return
            Log.w(TAG, "Automation auth: login returned but wallet not ready, trying register")
        } catch (e: Exception) {
            Log.w(TAG, "Automation auth: login failed (${e.message}), trying register")
        }

        // Rebuild if login left us in Error state.
        if (wallet.state.value is WalletState.Error) {
            rebuildWalletIfNeeded()
        }

        try {
            Log.i(TAG, "Automation auth: attempting register")
            wallet.register("Conformance User")
            if (waitForConnected()) return
        } catch (e: Exception) {
            Log.e(TAG, "Automation auth: register failed", e)
            throw e
        }

        if (!isConnectedState(wallet.state.value)) {
            throw IllegalStateException("Wallet not connected after auth (state=${wallet.state.value})")
        }
    }

    fun cancelCurrentFlow() {
        wallet.cancelCurrentFlow()
    }

    fun disconnect() {
        wallet.logout()
        _showAddCredential.value = false
        _availableCredentials.value = emptyList()
    }

    /** Open the add-credential screen — fetches available offers from issuers. */
    fun openAddCredential() {
        _showAddCredential.value = true
        _isLoadingOffers.value = true
        viewModelScope.launch {
            try {
                _availableCredentials.value = wallet.getAvailableCredentials()
                android.util.Log.d("SIROS_VM", "Available credentials: ${_availableCredentials.value.size}")
            } catch (e: Exception) {
                android.util.Log.e("SIROS_VM", "getAvailableCredentials failed", e)
                _availableCredentials.value = emptyList()
            } finally {
                _isLoadingOffers.value = false
            }
        }
    }

    /** Close the add-credential screen. */
    fun closeAddCredential() {
        _showAddCredential.value = false
        _pendingIssuanceOffer.value = null
    }

    /** Offer awaiting user consent before issuance starts. */
    private val _pendingIssuanceOffer = MutableStateFlow<CredentialOffer?>(null)
    val pendingIssuanceOffer: StateFlow<CredentialOffer?> = _pendingIssuanceOffer

    /** User picked a credential — show consent first. */
    fun selectCredentialOffer(offer: CredentialOffer) {
        _pendingIssuanceOffer.value = offer
    }

    /** User confirmed issuance consent. */
    fun confirmIssuance() {
        val offer = _pendingIssuanceOffer.value ?: return
        _pendingIssuanceOffer.value = null
        _showAddCredential.value = false
        viewModelScope.launch { wallet.startIssuanceByOffer(offer) }
    }

    /** User declined issuance. */
    fun cancelIssuance() {
        _pendingIssuanceOffer.value = null
    }

    // ── Credential detail ───────────────────────────────────────────

    fun openCredentialDetail(credential: StoredCredential) {
        _selectedCredential.value = credential
    }

    fun closeCredentialDetail() {
        _selectedCredential.value = null
    }

    fun deleteCredential(credentialId: String) {
        _selectedCredential.value = null
        viewModelScope.launch {
            try {
                wallet.deleteCredential(credentialId)
            } catch (e: Exception) {
                _errorMessage.value = e.message ?: "Delete failed"
            }
        }
    }

    // ── Presentation history ────────────────────────────────────────

    fun openHistory() {
        _presentationHistory.value = wallet.presentationHistory
        _showHistory.value = true
    }

    fun closeHistory() {
        _showHistory.value = false
    }

    // ── WSCD lifecycle ──────────────────────────────────────────────

    private val _lifecycleState = MutableStateFlow<LifecycleState?>(null)
    val lifecycleState: StateFlow<LifecycleState?> = _lifecycleState

    private val _enrollmentInProgress = MutableStateFlow(false)
    val enrollmentInProgress: StateFlow<Boolean> = _enrollmentInProgress

    /** Stored reference to the UniFFISigner for lifecycle operations. */
    private var wscdSigner: UniFFISigner? = null
    private var r2psRegistered = false

    /** Register the R2PS plugin on the given signer (idempotent). */
    private fun registerR2psOnSigner(signer: UniFFISigner) {
        if (r2psRegistered) return
        // Generate ephemeral P-256 key pair for channel binding
        val kpg = java.security.KeyPairGenerator.getInstance("EC")
        kpg.initialize(java.security.spec.ECGenParameterSpec("secp256r1"))
        val kp = kpg.generateKeyPair()
        val clientKeyPem = "-----BEGIN PRIVATE KEY-----\n" +
            android.util.Base64.encodeToString(kp.private.encoded, android.util.Base64.NO_WRAP)
                .chunked(64).joinToString("\n") +
            "\n-----END PRIVATE KEY-----"
        val serverPubPem = "-----BEGIN PUBLIC KEY-----\n" +
            android.util.Base64.encodeToString(kp.public.encoded, android.util.Base64.NO_WRAP)
                .chunked(64).joinToString("\n") +
            "\n-----END PUBLIC KEY-----"
        val r2psConfig = FfiR2psConfig(
            serverUrl = _r2psServerUrl.value,
            clientId = "sample-app",
            context = "wallet",
            authMode = "opaque",
            rpId = "",
            allowedCredentialIds = emptyList(),
            clientKeyPem = clientKeyPem,
            serverPublicKeyPem = serverPubPem,
        )
        signer.registerR2psPlugin(
            r2psConfig,
            OkHttpR2psTransport(serverUrl = _r2psServerUrl.value),
            SamplePakeClient(),
        )
        r2psRegistered = true
        Log.i(TAG, "R2PS plugin registered at ${_r2psServerUrl.value}")
    }

    private var fido2Registered = false

    /** Register the FIDO2 previewSign plugin on the given signer (idempotent). */
    private fun registerFido2OnSigner(signer: UniFFISigner) {
        if (fido2Registered) return
        val transport = UsbCtap2Transport(activity.applicationContext)
        signer.registerFido2Plugin(transport)
        fido2Registered = true
        Log.i(TAG, "FIDO2 previewSign plugin registered")
    }

    /**
     * Enroll the WSCD: register + activate lifecycle.
     * Identity binding is handled separately via OID4VCI credential issuance
     * (deferred flow + key attestation), not at this layer.
     */
    fun enrollWscd() {
        _enrollmentInProgress.value = true
        viewModelScope.launch {
            try {
                val signer = wscdSigner
                if (signer == null) {
                    _errorMessage.value = "WSCD signer not initialized"
                    return@launch
                }
                val pluginId = activePluginId
                // Lazily register R2PS plugin if switching at runtime
                if (pluginId == "r2ps") {
                    registerR2psOnSigner(signer)
                } else if (pluginId == "fido2") {
                    registerFido2OnSigner(signer)
                }
                val contextId = "ctx-${System.currentTimeMillis()}"
                val factorKind = when (pluginId) {
                    "r2ps" -> FactorKind.Opaque
                    else -> FactorKind.RawSign
                }

                val regOutcome = signer.registerLifecycle(
                    RegisterLifecycleRequest(
                        pluginId = pluginId,
                        contextId = contextId,
                        factorKind = factorKind,
                    ),
                )
                _lifecycleState.value = regOutcome.state
                Log.i(TAG, "Lifecycle registered: context=$contextId state=${regOutcome.state}")

                val actOutcome = signer.activateLifecycle(
                    ActivateLifecycleRequest(
                        pluginId = pluginId,
                        contextId = contextId,
                    ),
                )
                _lifecycleState.value = actOutcome.state
                lifecycleContextId = contextId
                Log.i(TAG, "Lifecycle activated: context=$contextId state=${actOutcome.state}")
                Log.i(MainActivity.WSCA_TEST_TAG, """{"action":"enroll","status":"ok","state":"${actOutcome.state}","context_id":"$contextId"}""")
            } catch (e: Exception) {
                Log.e(TAG, "WSCD enrollment failed", e)
                Log.e(MainActivity.WSCA_TEST_TAG, """{"action":"enroll","status":"error","error":"${e.message?.replace("\"", "'")}"}""")
                _errorMessage.value = "Enrollment failed: ${e.message}"
            } finally {
                _enrollmentInProgress.value = false
            }
        }
    }

    // ── WSCA developer screen state ─────────────────────────────────

    private val _showWscaDeveloper = MutableStateFlow(false)
    val showWscaDeveloper: StateFlow<Boolean> = _showWscaDeveloper

    private val _wscdKeys = MutableStateFlow<List<DetailedKeyInfo>>(emptyList())
    val wscdKeys: StateFlow<List<DetailedKeyInfo>> = _wscdKeys

    private val _wscdKeySecurityProps = MutableStateFlow<Map<String, SignerSecurityProperties>>(emptyMap())
    val wscdKeySecurityProps: StateFlow<Map<String, SignerSecurityProperties>> = _wscdKeySecurityProps

    private val _wscdLifecycleStatus = MutableStateFlow<LifecycleStatus?>(null)
    val wscdLifecycleStatus: StateFlow<LifecycleStatus?> = _wscdLifecycleStatus

    /** The context ID used for the current lifecycle session. */
    private var lifecycleContextId: String? = null

    /** The plugin ID used for the current lifecycle session. */
    private val activePluginId: String
        get() = _selectedPluginId.value

    fun openWscaDeveloper() {
        _showWscaDeveloper.value = true
        refreshWscdInfo()
    }

    fun closeWscaDeveloper() {
        _showWscaDeveloper.value = false
    }

    fun refreshWscdInfo() {
        viewModelScope.launch {
            val signer = wscdSigner ?: return@launch
            try {
                val keys = signer.listKeysDetailed()
                _wscdKeys.value = keys
                val props = mutableMapOf<String, SignerSecurityProperties>()
                for (key in keys) {
                    try {
                        props[key.keyId] = signer.securityProperties(key.keyId)
                    } catch (e: Exception) {
                        Log.w(TAG, "Failed to get security properties for ${key.keyId}", e)
                    }
                }
                _wscdKeySecurityProps.value = props
            } catch (e: Exception) {
                Log.w(TAG, "Failed to list keys", e)
            }
            val ctxId = lifecycleContextId ?: return@launch
            try {
                _wscdLifecycleStatus.value = signer.lifecycleStatus(activePluginId, ctxId)
                _lifecycleState.value = _wscdLifecycleStatus.value?.state
            } catch (e: Exception) {
                Log.w(TAG, "Failed to get lifecycle status", e)
            }
        }
    }

    /**
     * Emit WSCA status as structured JSON to logcat for test automation.
     * The test harness parses lines with tag [MainActivity.WSCA_TEST_TAG].
     */
    fun emitWscaTestStatus() {
        viewModelScope.launch {
            val signer = wscdSigner
            val state = _lifecycleState.value?.name ?: "null"
            val ctxId = lifecycleContextId ?: "null"
            val plugin = activePluginId
            val keys = try {
                signer?.listKeysDetailed()?.joinToString(",") { k ->
                    """{"kid":"${k.keyId}","alg":"${k.algorithm}","plugin":"${k.pluginId}","created":${k.createdAt}}"""
                } ?: ""
            } catch (_: Exception) { "" }
            val json = """{"action":"status","state":"$state","context_id":"$ctxId","plugin":"$plugin","r2ps_enabled":${_r2psEnabled.value},"keys":[$keys]}"""
            Log.i(MainActivity.WSCA_TEST_TAG, json)
        }
    }

    fun rotateLifecycle() {
        viewModelScope.launch {
            val signer = wscdSigner
            val ctxId = lifecycleContextId
            if (signer == null || ctxId == null) {
                _errorMessage.value = "WSCD not enrolled"
                Log.e(MainActivity.WSCA_TEST_TAG, """{"action":"rotate","status":"error","error":"WSCD not enrolled (signer=${signer != null}, ctxId=$ctxId)"}""")
                return@launch
            }
            try {
                val outcome = signer.rotateLifecycle(
                    RotateLifecycleRequest(
                        pluginId = activePluginId,
                        contextId = ctxId,
                    ),
                )
                _lifecycleState.value = outcome.state
                Log.i(TAG, "Lifecycle rotated: context=$ctxId state=${outcome.state}")
                Log.i(MainActivity.WSCA_TEST_TAG, """{"action":"rotate","status":"ok","state":"${outcome.state}","context_id":"$ctxId"}""")
                refreshWscdInfo()
            } catch (e: Exception) {
                Log.e(TAG, "Lifecycle rotation failed", e)
                Log.e(MainActivity.WSCA_TEST_TAG, """{"action":"rotate","status":"error","error":"${e.message?.replace("\"", "'")}"}""")
                _errorMessage.value = "Rotation failed: ${e.message}"
            }
        }
    }

    fun destroyLifecycle(mode: DestroyMode) {
        viewModelScope.launch {
            val signer = wscdSigner
            val ctxId = lifecycleContextId
            if (signer == null || ctxId == null) {
                _errorMessage.value = "WSCD not enrolled"
                Log.e(MainActivity.WSCA_TEST_TAG, """{"action":"destroy","status":"error","error":"WSCD not enrolled (signer=${signer != null}, ctxId=$ctxId)"}""")
                return@launch
            }
            try {
                val outcome = signer.destroyLifecycle(
                    DestroyLifecycleRequest(
                        pluginId = activePluginId,
                        contextId = ctxId,
                        mode = mode,
                    ),
                )
                _lifecycleState.value = outcome.state
                lifecycleContextId = null
                Log.i(TAG, "Lifecycle destroyed: mode=$mode state=${outcome.state}")
                Log.i(MainActivity.WSCA_TEST_TAG, """{"action":"destroy","status":"ok","state":"${outcome.state}","mode":"$mode"}""")
                refreshWscdInfo()
            } catch (e: Exception) {
                Log.e(TAG, "Lifecycle destruction failed", e)
                Log.e(MainActivity.WSCA_TEST_TAG, """{"action":"destroy","status":"error","error":"${e.message?.replace("\"", "'")}"}""")
                _errorMessage.value = "Destruction failed: ${e.message}"
            }
        }
    }

    // ── QR scanner ──────────────────────────────────────────────────

    fun openQrScanner() {
        _showQrScanner.value = true
    }

    fun closeQrScanner() {
        _showQrScanner.value = false
    }

    fun handleQrResult(uri: String) {
        _showQrScanner.value = false
        viewModelScope.launch {
            try {
                val jUri = try { java.net.URI(uri) } catch (_: Exception) { null }
                Log.i(TAG, "handleQrResult: ${jUri?.scheme}://${jUri?.host}")
                ensureAuthenticatedForTesting()
                when (val link = classifyDeepLink(uri, REDIRECT_SCHEME)) {
                    is DeepLinkType.CredentialOffer -> {
                        Log.i(TAG, "Routing to issuance")
                        wallet.startIssuance(link.uri)
                    }
                    is DeepLinkType.PresentationRequest -> {
                        Log.i(TAG, "Routing to presentation")
                        wallet.startPresentation(link.uri)
                    }
                    else -> {
                        // Fallback: treat unclassified URIs as presentation requests
                        // (covers plain https://...?request_uri= patterns from QR codes)
                        Log.i(TAG, "Routing to presentation (unclassified)")
                        wallet.startPresentation(uri)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "QR/deep-link flow failed", e)
                _errorMessage.value = e.message ?: "QR flow failed"
            }
        }
    }

    /**
     * Rebuild the SirosWallet instance if the user changed the
     * backend URL or tenant ID since the last creation.
     */
    private fun rebuildWalletIfNeeded() {
        val current = wallet
        val currentState = current.state.value
        if (currentState is WalletState.Disconnected || currentState is WalletState.Error) {
            current.destroy()
            wallet = SirosWallet.create(
                activity,
                buildWalletConfig(),
            )
            observeWalletState()
            setupEventListener()
        }
    }

    private fun buildWalletConfig(): WalletConfig {
        val proxyUrl = BuildConfig.ISSUER_PROXY_URL
        // Disable user-auth-bound keys on emulators/Waydroid where the lock screen
        // cannot be reliably unlocked via ADB.
        val isEmulator = Build.FINGERPRINT?.contains("generic") == true ||
            Build.PRODUCT?.contains("sdk") == true ||
            Build.MODEL?.contains("Emulator") == true ||
            Build.HARDWARE == "ranchu" ||
            Build.MANUFACTURER?.equals("waydroid", ignoreCase = true) == true ||
            Build.BRAND == "google" && Build.DEVICE?.startsWith("generic") == true

        // Build WSCD-backed keystore with the selected plugin
        val selectedPlugin = _selectedPluginId.value
        val keystore = try {
                val wscdConfig = FfiWscdConfig(defaultPlugin = selectedPlugin)
                val signer = UniFFISigner(
                    wscdConfig,
                    authProvider = object : AuthProvider {
                        override fun requestPin(): ByteArray {
                            // Debug builds use a fixed test PIN for R2PS OPAQUE registration
                            return "test-pin-1234".toByteArray()
                        }
                        override fun requestWebauthnAssertion(
                            challenge: ByteArray,
                            rpId: String,
                            allowedCredentials: List<ByteArray>,
                        ): ByteArray {
                            throw RuntimeException("WebAuthn assertion not implemented in sample app")
                        }
                    },
                )
                if (selectedPlugin == "r2ps") {
                    registerR2psOnSigner(signer)
                } else if (selectedPlugin == "fido2") {
                    val transport = UsbCtap2Transport(activity.applicationContext)
                    signer.registerFido2Plugin(transport)
                }
                Log.i(TAG, "WSCD keystore initialized with plugin: $selectedPlugin")
                wscdSigner = signer
                WscdKeystoreAdapter(signer)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to initialize WSCD keystore, falling back to default", e)
                null
            }

        return WalletConfig(
            backendUrl = backendUrl,
            tenantId = tenantId,
            redirectUri = REDIRECT_URI,
            requireUserAuth = !isEmulator,
            keystore = keystore,
            engineUrl = _engineUrl.value.ifBlank { null },
            useWmpProtocol = _useWmpProtocol.value,
            urlRewriter = if (proxyUrl.isNotBlank()) { url ->
                // Rewrite Docker-internal issuer URLs to the dev proxy
                url.replace("https://vc-proxy:8443", proxyUrl)
                    .replace("http://vc-proxy:8443", proxyUrl)
            } else null,
        )
    }

    companion object {
        private const val TAG = "SIROS_VM"
        private val DEFAULT_BACKEND_URL = BuildConfig.DEFAULT_BACKEND_URL
        private const val DEFAULT_TENANT_ID = "default"
        private const val DEFAULT_R2PS_URL = "http://192.168.240.1:9443"
        private const val REDIRECT_URI = "siros-sample://callback"
        private const val REDIRECT_SCHEME = "siros-sample"

        /** Map SDK error codes to Android string resource IDs. */
        private val ERROR_CODE_RESOURCES = mapOf(
            "network_error" to R.string.error_network_error,
            "network_timeout" to R.string.error_network_timeout,
            "auth_failed" to R.string.error_auth_failed,
            "auth_expired" to R.string.error_auth_expired,
            "keystore_error" to R.string.error_keystore_error,
            "keystore_locked" to R.string.error_keystore_locked,
            "wallet_error" to R.string.error_wallet_error,
            "wallet_not_connected" to R.string.error_wallet_not_connected,
            "wallet_prf_unsupported" to R.string.error_wallet_prf_unsupported,
            "idv_cancelled" to R.string.error_idv_cancelled,
            "idv_unavailable" to R.string.error_idv_unavailable,
            "idv_liveness_failed" to R.string.error_idv_liveness_failed,
            "idv_verification_failed" to R.string.error_idv_verification_failed,
            "idv_network_error" to R.string.error_idv_network_error,
            "ctap2_not_available" to R.string.error_ctap2_not_available,
            "ctap2_connection_failed" to R.string.error_ctap2_connection_failed,
            "ctap2_timeout" to R.string.error_ctap2_timeout,
            "ctap2_device_disconnected" to R.string.error_ctap2_device_disconnected,
            "insufficient_credentials" to R.string.error_insufficient_credentials,
            "flow_error" to R.string.error_flow_error,
        )
    }

    /**
     * Resolve a localized error message from an exception.
     * Uses [SirosException.errorCode] to look up a translated string resource,
     * falling back to the generic error message if no match is found.
     */
    private fun localizedErrorMessage(e: Exception): String {
        val code = (e as? SirosException)?.errorCode
        val resId = code?.let { ERROR_CODE_RESOURCES[it] }
        return if (resId != null) {
            activity.getString(resId)
        } else {
            activity.getString(R.string.error_generic)
        }
    }
}
