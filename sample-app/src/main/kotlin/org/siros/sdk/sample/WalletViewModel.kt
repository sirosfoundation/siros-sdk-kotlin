package org.siros.sdk.sample

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
import org.siros.sdk.credentials.CredentialConsumptionPolicy
import org.siros.sdk.credentials.CredentialOffer
import org.siros.sdk.credentials.CredentialUtils
import org.siros.sdk.sample.dcapi.DCAPIProviderRegistration
import org.siros.sdk.sample.dcapi.WalletSessionHolder
import org.siros.sdk.credentials.PresentationRecord
import org.siros.sdk.credentials.SirosException
import org.siros.sdk.credentials.SignerSecurityProperties
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.keystore.ActivateLifecycleRequest
import org.siros.sdk.keystore.AuthProvider
import org.siros.sdk.keystore.DestroyLifecycleRequest
import org.siros.sdk.keystore.DestroyMode
import org.siros.sdk.keystore.DetailedKeyInfo
import org.siros.sdk.keystore.FactorKind
import org.siros.sdk.keystore.LifecycleState
import org.siros.sdk.keystore.LifecycleStatus
import org.siros.sdk.keystore.PlayIntegrityProvider
import org.siros.sdk.keystore.R2psAuthMode
import org.siros.sdk.keystore.R2psConfig
import org.siros.sdk.keystore.RegisterLifecycleRequest
import org.siros.sdk.keystore.RotateLifecycleRequest
import org.siros.sdk.keystore.UniFFISigner
import org.siros.sdk.keystore.WscdKeystoreAdapter
import org.siros.sdk.keystore.WscdManager
import org.siros.sdk.wallet.SirosWallet
import org.siros.sdk.wallet.WalletConfig
import org.siros.sdk.wallet.WalletEventListener
import org.siros.sdk.wallet.WalletState
import org.siros.sdk.wallet.PresentationRequest
import org.siros.sdk.wallet.DeepLinkType
import org.siros.sdk.wallet.classifyDeepLink
import uniffi.siros_wscd_manager.FfiWscdConfig

/** A terminal issuance/presentation flow failure, shown as a dialog with Retry/Cancel. */
data class FlowErrorInfo(val message: String, val canRetry: Boolean)

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

    // ── Configuration (editable before login) ───────────────────────

    private val _backendUrl: MutableStateFlow<String>
    val backendUrl: StateFlow<String> get() = _backendUrl

    // Raw text of the "Engine URL (blank = auto)" field - blank means "derive
    // from the current backend URL" (see resolvedEngineUrl()), not "use the
    // BuildConfig.ENGINE_URL local-dev default" as a previous version of this
    // code did. That silently pinned every connection to 127.0.0.1:8082 even
    // after backendUrl was changed to a remote host, which looked to the user
    // like a hung/timed-out registration (the WebAuthn ceremony itself
    // succeeded; only the following engine WebSocket connect failed).
    private val _engineUrlOverride: MutableStateFlow<String>
    val engineUrlOverride: StateFlow<String> get() = _engineUrlOverride

    private val _tenantId: MutableStateFlow<String>
    val tenantId: StateFlow<String> get() = _tenantId

    private val _useWmpProtocol: MutableStateFlow<Boolean>
    val useWmpProtocol: StateFlow<Boolean> get() = _useWmpProtocol

    private val _showCredentialDetails: MutableStateFlow<Boolean>
    val showCredentialDetails: StateFlow<Boolean> get() = _showCredentialDetails

    private val _showDiagnosticMessages: MutableStateFlow<Boolean>
    val showDiagnosticMessages: StateFlow<Boolean> get() = _showDiagnosticMessages

    private val _credentialConsumptionPolicy: MutableStateFlow<CredentialConsumptionPolicy>
    val credentialConsumptionPolicy: StateFlow<CredentialConsumptionPolicy> get() = _credentialConsumptionPolicy

    init {
        // Read test overrides - set either via the settings sheet UI, or (debug
        // builds only) via `adb shell am start ... --es backend_url ... --es
        // tenant_id ...` - see MainActivity.applyIntentTestOverrides(), which
        // copies matching intent extras into this same prefs store before the
        // ViewModel is constructed.
        val prefs = activity.getSharedPreferences("siros_test_overrides", android.content.Context.MODE_PRIVATE)
        _backendUrl = MutableStateFlow(prefs.getString("backend_url", null) ?: DEFAULT_BACKEND_URL)
        _engineUrlOverride = MutableStateFlow(prefs.getString("engine_url", null) ?: "")
        _tenantId = MutableStateFlow(prefs.getString("tenant_id", null) ?: DEFAULT_TENANT_ID)
        _useWmpProtocol = MutableStateFlow(prefs.getBoolean("use_wmp_protocol", false))
        // Default follows build type (on for debug, off for release) - a
        // manual override either way is persisted across restarts, so e.g. a
        // tester can still flip it on in a release build if needed.
        _showCredentialDetails = MutableStateFlow(
            prefs.getBoolean("show_credential_details", BuildConfig.DEBUG)
        )
        // Raw FlowStep tokens shown alongside the friendly progress label -
        // default false: seeing both together in practice is redundant, the
        // localized label alone is enough. Kept as an opt-in toggle for
        // debugging (was default true during initial rollout).
        _showDiagnosticMessages = MutableStateFlow(
            prefs.getBoolean("show_diagnostic_messages", false)
        )
        // Core wallet policy (not a UI-only preference like the toggles
        // above) - persisted here, but enforced by SirosWallet itself. Can't
        // set it on `wallet` right here - that property initializes later in
        // declaration order - see its own initializer and rebuildWalletIfNeeded(),
        // both of which apply this value to whichever SirosWallet instance is current.
        _credentialConsumptionPolicy = MutableStateFlow(
            runCatching {
                CredentialConsumptionPolicy.valueOf(
                    prefs.getString("credential_consumption_policy", null) ?: ""
                )
            }.getOrDefault(CredentialConsumptionPolicy.NEVER_CONSUME)
        )
    }

    fun updateBackendUrl(url: String) { _backendUrl.value = url }
    fun updateTenantId(id: String) { _tenantId.value = id }
    fun updateEngineUrl(url: String) { _engineUrlOverride.value = url }

    /**
     * Resolves the engine URL to actually connect to: an explicit override if
     * the user typed one, otherwise derived from the current backend URL -
     * same origin for any remote/reverse-proxied deployment (engine traffic
     * is split from backend traffic by path, e.g. wallet-proxy's
     * /api/v2/wallet, not by port), or backendUrl with the port swapped to
     * 8082 for plain localhost dev (where the engine really is a separate
     * listener on the same host).
     */
    private fun resolvedEngineUrl(): String {
        val override = _engineUrlOverride.value.trim()
        if (override.isNotBlank()) return override
        val backend = _backendUrl.value
        val isLocalhost = backend.contains("127.0.0.1") || backend.contains("localhost")
        return if (isLocalhost) backend.replace(Regex(":\\d+(?=/|$)"), ":8082") else backend
    }
    fun updateUseWmpProtocol(enabled: Boolean) {
        _useWmpProtocol.value = enabled
        activity.getSharedPreferences("siros_test_overrides", android.content.Context.MODE_PRIVATE)
            .edit()
            .putBoolean("use_wmp_protocol", enabled)
            .apply()
    }

    fun updateShowCredentialDetails(enabled: Boolean) {
        _showCredentialDetails.value = enabled
        activity.getSharedPreferences("siros_test_overrides", android.content.Context.MODE_PRIVATE)
            .edit()
            .putBoolean("show_credential_details", enabled)
            .apply()
    }

    fun updateShowDiagnosticMessages(enabled: Boolean) {
        _showDiagnosticMessages.value = enabled
        activity.getSharedPreferences("siros_test_overrides", android.content.Context.MODE_PRIVATE)
            .edit()
            .putBoolean("show_diagnostic_messages", enabled)
            .apply()
    }

    fun updateCredentialConsumptionPolicy(policy: CredentialConsumptionPolicy) {
        _credentialConsumptionPolicy.value = policy
        wallet.credentialConsumptionPolicy = policy
        activity.getSharedPreferences("siros_test_overrides", android.content.Context.MODE_PRIVATE)
            .edit()
            .putString("credential_consumption_policy", policy.name)
            .apply()
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

    /** Offer pending user confirmation before issuance starts. */
    private val _pendingIssuanceOffer = MutableStateFlow<CredentialOffer?>(null)
    val pendingIssuanceOffer: StateFlow<CredentialOffer?> = _pendingIssuanceOffer

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

    // ── Proximity (ISO 18013-5) engagement state ────────────────────

    private val _showProximityEngagement = MutableStateFlow(false)
    val showProximityEngagement: StateFlow<Boolean> = _showProximityEngagement

    fun openProximityEngagement() {
        _showProximityEngagement.value = true
    }

    fun closeProximityEngagement() {
        _showProximityEngagement.value = false
    }

    /** For `BlePeripheralServer`'s injected `getCredentials` dependency - see its constructor doc comment. */
    suspend fun getCredentialsForProximity() = wallet.getCredentials()

    /** For `BlePeripheralServer`'s injected `signPresentation` dependency. */
    suspend fun signMdocPresentationForProximity(
        credentialId: Long,
        disclosedClaims: List<String>?,
        sessionTranscriptBytes: ByteArray,
    ) = wallet.signMdocPresentationForProximity(credentialId, disclosedClaims, sessionTranscriptBytes)

    /** For `BlePeripheralServer`/`BleCentralClient`'s injected `filterEligible` dependency. */
    fun filterEligibleForProximity(instances: List<StoredCredential>): List<StoredCredential> =
        CredentialUtils.eligibleInstances(instances, wallet.credentialConsumptionPolicy, wallet.presentationHistory)

    // ── Loading / error feedback ────────────────────────────────────

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading

    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage

    fun clearError() { _errorMessage.value = null }

    // ── Info feedback (non-error, transient confirmations e.g. batch receipt) ─

    private val _infoMessage = MutableStateFlow<String?>(null)
    val infoMessage: StateFlow<String?> = _infoMessage

    fun clearInfo() { _infoMessage.value = null }

    /**
     * Credentials received so far in the current flow. Flows in this app run
     * one at a time, so a plain counter reset on consumption (in
     * onFlowComplete) is enough - no need to key it by flowId, which
     * onCredentialReceived doesn't carry anyway.
     */
    private var receivedCredentialCount = 0

    // ── Flow error feedback (issuance/presentation flows that fail server-side,
    // e.g. an untrusted issuer) ──────────────────────────────────────────────
    // Distinct from the transient Snackbar above: a flow error is terminal for
    // that flow (see SirosWallet's WalletEventListener.onFlowError), so the
    // user needs an explicit next action rather than a message that auto-dismisses.

    /** Re-runs whichever flow-starting call (QR scan or offer button) last ran, for Retry. */
    private var lastFlowRetry: (() -> Unit)? = null

    private val _flowErrorDialog = MutableStateFlow<FlowErrorInfo?>(null)
    val flowErrorDialog: StateFlow<FlowErrorInfo?> = _flowErrorDialog

    fun retryLastFlow() {
        val retry = lastFlowRetry
        _flowErrorDialog.value = null
        retry?.invoke()
    }

    fun dismissFlowError() {
        _flowErrorDialog.value = null
    }

    // ── Wallet ──────────────────────────────────────────────────────

    private var wallet: SirosWallet = SirosWallet.create(
        activity,
        buildWalletConfig(),
    ).also { it.credentialConsumptionPolicy = _credentialConsumptionPolicy.value }

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
            wallet.state.collect { newState ->
                _walletState.value = newState
                // Keep the DC API credential-provider registry (and the
                // session it presents against) in sync with the wallet's
                // actual state - see WalletSessionHolder's doc comment for
                // why the DC API Activity needs this instead of its own
                // login flow.
                when (newState) {
                    is WalletState.Ready -> {
                        WalletSessionHolder.update(wallet)
                        DCAPIProviderRegistration.refresh(activity, newState.credentials)
                    }
                    else -> {
                        WalletSessionHolder.update(null)
                        DCAPIProviderRegistration.clear(activity)
                    }
                }
            }
        }
    }

    /** Pending authorization flow ID (set when browser opens, consumed on redirect). */
    private var pendingAuthFlowId: String? = null

    // ── Presentation consent state ─────────────────────────────────

    private val _pendingPresentationRequest = MutableStateFlow<PresentationRequest?>(null)
    val pendingPresentationRequest: StateFlow<PresentationRequest?> = _pendingPresentationRequest

    private var presentationContinuation: kotlinx.coroutines.CancellableContinuation<List<Long>>? = null

    init {
        observeWalletState()
        setupEventListener()
    }

    private fun setupEventListener() {
        wallet.setEventListener(object : WalletEventListener {
            override suspend fun onCredentialSelectionRequired(
                request: PresentationRequest,
            ): List<Long> {
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

            override fun onFlowError(flowId: String, errorMessage: String) {
                Log.e(TAG, "Flow $flowId failed: $errorMessage")
                if (pendingAuthFlowId == flowId) {
                    pendingAuthFlowId = null
                }
                receivedCredentialCount = 0
                _flowErrorDialog.value = FlowErrorInfo(errorMessage, canRetry = lastFlowRetry != null)
            }

            override fun onCredentialReceived(credential: StoredCredential) {
                receivedCredentialCount++
            }

            override fun onFlowComplete(flowId: String) {
                if (receivedCredentialCount > 0) {
                    _infoMessage.value = activity.getString(
                        R.string.flow_credentials_received,
                        receivedCredentialCount,
                    )
                    receivedCredentialCount = 0
                } else if ((wallet.state.value as? WalletState.FlowActive)?.flowType == "presentation") {
                    // onFlowComplete fires before the SDK transitions FlowActive -> Ready
                    // (see SirosWallet's handleFlowComplete/WMP onComplete), so flowType
                    // is still readable here. Issuance gets the credential-count message
                    // above; presentation has no analogous per-item count, so a plain
                    // confirmation is the equivalent "something happened" signal for a
                    // flow whose whole point is watching this screen after a QR scan.
                    _infoMessage.value = activity.getString(R.string.flow_presentation_sent)
                }
            }
        })
    }

    /** User consented to share selected credentials. */
    fun acceptPresentation(selectedIds: List<Long>) {
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

    fun login(accountId: String? = null) {
        rebuildWalletIfNeeded()
        _isLoading.value = true
        viewModelScope.launch {
            try {
                wallet.login(accountId)
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

    /** Delete the current account - also removes it from the cached "Welcome back" list. */
    fun deleteAccount() {
        wallet.deleteAccount()
        _showAddCredential.value = false
        _availableCredentials.value = emptyList()
    }

    // ── Account & Passkey management ────────────────────────────────

    /** Remove a cached account from the local registry. */
    fun forgetAccount(accountId: String) {
        wallet.forgetAccount(accountId)
    }

    /** List passkeys registered for the current account. */
    fun listPasskeys(): List<org.siros.sdk.wallet.CachedPasskey> {
        return wallet.listPasskeys()
    }

    /** Rename a passkey's user-visible nickname. */
    fun renamePasskey(credentialId: String, nickname: String) {
        wallet.renamePasskey(credentialId, nickname)
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
                _errorMessage.value = e.message ?: "Failed to load available credentials"
            } finally {
                _isLoadingOffers.value = false
            }
        }
    }

    /** Close the add-credential screen. */
    fun closeAddCredential() {
        _showAddCredential.value = false
    }

    /** User picked a credential to issue. */
    fun selectCredentialOffer(offer: CredentialOffer) {
        _pendingIssuanceOffer.value = offer
    }

    /** User confirmed the pending issuance offer. */
    fun confirmIssuance() {
        val offer = _pendingIssuanceOffer.value ?: return
        _pendingIssuanceOffer.value = null
        _showAddCredential.value = false
        startIssuanceByOffer(offer)
    }

    /**
     * Re-request a fresh batch of [credential] directly from its own
     * issuer/config (already stored on it - see
     * [StoredCredential.credentialIssuerIdentifier]/[StoredCredential.credentialConfigurationId]),
     * skipping the generic issuer-browsing screen entirely - for
     * [CredentialCard]'s "Renew" action once every batch instance has been
     * used up (see [CredentialUtils.eligibleInstances]).
     */
    fun renewCredential(credential: StoredCredential) {
        val issuerId = credential.credentialIssuerIdentifier
        val configId = credential.credentialConfigurationId
        if (issuerId == null || configId == null) {
            _errorMessage.value = "Cannot renew this credential - issuer information is missing"
            return
        }
        startIssuanceByOffer(
            CredentialOffer(
                credentialConfigurationId = configId,
                credentialIssuerIdentifier = issuerId,
                credentialName = credential.metadata?.name ?: credential.format,
                issuerName = credential.metadata?.issuer?.name ?: issuerId,
            ),
        )
    }

    private fun startIssuanceByOffer(offer: CredentialOffer) {
        lastFlowRetry = { startIssuanceByOffer(offer) }
        viewModelScope.launch {
            try {
                wallet.startIssuanceByOffer(offer)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start issuance for ${offer.credentialConfigurationId}", e)
                _errorMessage.value = e.message ?: "Failed to start issuance"
            }
        }
    }

    /** User cancelled the pending issuance offer. */
    fun cancelIssuance() {
        _pendingIssuanceOffer.value = null
    }

    // ── Identity Verification (FaceTec IDV) ─────────────────────────

    /** IDV server URL — defaults to facetec-api co-hosted with the backend. */
    val idvServerUrl: String get() = _backendUrl.value.trimEnd('/') + "/idv"

    fun startIDV() {
        _showAddCredential.value = false
        viewModelScope.launch {
            try {
                _isLoading.value = true
                val token = wallet.getAccessToken() // Auth token for facetec-api
                val delegate = org.siros.sdk.idv.facetec.FaceTecCaptureDelegate()
                val client = org.siros.sdk.idv.RemoteIDVClient(
                    org.siros.sdk.idv.RemoteIDVClient.Config(
                        serverUrl = idvServerUrl,
                        authToken = "Bearer $token",
                    )
                )
                val provider = org.siros.sdk.idv.RemoteIDVProvider(client, delegate)
                wallet.verifyIdentityAndIssue(provider, activity)
            } catch (e: Exception) {
                android.util.Log.e("SIROS_VM", "IDV failed", e)
                _errorMessage.value = e.message ?: "Identity verification failed"
            } finally {
                _isLoading.value = false
            }
        }
    }

    // ── Credential detail ───────────────────────────────────────────

    fun openCredentialDetail(credential: StoredCredential) {
        if (!_showCredentialDetails.value) return
        _selectedCredential.value = credential
    }

    fun closeCredentialDetail() {
        _selectedCredential.value = null
    }

    fun deleteCredential(credentialId: Long) {
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

    /**
     * Stored reference to the UniFFISigner for diagnostic-only calls
     * ([UniFFISigner.listKeysDetailed]/[UniFFISigner.securityProperties])
     * that aren't part of the [WscdManager]/[org.siros.sdk.keystore.KeystoreManager]
     * surface at all - everything else (lifecycle, plugin registration)
     * goes through [wallet]'s own [SirosWallet.wscdManager].
     */
    private var wscdSigner: UniFFISigner? = null
    private var r2psRegistered = false

    /** Register the R2PS plugin on the given manager (idempotent). */
    private fun registerR2psOnSigner(manager: WscdManager) {
        if (r2psRegistered) return
        // Generate ephemeral P-256 key pair for the R2PS message envelope
        // (JWS/JWE identity) - required regardless of auth mode.
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
        val r2psConfig = R2psConfig(
            serverUrl = _r2psServerUrl.value,
            clientId = "sample-app",
            context = "wallet",
            clientKeyPem = clientKeyPem,
            serverPublicKeyPem = serverPubPem,
            authMode = R2psAuthMode.Opaque,
        )
        manager.registerR2psPlugin(r2psConfig, OkHttpR2psTransport(serverUrl = _r2psServerUrl.value))
        r2psRegistered = true
        Log.i(TAG, "R2PS plugin registered at ${_r2psServerUrl.value}")
    }

    private var fido2Registered = false

    /** Register the FIDO2 previewSign plugin on the given manager (idempotent). */
    private fun registerFido2OnSigner(manager: WscdManager) {
        if (fido2Registered) return
        val transport = UsbCtap2Transport(activity.applicationContext)
        manager.registerFido2Plugin(transport)
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
                val manager = wallet.wscdManager
                if (manager == null) {
                    _errorMessage.value = "WSCD signer not initialized"
                    return@launch
                }
                val pluginId = activePluginId
                // Lazily register R2PS plugin if switching at runtime
                if (pluginId == "r2ps") {
                    registerR2psOnSigner(manager)
                } else if (pluginId == "fido2") {
                    registerFido2OnSigner(manager)
                }
                val contextId = "ctx-${System.currentTimeMillis()}"
                val factorKind = when (pluginId) {
                    "r2ps" -> FactorKind.Opaque
                    else -> FactorKind.RawSign
                }

                val regOutcome = manager.registerLifecycle(
                    RegisterLifecycleRequest(
                        pluginId = pluginId,
                        contextId = contextId,
                        factorKind = factorKind,
                    ),
                )
                _lifecycleState.value = regOutcome.state
                Log.i(TAG, "Lifecycle registered: context=$contextId state=${regOutcome.state}")

                val actOutcome = manager.activateLifecycle(
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
            val signer = wscdSigner
            if (signer != null) {
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
            }
            val manager = wallet.wscdManager ?: return@launch
            val ctxId = lifecycleContextId ?: return@launch
            try {
                _wscdLifecycleStatus.value = manager.lifecycleStatus(activePluginId, ctxId)
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
            val manager = wallet.wscdManager
            val ctxId = lifecycleContextId
            if (manager == null || ctxId == null) {
                _errorMessage.value = "WSCD not enrolled"
                Log.e(MainActivity.WSCA_TEST_TAG, """{"action":"rotate","status":"error","error":"WSCD not enrolled (manager=${manager != null}, ctxId=$ctxId)"}""")
                return@launch
            }
            try {
                val outcome = manager.rotateLifecycle(
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
            val manager = wallet.wscdManager
            val ctxId = lifecycleContextId
            if (manager == null || ctxId == null) {
                _errorMessage.value = "WSCD not enrolled"
                Log.e(MainActivity.WSCA_TEST_TAG, """{"action":"destroy","status":"error","error":"WSCD not enrolled (manager=${manager != null}, ctxId=$ctxId)"}""")
                return@launch
            }
            try {
                val outcome = manager.destroyLifecycle(
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
        lastFlowRetry = { handleQrResult(uri) }
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
            ).also { it.credentialConsumptionPolicy = _credentialConsumptionPolicy.value }
            observeWalletState()
            setupEventListener()
        }
    }

    private fun buildWalletConfig(): WalletConfig {
        val proxyUrl = BuildConfig.ISSUER_PROXY_URL
        // Disable user-auth-bound keys on emulators/Waydroid where the lock screen
        // cannot be reliably unlocked via ADB.
        val isEmulator = Build.FINGERPRINT.contains("generic") ||
            Build.PRODUCT.contains("sdk") ||
            Build.MODEL.contains("Emulator") ||
            Build.HARDWARE == "ranchu" ||
            Build.MANUFACTURER.equals("waydroid", ignoreCase = true) ||
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
                    registerFido2OnSigner(signer)
                }
                Log.i(TAG, "WSCD keystore initialized with plugin: $selectedPlugin")
                wscdSigner = signer
                WscdKeystoreAdapter(signer)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to initialize WSCD keystore, falling back to default", e)
                null
            }

        // 0/unset = disabled (default) - a real cloud project number is tied
        // to the host app's own Play Console/Firebase project and can't be
        // hardcoded into the SDK or sample app; native attestation simply
        // stays off (matching pre-native-attestation behavior) until one is
        // supplied.
        val playIntegrityCloudProjectNumber = BuildConfig.PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER
        val nativeAttestationProvider = if (playIntegrityCloudProjectNumber != 0L) {
            PlayIntegrityProvider(activity, playIntegrityCloudProjectNumber)
        } else {
            null
        }

        return WalletConfig(
            backendUrl = _backendUrl.value,
            tenantId = _tenantId.value,
            // Explicit override > derived from backendUrl (see resolvedEngineUrl())
            engineUrl = resolvedEngineUrl(),
            useWmpProtocol = _useWmpProtocol.value,
            redirectUri = REDIRECT_URI,
            // Emulators/Waydroid don't reliably have a working Credential Manager
            // passkey provider - fall back to the local KeyStore-backed provider there.
            useSystemCredentialManager = !isEmulator,
            requireUserAuth = !isEmulator,
            keystore = keystore,
            nativeAttestationProvider = nativeAttestationProvider,
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
