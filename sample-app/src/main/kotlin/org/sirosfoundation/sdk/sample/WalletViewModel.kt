package org.sirosfoundation.sdk.sample

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import org.sirosfoundation.sdk.credentials.CredentialOffer
import org.sirosfoundation.sdk.credentials.PresentationRecord
import org.sirosfoundation.sdk.credentials.StoredCredential
import org.sirosfoundation.sdk.wallet.SirosWallet
import org.sirosfoundation.sdk.wallet.WalletConfig
import org.sirosfoundation.sdk.wallet.WalletEventListener
import org.sirosfoundation.sdk.wallet.WalletState
import org.sirosfoundation.sdk.wallet.PresentationRequest
import org.sirosfoundation.sdk.wallet.DeepLinkType
import org.sirosfoundation.sdk.wallet.classifyDeepLink

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

    private val _backendUrl = MutableStateFlow(DEFAULT_BACKEND_URL)
    val backendUrl: StateFlow<String> = _backendUrl

    private val _tenantId = MutableStateFlow(DEFAULT_TENANT_ID)
    val tenantId: StateFlow<String> = _tenantId

    fun updateBackendUrl(url: String) { _backendUrl.value = url }
    fun updateTenantId(id: String) { _tenantId.value = id }

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

    /** Observable wallet state — collect this from your Composable. */
    val state: StateFlow<WalletState> get() = wallet.state

    /** Pending authorization flow ID (set when browser opens, consumed on redirect). */
    private var pendingAuthFlowId: String? = null

    // ── Presentation consent state ─────────────────────────────────

    private val _pendingPresentationRequest = MutableStateFlow<PresentationRequest?>(null)
    val pendingPresentationRequest: StateFlow<PresentationRequest?> = _pendingPresentationRequest

    private var presentationContinuation: kotlinx.coroutines.CancellableContinuation<List<String>>? = null

    init {
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
            _errorMessage.value = "Authorization failed: no pending flow"
        }
    }

    fun login() {
        rebuildWalletIfNeeded()
        _isLoading.value = true
        viewModelScope.launch {
            try {
                wallet.login()
            } catch (e: Exception) {
                _errorMessage.value = e.message ?: "Login failed"
            } finally {
                _isLoading.value = false
            }
        }
    }

    fun register() {
        rebuildWalletIfNeeded()
        _isLoading.value = true
        viewModelScope.launch {
            try {
                wallet.register("Sample User")
            } catch (e: Exception) {
                _errorMessage.value = e.message ?: "Registration failed"
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
                _errorMessage.value = e.message ?: "Issuance failed"
            }
        }
    }

    fun startPresentation(requestUri: String) {
        viewModelScope.launch {
            try {
                wallet.startPresentation(requestUri)
            } catch (e: Exception) {
                Log.e(TAG, "startPresentation failed", e)
                _errorMessage.value = e.message ?: "Presentation failed"
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
    }

    /** User picked a credential to issue. */
    fun selectCredentialOffer(offer: CredentialOffer) {
        _showAddCredential.value = false
        viewModelScope.launch { wallet.startIssuanceByOffer(offer) }
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
            setupEventListener()
        }
    }

    private fun buildWalletConfig(): WalletConfig {
        val proxyUrl = BuildConfig.ISSUER_PROXY_URL
        return WalletConfig(
            backendUrl = _backendUrl.value,
            tenantId = _tenantId.value,
            redirectUri = REDIRECT_URI,
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
        private const val REDIRECT_URI = "siros-sample://callback"
        private const val REDIRECT_SCHEME = "siros-sample"
    }
}
