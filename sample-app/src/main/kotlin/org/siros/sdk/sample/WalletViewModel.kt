package org.siros.sdk.sample

import android.app.Activity
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.wallet.SirosWallet
import org.siros.sdk.wallet.WalletConfig
import org.siros.sdk.wallet.WalletEventListener
import org.siros.sdk.wallet.WalletState

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

    private val _backendUrl = MutableStateFlow("https://wallet.sirosid.dev")
    val backendUrl: StateFlow<String> = _backendUrl

    private val _tenantId = MutableStateFlow("default")
    val tenantId: StateFlow<String> = _tenantId

    fun updateBackendUrl(url: String) { _backendUrl.value = url }
    fun updateTenantId(id: String) { _tenantId.value = id }

    // ── Wallet ──────────────────────────────────────────────────────

    private var wallet: SirosWallet = SirosWallet.create(
        activity,
        WalletConfig(_backendUrl.value, _tenantId.value),
    )

    /** Observable wallet state — collect this from your Composable. */
    val state: StateFlow<WalletState> get() = wallet.state

    init {
        // Wire up the event listener for credential selection UX
        wallet.setEventListener(object : WalletEventListener {
            override suspend fun onCredentialSelectionRequired(
                verifierName: String?,
                candidates: List<StoredCredential>,
            ): List<String> {
                // Auto-accept all candidates in the sample app.
                // A real app would show a picker dialog here.
                return candidates.map { it.id }
            }
        })
    }

    fun login() {
        rebuildWalletIfNeeded()
        viewModelScope.launch { wallet.login() }
    }

    fun register() {
        rebuildWalletIfNeeded()
        viewModelScope.launch { wallet.register("Sample User") }
    }

    fun startIssuance(credentialOfferUri: String) {
        viewModelScope.launch { wallet.startIssuance(credentialOfferUri) }
    }

    fun startPresentation(requestUri: String) {
        viewModelScope.launch { wallet.startPresentation(requestUri) }
    }

    fun disconnect() {
        wallet.logout()
    }

    /**
     * Rebuild the SirosWallet instance if the user changed the
     * backend URL or tenant ID since the last creation.
     */
    private fun rebuildWalletIfNeeded() {
        val current = wallet
        val currentState = current.state.value
        if (currentState is WalletState.Disconnected || currentState is WalletState.Error) {
            wallet = SirosWallet.create(
                activity,
                WalletConfig(_backendUrl.value, _tenantId.value),
            )
        }
    }
}
