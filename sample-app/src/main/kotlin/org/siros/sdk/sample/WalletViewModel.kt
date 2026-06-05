package org.siros.sdk.sample

import android.app.Activity
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import org.siros.sdk.credentials.CredentialOffer
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

    private val _backendUrl = MutableStateFlow("https://backend.id.siros.org")
    val backendUrl: StateFlow<String> = _backendUrl

    private val _tenantId = MutableStateFlow("default")
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

    // ── Loading / error feedback ────────────────────────────────────

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading

    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage

    fun clearError() { _errorMessage.value = null }

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
        viewModelScope.launch { wallet.startIssuance(credentialOfferUri) }
    }

    fun startPresentation(requestUri: String) {
        viewModelScope.launch { wallet.startPresentation(requestUri) }
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
            } catch (_: Exception) {
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
