package org.siros.sdk.sample

import android.app.Activity
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.siros.sdk.auth.AuthSession
import org.siros.sdk.auth.BackendApiClient
import org.siros.sdk.auth.CredentialManagerAuthProvider
import org.siros.sdk.auth.WebAuthnAuthClient
import org.siros.sdk.transport.engine.WalletEngineSession
import timber.log.Timber

sealed class WalletUiState {
    data class NotConnected(
        val backendUrl: String = "https://wallet.sirosid.dev",
        val tenantId: String = "default",
    ) : WalletUiState()
    data object Connecting : WalletUiState()
    data class Connected(
        val isAuthenticated: Boolean = false,
        val userId: String? = null,
        val displayName: String? = null,
        val flowStatus: String? = null,
    ) : WalletUiState()
    data class Error(val message: String) : WalletUiState()
}

class WalletViewModel(private val activity: Activity) : ViewModel() {

    class Factory(private val activity: Activity) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return WalletViewModel(activity) as T
        }
    }

    private val _uiState = MutableStateFlow<WalletUiState>(WalletUiState.NotConnected())
    val uiState: StateFlow<WalletUiState> = _uiState

    private var backendUrl: String = "https://wallet.sirosid.dev"
    private var tenantId: String = "default"
    private var engineSession: WalletEngineSession? = null
    private var apiClient: BackendApiClient? = null
    private var authSession: AuthSession? = null

    private val authProvider = CredentialManagerAuthProvider(activity)

    fun updateBackendUrl(url: String) {
        backendUrl = url
        _uiState.update { if (it is WalletUiState.NotConnected) it.copy(backendUrl = url) else it }
    }

    fun updateTenantId(id: String) {
        tenantId = id
        _uiState.update { if (it is WalletUiState.NotConnected) it.copy(tenantId = id) else it }
    }

    /**
     * Connect the engine WebSocket and start observing flow events.
     * Called automatically after successful login/register.
     */
    private fun connectEngine(appToken: String) {
        val tid = tenantId.ifBlank { "default" }
        engineSession = WalletEngineSession(backendUrl, tid)
        engineSession!!.connect(appToken)

        viewModelScope.launch {
            engineSession!!.flowProgress().collect { msg ->
                Timber.d("Flow ${msg.flowId} progress: ${msg.step}")
                _uiState.update {
                    if (it is WalletUiState.Connected) it.copy(flowStatus = "${msg.step}") else it
                }
            }
        }
        viewModelScope.launch {
            engineSession!!.flowComplete().collect { msg ->
                Timber.i("Flow ${msg.flowId} complete: ${msg.credentials?.size ?: 0} credentials")
                _uiState.update {
                    if (it is WalletUiState.Connected) it.copy(flowStatus = "complete") else it
                }
            }
        }
        viewModelScope.launch {
            engineSession!!.flowErrors().collect { msg ->
                Timber.e("Flow ${msg.flowId} error: ${msg.error.code} — ${msg.error.message}")
                _uiState.update {
                    if (it is WalletUiState.Connected) it.copy(flowStatus = "error: ${msg.error.message}") else it
                }
            }
        }
        viewModelScope.launch {
            engineSession!!.signRequests().collect { msg ->
                Timber.d("Sign request: ${msg.action} for flow ${msg.flowId}")
                // TODO: Generate proof JWT using keystore and send sign_response
            }
        }
        viewModelScope.launch {
            engineSession!!.matchRequests().collect { msg ->
                Timber.d("Match request for flow ${msg.flowId}")
                // TODO: Match credentials locally and send match_response
            }
        }
    }

    private fun onAuthSuccess(session: AuthSession) {
        authSession = session
        apiClient = BackendApiClient(backendUrl, tenantId.ifBlank { "default" }).apply {
            setAppToken(session.appToken)
        }
        connectEngine(session.appToken)
        _uiState.value = WalletUiState.Connected(
            isAuthenticated = true,
            userId = session.uuid,
            displayName = session.displayName,
        )
    }

    fun login() {
        viewModelScope.launch {
            _uiState.value = WalletUiState.Connecting
            try {
                val tid = tenantId.ifBlank { "default" }
                val authClient = WebAuthnAuthClient(backendUrl, tid, authProvider)
                val session = authClient.login()
                Timber.i("Login successful: ${session.uuid}")
                onAuthSuccess(session)
            } catch (e: Exception) {
                Timber.e(e, "Login failed")
                _uiState.value = WalletUiState.Error(e.message ?: "Login failed")
            }
        }
    }

    fun register() {
        viewModelScope.launch {
            _uiState.value = WalletUiState.Connecting
            try {
                val tid = tenantId.ifBlank { "default" }
                val authClient = WebAuthnAuthClient(backendUrl, tid, authProvider)
                val session = authClient.register("Sample User")
                Timber.i("Registration successful: ${session.uuid}")
                onAuthSuccess(session)
            } catch (e: Exception) {
                Timber.e(e, "Registration failed")
                _uiState.value = WalletUiState.Error(e.message ?: "Registration failed")
            }
        }
    }

    /** Start an OID4VCI issuance flow via the engine WebSocket. */
    fun startIssuance(credentialOfferUri: String) {
        viewModelScope.launch {
            try {
                val engine = engineSession
                    ?: throw IllegalStateException("Engine not connected — login first")
                engine.startIssuance(credentialOfferUri = credentialOfferUri)
                Timber.i("Issuance flow started")
            } catch (e: Exception) {
                Timber.e(e, "Failed to start issuance")
                _uiState.value = WalletUiState.Error(e.message ?: "Issuance failed")
            }
        }
    }

    /** Start an OID4VP presentation flow via the engine WebSocket. */
    fun startPresentation(requestUri: String) {
        viewModelScope.launch {
            try {
                val engine = engineSession
                    ?: throw IllegalStateException("Engine not connected — login first")
                engine.startPresentation(requestUri = requestUri)
                Timber.i("Presentation flow started")
            } catch (e: Exception) {
                Timber.e(e, "Failed to start presentation")
                _uiState.value = WalletUiState.Error(e.message ?: "Presentation failed")
            }
        }
    }

    fun disconnect() {
        engineSession?.disconnect()
        engineSession = null
        apiClient = null
        authSession = null
        _uiState.value = WalletUiState.NotConnected(backendUrl, tenantId)
    }

    override fun onCleared() {
        super.onCleared()
        engineSession?.disconnect()
    }
}
