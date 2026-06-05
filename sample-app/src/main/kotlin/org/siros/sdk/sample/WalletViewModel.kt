package org.siros.sdk.sample

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import org.siros.sdk.auth.WebAuthnAuthClient
import org.siros.sdk.credentials.InMemoryCredentialStore
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.flow.FlowClient
import org.siros.sdk.flow.FlowEvent
import org.siros.sdk.flow.OID4VCIFlowParams
import org.siros.sdk.keystore.JweKeystore
import org.siros.sdk.transport.wmp.WmpCodec
import org.siros.sdk.transport.wmp.WmpSession
import org.siros.sdk.transport.wmp.WmpWebSocketTransport
import timber.log.Timber

sealed class WalletUiState {
    data class NotConnected(
        val backendUrl: String = "https://wallet.sirosid.dev",
        val tenantId: String = "",
    ) : WalletUiState()
    data object Connecting : WalletUiState()
    data class Connected(
        val isAuthenticated: Boolean = false,
        val userId: String? = null,
        val displayName: String? = null,
        val credentials: List<StoredCredential> = emptyList(),
    ) : WalletUiState()
    data class Error(val message: String) : WalletUiState()
}

class WalletViewModel : ViewModel() {

    private val _uiState = MutableStateFlow<WalletUiState>(WalletUiState.NotConnected())
    val uiState: StateFlow<WalletUiState> = _uiState

    private var backendUrl: String = "https://wallet.sirosid.dev"
    private var tenantId: String = ""
    private var transport: WmpWebSocketTransport? = null
    private var session: WmpSession? = null
    private var flowClient: FlowClient? = null
    private val keystore = JweKeystore()
    private val credentialStore = InMemoryCredentialStore()

    fun updateBackendUrl(url: String) {
        backendUrl = url
        _uiState.update { if (it is WalletUiState.NotConnected) it.copy(backendUrl = url) else it }
    }

    fun updateTenantId(id: String) {
        tenantId = id
        _uiState.update { if (it is WalletUiState.NotConnected) it.copy(tenantId = id) else it }
    }

    fun connect() {
        viewModelScope.launch {
            _uiState.value = WalletUiState.Connecting
            try {
                val extraHeaders = buildMap {
                    if (tenantId.isNotBlank()) put("X-Tenant-ID", tenantId)
                }
                val wsUrl = backendUrl.replace("https://", "wss://")
                    .replace("http://", "ws://") + "/wmp"
                transport = WmpWebSocketTransport(wsUrl, extraHeaders = extraHeaders)
                session = WmpSession(transport!!, WmpCodec())
                _uiState.value = WalletUiState.Connected()
                Timber.i("Transport created for $wsUrl")
            } catch (e: Exception) {
                Timber.e(e, "Connection failed")
                _uiState.value = WalletUiState.Error(e.message ?: "Connection failed")
            }
        }
    }

    fun login() {
        viewModelScope.launch {
            try {
                // TODO: Integrate with Android Credential Manager for real passkey auth.
                // For now, this demonstrates the flow structure.
                Timber.i("Login requested — requires Credential Manager integration")
                _uiState.update {
                    if (it is WalletUiState.Connected) {
                        it.copy(
                            isAuthenticated = true,
                            userId = "demo-user",
                            displayName = "Demo User",
                        )
                    } else it
                }
            } catch (e: Exception) {
                Timber.e(e, "Login failed")
                _uiState.value = WalletUiState.Error(e.message ?: "Login failed")
            }
        }
    }

    fun register() {
        viewModelScope.launch {
            try {
                // TODO: Integrate with Android Credential Manager for real passkey registration.
                Timber.i("Registration requested — requires Credential Manager integration")
            } catch (e: Exception) {
                Timber.e(e, "Registration failed")
                _uiState.value = WalletUiState.Error(e.message ?: "Registration failed")
            }
        }
    }

    fun startIssuance(credentialOfferUri: String) {
        viewModelScope.launch {
            try {
                val fc = flowClient ?: run {
                    val fc = FlowClient(session!!, keystore)
                    fc.start()
                    flowClient = fc

                    // Observe flow events
                    viewModelScope.launch {
                        fc.events().collect { event ->
                            handleFlowEvent(event)
                        }
                    }
                    fc
                }

                fc.startIssuance(OID4VCIFlowParams(credentialOfferUri = credentialOfferUri))
                Timber.i("Issuance flow started")
            } catch (e: Exception) {
                Timber.e(e, "Failed to start issuance")
                _uiState.value = WalletUiState.Error(e.message ?: "Issuance failed")
            }
        }
    }

    private suspend fun handleFlowEvent(event: FlowEvent) {
        when (event) {
            is FlowEvent.Complete -> {
                Timber.i("Flow ${event.flowId} completed")
                // Refresh credential list
                val credentials = credentialStore.getAll()
                _uiState.update {
                    if (it is WalletUiState.Connected) it.copy(credentials = credentials) else it
                }
            }
            is FlowEvent.Error -> {
                Timber.e("Flow ${event.flowId} error: ${event.message}")
            }
            is FlowEvent.Progress -> {
                Timber.d("Flow ${event.flowId} progress: ${event.step}")
            }
            is FlowEvent.SignRequest -> {
                Timber.d("Flow ${event.flowId} sign request: ${event.action}")
            }
            is FlowEvent.MatchRequest -> {
                Timber.d("Flow ${event.flowId} match request")
            }
        }
    }

    fun disconnect() {
        viewModelScope.launch {
            try {
                session?.close()
            } catch (e: Exception) {
                Timber.w(e, "Error during disconnect")
            }
            transport = null
            session = null
            flowClient = null
            keystore.lock()
            _uiState.value = WalletUiState.NotConnected(backendUrl, tenantId)
        }
    }

    override fun onCleared() {
        super.onCleared()
        keystore.lock()
    }
}
