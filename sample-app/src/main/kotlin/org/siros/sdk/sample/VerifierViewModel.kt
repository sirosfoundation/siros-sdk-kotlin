// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.siros.sdk.verifier.mdoc.MdocDocumentRequest
import org.siros.sdk.verifier.mdoc.MdocReaderInbound
import org.siros.sdk.verifier.mdoc.MdocRequestedElement
import org.siros.sdk.verifier.mdoc.MdocRequestedNamespace
import org.siros.sdk.verifier.mdoc.proximity.MdocEngagement
import org.siros.sdk.verifier.mdoc.proximity.MdocMessageTransport
import org.siros.sdk.verifier.mdoc.proximity.MdocProximityVerifier
import org.siros.sdk.verifier.mdoc.proximity.MdocQrEngagementParser
import org.siros.sdk.verifier.trust.AuthZenDeniedException
import org.siros.sdk.verifier.trust.AuthZenPdp
import org.siros.sdk.verifier.trust.HttpAuthZenPdp

/** Account-free verifier flow. It has no dependency on WalletViewModel or SirosWallet. */
class VerifierViewModel(
    private val transportFactory: suspend (MdocEngagement, CoroutineScope) -> MdocMessageTransport,
    private val pdpFactory: (String, String) -> AuthZenPdp = { endpoint, tenant ->
        HttpAuthZenPdp(endpoint, tenant)
    },
    private val nfcHandoverReader: (suspend () -> MdocEngagement)? = null,
) : ViewModel() {
    private val _state = MutableStateFlow(
        VerifierUiState(endpoint = BuildConfig.DEFAULT_VERIFIER_PDP_URL),
    )
    val state: StateFlow<VerifierUiState> = _state
    private var verificationJob: Job? = null

    fun updateEndpoint(value: String) = _state.update { it.copy(endpoint = value) }

    fun updateTenant(value: String) = _state.update { it.copy(tenantId = value) }

    fun bluetoothPermissionsDenied() {
        _state.update {
            it.copy(documents = emptyList(), error = "Bluetooth permissions are required for proximity verification")
        }
    }

    fun startScan() {
        if (_state.value.busy) return
        _state.update {
            it.copy(scanning = true, documents = emptyList(), error = null, status = null)
        }
    }

    fun cancelScan() = _state.update { it.copy(scanning = false) }

    fun clear() {
        if (!_state.value.busy) {
            _state.update { it.copy(documents = emptyList(), error = null, status = null) }
        }
    }

    fun cancelVerification() {
        verificationJob?.cancel()
    }

    fun onQrScanned(value: String) {
        startVerification { MdocQrEngagementParser.parse(value) }
    }

    fun startNfc() {
        val reader = nfcHandoverReader
        if (reader == null) {
            showError("NFC static handover is unavailable on this device")
            return
        }
        startVerification(reader)
    }

    private fun startVerification(produceEngagement: suspend () -> MdocEngagement) {
        if (_state.value.busy) return
        _state.update { it.copy(scanning = false, busy = true, documents = emptyList(), error = null) }
        verificationJob = viewModelScope.launch {
            var session: org.siros.sdk.verifier.mdoc.proximity.MdocReaderSession? = null
            var transport: MdocMessageTransport? = null
            try {
                _state.update { it.copy(status = "Reading device engagement") }
                val engagement = produceEngagement()
                val verifier = MdocProximityVerifier(pdpFactory(_state.value.endpoint, _state.value.tenantId))
                val activeSession = verifier.start(engagement, defaultRequest)
                session = activeSession
                val activeTransport = transportFactory(engagement, this)
                transport = activeTransport

                _state.update { it.copy(status = "Requesting presentation") }
                activeTransport.send(activeSession.establishmentMessage())
                _state.update { it.copy(status = "Waiting for presentation") }
                when (val inbound = activeSession.openResponse(activeTransport.receive())) {
                    is MdocReaderInbound.Verified -> {
                        _state.update {
                            it.copy(documents = inbound.documents, status = null, error = null)
                        }
                        runCatching { activeTransport.send(activeSession.terminationMessage()) }
                    }
                    is MdocReaderInbound.SessionOver -> {
                        _state.update {
                            it.copy(documents = emptyList(), error = "Wallet ended the session with status ${inbound.status}")
                        }
                    }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: AuthZenDeniedException) {
                showError("go-trust denied this issuer")
            } catch (e: Exception) {
                showError(e.message ?: "Verification failed")
            } finally {
                session?.close()
                withContext(NonCancellable) { transport?.close() }
                _state.update { it.copy(busy = false, status = null) }
            }
        }
    }

    private fun showError(message: String) {
        _state.update { it.copy(documents = emptyList(), error = message, status = null) }
    }

    companion object {
        private val defaultRequest = listOf(
            MdocDocumentRequest(
                docType = "org.iso.18013.5.1.mDL",
                namespaces = listOf(
                    MdocRequestedNamespace(
                        namespace = "org.iso.18013.5.1",
                        elements = listOf(
                            MdocRequestedElement("given_name"),
                            MdocRequestedElement("family_name"),
                        ),
                    ),
                ),
            ),
        )
    }
}
