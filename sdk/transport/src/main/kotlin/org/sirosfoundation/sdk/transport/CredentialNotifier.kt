package org.sirosfoundation.sdk.transport

/**
 * Transport-independent interface for sending OID4VCI §10 credential
 * lifecycle notifications.
 *
 * Both the legacy WebSocket engine ([WalletEngineSession]) and the WMP
 * [FlowClient] implement this so the wallet facade can send notifications
 * regardless of the active transport binding.
 */
interface CredentialNotifier {
    /**
     * Send a credential lifecycle notification (e.g. `credential_accepted`
     * or `credential_failure`).
     *
     * Implementations should be fire-and-forget: best-effort delivery,
     * no-op when not connected.
     */
    fun sendCredentialNotification(
        flowId: String,
        notificationId: String,
        event: String,
        eventDescription: String? = null,
    )
}
