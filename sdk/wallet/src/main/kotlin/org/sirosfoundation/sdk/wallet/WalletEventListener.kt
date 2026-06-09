// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.sirosfoundation.sdk.wallet

import org.sirosfoundation.sdk.credentials.StoredCredential

/**
 * Callback interface for wallet events that require user interaction.
 *
 * Implement this in your Activity or Fragment and pass it to
 * [SirosWallet.setEventListener]. All callbacks are invoked on the
 * main thread.
 */
interface WalletEventListener {

    /**
     * A verifier has requested credentials. The app should present a
     * picker UI and return the IDs the user has consented to share.
     *
     * Return an empty list to cancel the presentation.
     */
    suspend fun onCredentialSelectionRequired(
        verifierName: String?,
        candidates: List<StoredCredential>,
    ): List<String>

    /**
     * A new credential has been received from an issuer.
     * The SDK has already stored it — this callback is for
     * showing a confirmation / toast.
     */
    fun onCredentialReceived(credential: StoredCredential) {}

    /**
     * Called when a flow completes (issuance or presentation).
     */
    fun onFlowComplete(flowId: String) {}

    /**
     * Called when a flow fails.
     */
    fun onFlowError(flowId: String, errorMessage: String) {}

    /**
     * An issuer requires user authorization (OAuth consent).
     *
     * The app should open [authorizationUrl] in a Custom Tab or browser.
     * When the user approves and the browser redirects to [redirectUri],
     * call [SirosWallet.completeAuthorization] with the received `code`
     * and `state` query parameters.
     *
     * @param flowId The flow that requires authorization.
     * @param authorizationUrl The URL to open for user consent.
     * @param redirectUri The expected redirect URI (register as an app link).
     * @param state OAuth state parameter for CSRF validation.
     */
    fun onAuthorizationRequired(
        flowId: String,
        authorizationUrl: String,
        redirectUri: String,
        state: String,
    ) {}
}
