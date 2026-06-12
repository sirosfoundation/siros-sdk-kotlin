// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.sirosfoundation.sdk.wallet

import org.sirosfoundation.sdk.credentials.CredentialMatcher
import org.sirosfoundation.sdk.credentials.StoredCredential

/**
 * Context provided when a verifier requests credential presentation.
 *
 * Contains the matched credentials, requested claims, and optional
 * verifier identity so the app can render an informed consent screen.
 */
data class PresentationRequest(
    /** Verifier display name (from trust evaluation), null if unknown. */
    val verifierName: String?,
    /** Matched credentials grouped by DCQL query. */
    val matchResults: List<CredentialMatcher.MatchResult>,
    /** Flat list of candidate credentials (convenience). */
    val candidates: List<StoredCredential>,
    /** DCQL credential set constraints, null if no `credential_sets` in query. */
    val credentialSets: List<CredentialMatcher.CredentialSetQuery>? = null,
    /** Which credential set options are satisfiable with available credentials. */
    val satisfiableOptions: List<CredentialMatcher.SatisfiableOption> = emptyList(),
)

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
     * consent UI showing the verifier name and requested claims,
     * then return the IDs the user has consented to share.
     *
     * The [request] parameter provides verifier identity and the
     * DCQL match results including which claims are requested.
     *
     * Return an empty list to cancel the presentation.
     */
    suspend fun onCredentialSelectionRequired(
        request: PresentationRequest,
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
