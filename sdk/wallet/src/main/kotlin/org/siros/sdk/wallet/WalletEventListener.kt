// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.siros.sdk.credentials.CredentialMatcher
import org.siros.sdk.credentials.StoredCredential

/**
 * Context provided when a verifier requests credential presentation.
 *
 * Contains the matched credentials, requested claims, and optional
 * verifier identity so the app can render an informed consent screen.
 */
data class PresentationRequest(
    /** Verifier display name (from trust evaluation), null if unknown. */
    val verifierName: String?,
    /** Trust evaluation result with full metadata. Null if trust was not evaluated. */
    val trustResult: TrustResult? = null,
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
    ): List<Long>

    /**
     * A new credential has been received from an issuer.
     * The SDK has already stored it — this callback is for
     * showing a confirmation / toast.
     */
    fun onCredentialReceived(credential: StoredCredential) {}

    /**
     * Called when a flow completes (issuance or presentation).
     *
     * @param redirectUri For an OID4VP `direct_post.jwt` presentation, some
     *   verifiers (e.g. verifier.multipaz.org) return a `redirect_uri` in
     *   their response so the user's browser/session can be returned to the
     *   verifier's own page to see the result. When present, the app should
     *   open it (Custom Tab or browser), matching [onAuthorizationRequired]'s
     *   pattern. Null when the verifier didn't return one (also true for
     *   every OID4VCI issuance completion).
     */
    fun onFlowComplete(flowId: String, redirectUri: String? = null) {}

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

    /**
     * An issuer requires a transaction code (PIN) for pre-authorized issuance.
     *
     * Return the PIN/tx_code value, or null to cancel the flow.
     *
     * @param flowId The flow that requires a tx_code.
     * @param description Human-readable description from the issuer (may contain the code for testing).
     */
    fun onTxCodeRequired(
        flowId: String,
        description: String?,
    ): String? = null

    /**
     * The current session could not be silently refreshed and is no longer
     * valid - e.g. the engine WebSocket's token refresh failed before a
     * reconnect, or repeated REST calls were rejected as unauthenticated.
     * [SirosWallet] fires this *before* logging out (logout is launched
     * asynchronously right after), so wallet state read during this callback
     * may still briefly reflect the old session. Unlike [onFlowError] (a
     * specific flow's failure, session otherwise fine), this means the whole
     * session is gone - route the user to the login screen rather than
     * surfacing a generic error message.
     */
    fun onReauthenticationRequired() {
        // Default: no-op. Host apps override to route to a login screen.
    }
}
