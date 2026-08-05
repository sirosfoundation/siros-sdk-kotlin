package org.siros.sdk.flow

/**
 * Canonical [FlowEvent.Progress.step] token vocabulary and ordering, per
 * flow type - mirrors go-wallet-backend's FlowStep tokens (see
 * `internal/engine/messages.go`), shared by both the legacy engine
 * protocol and the newer WMP/JSON-RPC protocol.
 *
 * A consumer building its own progress UI needs this to turn a raw step
 * token into a position/fraction without independently reverse-engineering
 * the backend's token vocabulary and order (as this SDK's own sample app
 * previously did in its private copy). Only the ordering is canonical here
 * - localized display text is app-specific and stays out of this SDK.
 *
 * The ordinal position lists declare each step's canonical position, not
 * its guaranteed real-world order - a step can be skipped (e.g. no tx_code
 * required) or, rarely, arrive out of order relative to this list. Callers
 * should combine the fraction from [flowStepProgress] with a monotonic max
 * guard so a progress bar never visibly jumps backward.
 */
object FlowStepCatalog {
    val issuanceSteps: List<String> = listOf(
        "parsing_offer",
        "offer_parsed",
        "fetching_metadata",
        "metadata_fetched",
        "evaluating_trust",
        "trust_evaluated",
        "awaiting_selection",
        "authorization_required",
        "exchanging_token",
        "token_obtained",
        "requesting_credential",
        "deferred",
    )

    val presentationSteps: List<String> = listOf(
        "parsing_request",
        "request_parsed",
        "evaluating_verifier_trust",
        "match_credentials",
        "awaiting_consent",
        "credential_selection",
        "submitting_response",
    )

    /**
     * ISO 18013-5 BLE proximity presentation - a local-only flow (no
     * wallet-backend/engine involved), but conceptually the same operation
     * as [presentationSteps] once a reader has connected, so those steps
     * are reused verbatim below rather than duplicated.
     */
    val proximitySteps: List<String> = listOf(
        "waiting_for_reader",
        "reader_connected",
        "parsing_request",
        "match_credentials",
        "awaiting_consent",
        "submitting_response",
    )

    /**
     * Progress fraction (0f..1f) for [step] within [flowType]
     * ("issuance"/"presentation"/"proximity"), or null if the flow type or
     * step isn't recognized (caller should fall back to an indeterminate
     * indicator in that case).
     */
    fun flowStepProgress(flowType: String, step: String): Float? {
        val steps = when (flowType) {
            "issuance" -> issuanceSteps
            "presentation" -> presentationSteps
            "proximity" -> proximitySteps
            else -> return null
        }
        val index = steps.indexOf(step)
        if (index < 0) return null
        // +1 so the first step already shows some progress rather than an empty bar.
        return (index + 1).toFloat() / steps.size.toFloat()
    }
}
