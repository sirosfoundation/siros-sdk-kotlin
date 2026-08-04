package org.siros.sdk.sample

/**
 * Localized display support for go-wallet-backend's FlowStep token vocabulary
 * (see internal/engine/messages.go) - shared by both the legacy engine
 * protocol and the newer WMP/JSON-RPC protocol.
 *
 * Ordinal position lists below drive the flow progress bar's fraction. They
 * declare each step's canonical position, not its guaranteed real-world
 * order - a step can be skipped (e.g. no tx_code required) or, rarely,
 * arrive out of order relative to this list. Callers should combine the
 * fraction from [flowStepProgress] with a monotonic max guard so the bar
 * never visibly jumps backward.
 */

private val ISSUANCE_STEPS = listOf(
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

private val PRESENTATION_STEPS = listOf(
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
 * wallet-backend/engine involved, see `SirosWallet.signMdocPresentationForProximity`),
 * but conceptually the same operation as [PRESENTATION_STEPS] once a reader
 * has connected, so those steps are reused verbatim below rather than
 * duplicated.
 */
private val PROXIMITY_STEPS = listOf(
    "waiting_for_reader",
    "reader_connected",
    "parsing_request",
    "match_credentials",
    "awaiting_consent",
    "submitting_response",
)

private val STEP_LABEL_RES: Map<String, Int> = mapOf(
    "parsing_offer" to R.string.flow_step_parsing_offer,
    "offer_parsed" to R.string.flow_step_offer_parsed,
    "fetching_metadata" to R.string.flow_step_fetching_metadata,
    "metadata_fetched" to R.string.flow_step_metadata_fetched,
    "evaluating_trust" to R.string.flow_step_evaluating_trust,
    "trust_evaluated" to R.string.flow_step_trust_evaluated,
    "awaiting_selection" to R.string.flow_step_awaiting_selection,
    "authorization_required" to R.string.flow_step_authorization_required,
    "exchanging_token" to R.string.flow_step_exchanging_token,
    "token_obtained" to R.string.flow_step_token_obtained,
    "requesting_credential" to R.string.flow_step_requesting_credential,
    "deferred" to R.string.flow_step_deferred,
    "parsing_request" to R.string.flow_step_parsing_request,
    "request_parsed" to R.string.flow_step_request_parsed,
    "evaluating_verifier_trust" to R.string.flow_step_evaluating_verifier_trust,
    "match_credentials" to R.string.flow_step_match_credentials,
    "awaiting_consent" to R.string.flow_step_awaiting_consent,
    "credential_selection" to R.string.flow_step_credential_selection,
    "submitting_response" to R.string.flow_step_submitting_response,
    "waiting_for_reader" to R.string.flow_step_waiting_for_reader,
    "reader_connected" to R.string.flow_step_reader_connected,
)

/** Localized label resource for a raw FlowStep token, falling back to a generic "Processing…" for unrecognized tokens. */
fun flowStepLabelRes(step: String): Int = STEP_LABEL_RES[step] ?: R.string.flow_step_unknown

/**
 * Progress fraction (0f..1f) for a step within a flow type, or null if the
 * flow type or step isn't recognized (caller should fall back to an
 * indeterminate indicator in that case).
 */
fun flowStepProgress(flowType: String, step: String): Float? {
    val steps = when (flowType) {
        "issuance" -> ISSUANCE_STEPS
        "presentation" -> PRESENTATION_STEPS
        "proximity" -> PROXIMITY_STEPS
        else -> return null
    }
    val index = steps.indexOf(step)
    if (index < 0) return null
    // +1 so the first step already shows some progress rather than an empty bar.
    return (index + 1).toFloat() / steps.size.toFloat()
}
