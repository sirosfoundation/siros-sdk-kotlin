package org.siros.sdk.sample

import org.siros.sdk.flow.FlowStepCatalog

/**
 * Localized display support for [FlowStepCatalog]'s raw FlowStep tokens.
 * Ordering/progress-fraction logic lives in the SDK now
 * ([FlowStepCatalog.flowStepProgress]) - this file only owns the
 * app-specific localized label mapping.
 */

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

/** See [FlowStepCatalog.flowStepProgress]. */
fun flowStepProgress(flowType: String, step: String): Float? =
    FlowStepCatalog.flowStepProgress(flowType, step)
