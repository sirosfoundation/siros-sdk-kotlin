package org.siros.sdk.wallet

/**
 * One connected WMP backend (issue #77's endpoint surface).
 *
 * The wallet speaks WMP to potentially several backends at once: its own
 * configured engine ([ORIGIN_ENGINE] — issuance/presentation ride it) and,
 * since the invitation flows, one backend per scanned invitation that named
 * one ([ORIGIN_INVITATION] — the nonce exists only on the backend that
 * minted it, so the join lands there; see [SirosWallet.consumeInvitation]).
 *
 * The sample apps render the list ([WmpEndpointInfo] is the model); the SDK
 * owns the tracking. `state` is the [org.siros.sdk.transport.wmp.WmpSessionState]
 * name, lower-cased, and `sessionId` the live session on that backend when
 * one exists (the invitation join's group id).
 */
data class WmpEndpointInfo(
    /** [ORIGIN_ENGINE] (the configured engine) or [ORIGIN_INVITATION] (an invite's backend). */
    val origin: String,
    /** The invitation's provider URL (the join's target); `null` for the engine. */
    val providerUrl: String?,
    /** The backend's POST /wmp URL ("local" for the in-process engine). */
    val sendUrl: String,
    /** The backend's GET /wmp/events URL; `null` for the WS transports. */
    val sseUrl: String?,
    /** The [org.siros.sdk.transport.wmp.WmpSessionState] name, lower-cased. */
    val state: String,
    /** The live session's id on this backend, when one exists. */
    val sessionId: String?,
) {
    companion object {
        /** The wallet's own configured engine. */
        const val ORIGIN_ENGINE = "engine"
        /** A backend a scanned invitation named (the join lands there). */
        const val ORIGIN_INVITATION = "invitation"
    }
}