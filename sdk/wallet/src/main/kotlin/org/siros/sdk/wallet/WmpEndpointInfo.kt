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
    /**
     * The GROUP the wallet joined on this backend (issue #77's group-centric
     * view): the invitation's `session_id` — the inviter's session, the group
     * every member shares. `null` until a join lands (the engine backend has
     * no joined group on the invitation path) — the group-centric UI keys
     * its cards by it and falls back to the session id.
     */
    val groupId: String? = null,
    /**
     * The group's display name, when the backend named one (wmp-mcp names
     * every group — two random words — and the invitation may carry it).
     * `null` renders the group id.
     */
    val groupName: String? = null,
    /**
     * The capabilities the live session negotiated on this backend, when one
     * exists: the create answer's `capabilities`, by name (flows / mcp / …).
     * The group-centric view renders them as chips — what the group may ask
     * of this wallet.
     */
    val caps: List<String> = emptyList(),
) {
    companion object {
        /** The wallet's own configured engine. */
        const val ORIGIN_ENGINE = "engine"
        /** A backend a scanned invitation named (the join lands there). */
        const val ORIGIN_INVITATION = "invitation"
    }
}