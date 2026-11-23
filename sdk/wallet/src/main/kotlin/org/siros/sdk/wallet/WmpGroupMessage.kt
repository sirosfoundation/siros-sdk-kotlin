package org.siros.sdk.wallet

/**
 * One group message (issue #77): a `wmp.message.deliver` the wallet's
 * session received — pulled from its backend's mailbox
 * ([SirosWallet.pollGroupMessages]) or arrived live (the SSE ping → the
 * poll, [SirosWallet.groupMessageEvents]).
 *
 * The `backend`/`sessionId` pair names the wallet session that received
 * it (the engine or an invited backend's session — see
 * [WmpEndpointInfo]); `from` is the sender's session id when the envelope
 * carries one (`params.wmp.session_id` — absent when the sender omitted
 * it). The message body rides `params.body.text` (the `text/plain` form;
 * other content types are not parsed by the sample surface).
 */
data class WmpGroupMessage(
    /** [WmpEndpointInfo.ORIGIN_ENGINE] or the invited backend's provider URL. */
    val backend: String,
    /** The wallet's session on that backend (the box the message landed in). */
    val sessionId: String,
    /** The sender's session id, when the envelope carries one. */
    val from: String?,
    /** The message text (`params.body.text`). */
    val text: String,
    /** The engine's message id (`wmp_message_id`), when carried. */
    val messageId: String?,
    /**
     * The direction, for the trace: `false` (the default) = inbound (the
     * session received it); `true` = outbound (the wallet SENT it —
     * [SirosWallet.sendMessage] appends its own sends so a group's trace
     * shows both sides of the conversation, machine traffic and all).
     */
    val outbound: Boolean = false,
)