package org.siros.sdk.wallet

/**
 * The minimum state needed to restore a joined WMP group after an app
 * restart: the invited backend, the session's latest resumption token
 * (rotated on every resume), and the dynamically registered AS client when
 * the join used one. HTTPS sessions are bound to the authenticated principal,
 * so a restart must mint the replacement bearer for the SAME client rather
 * than registering a fresh principal. The invitation nonce itself is
 * single-use and is NOT stored — resuming uses the session's resumption token
 * instead.
 *
 * Group metadata is carried so the Groups view can restore its identity.
 */
data class WmpJoinRecord(
    /** The invited backend's provider URL. */
    val providerUrl: String,
    /** The backend's POST /wmp endpoint. */
    val sendUrl: String,
    /** The backend's GET /wmp/events endpoint. */
    val sseUrl: String,
    /** The live session's id on the invited backend. */
    val sessionId: String,
    /** The session's latest resumption token (rotated on every resume). */
    val resumptionToken: String,
    /** The invitation's group session, when it differs from sessionId. */
    val groupId: String? = null,
    /** The group's display name, when one was named. */
    val groupName: String? = null,
    /** The invited AS's dynamically registered client id, when the join used DCR. */
    val asClientId: String? = null,
    /** The registered client secret; the app protects it like the resumption token. */
    val asClientSecret: String? = null,
)
