// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.auth

import org.siros.sdk.credentials.BackendApiException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

/**
 * The three states of a wallet instance's lifecycle (SID-AUTH-06,
 * go-wallet-backend#319). `active` → `suspended` is reversible and only
 * blocks that installation; `revoked` is terminal, and revoking the last
 * non-revoked instance deactivates the wallet and erases its data
 * server-side.
 *
 * The [wire] value is what the backend sends and expects; this enum exists so
 * callers cannot pass a status the backend will reject.
 */
enum class WalletInstanceStatus(val wire: String) {
    ACTIVE(WalletInstance.STATUS_ACTIVE),
    SUSPENDED(WalletInstance.STATUS_SUSPENDED),
    REVOKED(WalletInstance.STATUS_REVOKED),
    ;

    companion object {
        /** The status for [wire], or null for a value this SDK does not know. */
        fun fromWire(wire: String?): WalletInstanceStatus? =
            entries.firstOrNull { it.wire.equals(wire, ignoreCase = true) }
    }
}

/**
 * Why the authorization server refused a login for this installation: the
 * wallet instance linked to the passkey is suspended, or the wallet has been
 * deactivated and its data erased.
 *
 * Carried as the AS error code (`WALLET_SUSPENDED` / `WALLET_REVOKED`) on a
 * `403` from a login or token request; see
 * [org.siros.sdk.credentials.AuthException.errorCode].
 */
enum class WalletLifecycleRefusal(val errorCode: String) {
    /** Reversible: another device or the provider can reactivate this instance. */
    SUSPENDED("WALLET_SUSPENDED"),

    /** Terminal: the wallet was deactivated, its data erased; re-enrollment is required. */
    REVOKED("WALLET_REVOKED"),
    ;

    companion object {
        /**
         * The refusal [errorCode] names, or null when it is not a lifecycle
         * refusal (a plain expired session, a wrong passkey, …).
         */
        fun fromErrorCode(errorCode: String?): WalletLifecycleRefusal? =
            entries.firstOrNull { it.errorCode.equals(errorCode, ignoreCase = true) }
    }
}

/**
 * Result of deactivating the wallet (`POST
 * /user/session/instances/revoke-all`) or revoking its last instance.
 *
 * The backend records the revocation before it erases the data, so a call can
 * legitimately end with the instances revoked and the erasure unfinished
 * ([complete] false, after `409 ERASURE_INCOMPLETE` survived the client's
 * retry budget). The wallet is deactivated either way - an administrator
 * finishes the cascade by re-sending the same status through the admin API -
 * so a caller should forget its local account in both cases and use
 * [complete] only to decide what to tell the user.
 */
data class DeactivationOutcome(
    /** How many instances this call revoked. A repeated (retry) call answers 0. */
    val revoked: Int,
    /** True when the backend confirmed the erasure with a `200`. */
    val complete: Boolean,
)

/** Backend error code for a `409` whose status change stands but whose erasure must be retried. */
const val ERROR_ERASURE_INCOMPLETE: String = "ERASURE_INCOMPLETE"

/** Backend error code for a `credential_id` that is not one of the caller's own passkeys. */
const val ERROR_CREDENTIAL_NOT_OWNED: String = "CREDENTIAL_NOT_OWNED"

private val errorJson = Json { ignoreUnknownKeys = true }

/**
 * The backend's stable `error` code from this exception's JSON body (e.g.
 * `ERASURE_INCOMPLETE`, `CREDENTIAL_NOT_OWNED`), or null when the body is
 * absent, not JSON, or carries no `error` field. Lets callers branch on the
 * protocol's error codes without each re-parsing the body.
 */
fun BackendApiException.apiErrorCode(): String? = runCatching {
    (errorJson.parseToJsonElement(body ?: return null).jsonObject["error"] as? JsonPrimitive)?.content
}.getOrNull()?.takeIf { it.isNotBlank() }
