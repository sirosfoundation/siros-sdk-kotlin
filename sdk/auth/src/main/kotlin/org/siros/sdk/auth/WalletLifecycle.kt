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
 * How far a SID-AUTH-06 refusal reaches: this one installation's wallet
 * instance, or the whole wallet the login was for.
 *
 * Sent as `scope` alongside the error code on a `403`. The distinction cannot
 * live in the code, because `WALLET_REVOKED` has meant both since the first
 * release, and it is the only thing that decides whether anything local may
 * be forgotten.
 *
 * [WALLET] is about the tenant the refused login was for: it says this wallet
 * cannot be opened here and a new enrollment is required, not that nothing of
 * the user's is left anywhere.
 */
enum class WalletLifecycleScope(val wire: String) {
    /** One wallet instance. The wallet still exists; other devices answer for themselves. */
    INSTANCE("instance"),

    /** The whole wallet: no instance is left to reactivate, and its data has been erased. */
    WALLET("wallet"),
    ;

    companion object {
        /** The scope [wire] names, or null when absent or unrecognised. */
        fun fromWire(wire: String?): WalletLifecycleScope? =
            entries.firstOrNull { it.wire.equals(wire, ignoreCase = true) }
    }
}

/**
 * Why the authorization server refused a login for this installation: the
 * wallet instance linked to the passkey is suspended, that instance was
 * revoked, or the whole wallet was deactivated and its data erased.
 *
 * Carried as the AS error code (`WALLET_SUSPENDED` / `WALLET_REVOKED`) on a
 * `403` from a login or token request, together with a `scope`; see
 * [org.siros.sdk.credentials.AuthException.errorCode] and
 * [org.siros.sdk.credentials.AuthException.serverScope].
 *
 * [REVOKED] and [DEACTIVATED] share the `WALLET_REVOKED` code and are told
 * apart only by the scope, which is what makes [DEACTIVATED] the one refusal
 * that licenses forgetting local state. Under the EUDI specifications
 * revoking one wallet unit ends that unit and nothing else, so anything less
 * than [DEACTIVATED] must leave the user's other devices, passkeys and keys
 * alone.
 */
enum class WalletLifecycleRefusal(val errorCode: String) {
    /** Reversible: another device or the provider can reactivate this instance. */
    SUSPENDED("WALLET_SUSPENDED"),

    /**
     * Terminal for *this installation's* wallet instance. The wallet itself
     * still exists and the user's other devices keep their own status, so
     * nothing local may be forgotten. A fresh enrollment is the way forward
     * on this device.
     */
    REVOKED("WALLET_REVOKED"),

    /**
     * Terminal for the whole wallet: every instance has been revoked and the
     * server-side data erased, so no instance is left to reactivate and a new
     * enrollment is required. The only refusal that licenses forgetting the
     * cached account.
     */
    DEACTIVATED("WALLET_REVOKED"),
    ;

    companion object {
        /**
         * The refusal [errorCode] names, or null when it is not a lifecycle
         * refusal (a plain expired session, a wrong passkey, …).
         *
         * Resolves `WALLET_REVOKED` to [REVOKED], never [DEACTIVATED]: without
         * a scope the two are indistinguishable, and treating a per-instance
         * revocation as a deactivation would destroy passkeys that still work.
         * Prefer [fromRefusal], which reads the scope.
         */
        fun fromErrorCode(errorCode: String?): WalletLifecycleRefusal? =
            entries.firstOrNull { it.errorCode.equals(errorCode, ignoreCase = true) }

        /**
         * The refusal [errorCode] and [scope] name together, or null when it
         * is not a lifecycle refusal.
         *
         * A missing or unrecognised [scope] falls back to [fromErrorCode], so
         * a backend that does not send one yet keeps the conservative
         * per-instance reading.
         */
        fun fromRefusal(errorCode: String?, scope: String?): WalletLifecycleRefusal? {
            val byCode = fromErrorCode(errorCode) ?: return null
            if (byCode != REVOKED) return byCode
            return if (WalletLifecycleScope.fromWire(scope) == WalletLifecycleScope.WALLET) DEACTIVATED else byCode
        }
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
fun BackendApiException.apiErrorCode(): String? = stringField("error")

/**
 * The `scope` of a SID-AUTH-06 lifecycle refusal carried by this exception's
 * JSON body, or null when absent.
 *
 * The wallet API answers a refusal with the same `{error, scope, message}`
 * body as the authorization server does, so a refusal met on a wallet-API
 * call has to be read here rather than only on [AuthException].
 */
fun BackendApiException.apiRefusalScope(): String? = stringField("scope")

/**
 * The server's user-facing explanation from this exception's JSON body, or
 * null when absent. For display only: nothing a client decides may depend on
 * reading it.
 */
fun BackendApiException.apiRefusalMessage(): String? = stringField("message")

private fun BackendApiException.stringField(name: String): String? = runCatching {
    (errorJson.parseToJsonElement(body ?: return null).jsonObject[name] as? JsonPrimitive)?.content
}.getOrNull()?.takeIf { it.isNotBlank() }
