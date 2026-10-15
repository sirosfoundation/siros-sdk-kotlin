// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.auth

/** The only confirmation text the backend accepts for account deletion. */
const val DELETE_ACCOUNT_CONFIRMATION: String = "DELETE"

/**
 * Produces the fresh passkey assertion that authorises account deletion. The
 * SDK does not own the UI, so an app that shows its own confirmation or
 * authenticator sheet implements this; by default the wallet answers it with
 * its own [AuthProvider].
 */
fun interface StepUpAuthenticator {
    /** Answers [options] with a user-verified assertion, or throws if the user declines. */
    suspend fun assert(options: AuthenticateOptions): AuthenticateResult
}

/**
 * What `POST /user/session/delete-begin` returned: the challenge to answer and
 * the WebAuthn assertion [options] (the caller's own credentials, user
 * verification required) to answer it with. The challenge is single use and
 * expires after two minutes, so sign it promptly.
 */
class DeleteAccountChallenge(
    val challengeId: String,
    val options: AuthenticateOptions,
)

/** The backend's answer to `POST /user/session/delete-begin`. */
sealed interface DeleteAccountBegin {
    /** `200`: the challenge to answer. */
    data class Ready(val challenge: DeleteAccountChallenge) : DeleteAccountBegin

    /** `400 NO_PASSKEY`: the account has no passkey, so no step-up can be made. */
    data class NoPasskey(val message: String?) : DeleteAccountBegin

    /** `403`: the token lacks the `w` scope. */
    data class Forbidden(val message: String?) : DeleteAccountBegin

    /** `401`: the bearer token is revoked or expired. */
    data class SessionRevoked(val message: String?) : DeleteAccountBegin

    /** `404`: the backend has no such account. */
    data class NotFound(val message: String?) : DeleteAccountBegin
}

/**
 * The backend's answer to `DELETE /user/session`, for every outcome it defines.
 * [Deleted], [CleanupPending] and [OperatorRequired] mean the account is gone
 * from the caller's point of view; everything else leaves it in place.
 */
sealed interface DeleteAccountOutcome {
    /** `200 DELETED`: erased and confirmed. */
    data object Deleted : DeleteAccountOutcome

    /** `202 DELETION_CLEANUP_PENDING`: the account is gone and the backend finishes the sweep. Do not repeat. */
    data object CleanupPending : DeleteAccountOutcome

    /** `202 DELETION_OPERATOR_REQUIRED`: tokens are revoked; an operator completes the erasure. */
    data object OperatorRequired : DeleteAccountOutcome

    /** `409 DELETION_INCOMPLETE`: the account was kept. Repeat from [BackendApiClient.deleteAccountBegin] with a fresh assertion. */
    data class RetryNeeded(val message: String?) : DeleteAccountOutcome

    /** `401 STEP_UP_REQUIRED`: the request carried no assertion. */
    data class StepUpRequired(val message: String?) : DeleteAccountOutcome

    /** `401 STEP_UP_FAILED`: the assertion was rejected (wrong user, bad signature, replayed). */
    data class StepUpFailed(val message: String?) : DeleteAccountOutcome

    /** `410 STEP_UP_EXPIRED`: the challenge is older than two minutes or already used. */
    data class StepUpExpired(val message: String?) : DeleteAccountOutcome

    /** `400 CONFIRMATION_REQUIRED`: the confirmation was not [DELETE_ACCOUNT_CONFIRMATION]. */
    data class ConfirmationRequired(val message: String?) : DeleteAccountOutcome

    /** `401` without a step-up code: the bearer token is revoked or expired. */
    data class SessionRevoked(val message: String?) : DeleteAccountOutcome

    /** `404`: the backend has no such account. */
    data class NotFound(val message: String?) : DeleteAccountOutcome
}

internal const val ERROR_NO_PASSKEY = "NO_PASSKEY"
internal const val ERROR_STEP_UP_REQUIRED = "STEP_UP_REQUIRED"
internal const val ERROR_STEP_UP_FAILED = "STEP_UP_FAILED"
internal const val ERROR_CONFIRMATION_REQUIRED = "CONFIRMATION_REQUIRED"
internal const val CODE_DELETION_CLEANUP_PENDING = "DELETION_CLEANUP_PENDING"
internal const val CODE_DELETION_OPERATOR_REQUIRED = "DELETION_OPERATOR_REQUIRED"
