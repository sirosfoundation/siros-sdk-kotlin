// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

/**
 * What [SirosWallet.deleteAccount] did. Every outcome the backend defines is a
 * value here; only a network failure or an unexpected response throws.
 *
 * The three [AccountGone] outcomes are the only ones after which local state
 * was wiped. Every other result leaves the wallet exactly as it was.
 */
sealed interface DeleteAccountResult {

    /** The account is gone server-side and this device has been wiped. */
    sealed interface AccountGone : DeleteAccountResult {
        /** Which local stores could not be cleared, if any. */
        val localWipe: LocalWipeReport
    }

    /** `200`: erased and confirmed. */
    data class Deleted(override val localWipe: LocalWipeReport) : AccountGone

    /** `202`: the account is gone and the backend finishes the last cleanup itself. Do not repeat. */
    data class CleanupPending(override val localWipe: LocalWipeReport) : AccountGone

    /** `202`: tokens are revoked; an operator completes the erasure. */
    data class OperatorRequired(override val localWipe: LocalWipeReport) : AccountGone

    /** `409`: the account was kept. Call [SirosWallet.deleteAccount] again, which asks for a new assertion. */
    data class RetryNeeded(val reason: String?) : DeleteAccountResult

    /** The confirmation was not [org.siros.sdk.auth.DELETE_ACCOUNT_CONFIRMATION]. Nothing was sent if this was caught locally. */
    data class ConfirmationRequired(val message: String?) : DeleteAccountResult

    /** The passkey assertion could not be obtained (declined, cancelled, no authenticator). */
    data class StepUpUnavailable(val message: String?) : DeleteAccountResult

    /** The backend asked for an assertion that was not sent. */
    data class StepUpRequired(val message: String?) : DeleteAccountResult

    /** The backend rejected the assertion. Try again with a passkey of this account. */
    data class StepUpFailed(val message: String?) : DeleteAccountResult

    /** The assertion took longer than two minutes or was already used. Try again. */
    data class StepUpExpired(val message: String?) : DeleteAccountResult

    /** The account has no passkey, so it cannot be deleted from the wallet. */
    data class NoPasskey(val message: String?) : DeleteAccountResult

    /** The session token lacks the scope to start a deletion. */
    data class InsufficientScope(val message: String?) : DeleteAccountResult

    /** The session token is revoked or expired; log in again before deleting. */
    data class SessionRevoked(val message: String?) : DeleteAccountResult

    /** The backend has no such account. */
    data class NotFound(val message: String?) : DeleteAccountResult
}

/** One local store that [SirosWallet.deleteAccount] could not clear. */
data class LocalWipeFailure(val store: String, val cause: Throwable)

/** The result of wiping this device after a deletion; the wipe never stops at the first failure. */
data class LocalWipeReport(val failures: List<LocalWipeFailure>) {
    /** True when every store was cleared. */
    val complete: Boolean get() = failures.isEmpty()
}

/** One named clear in the local wipe. */
internal class LocalWipeStep(val store: String, val clear: suspend () -> Unit)

/**
 * Runs every [steps] clear, in order, and reports the ones that threw. A
 * failing clear must not leave the stores after it holding the deleted
 * account's data.
 */
internal suspend fun runLocalWipe(steps: List<LocalWipeStep>): LocalWipeReport {
    val failures = mutableListOf<LocalWipeFailure>()
    for (step in steps) {
        try {
            step.clear()
        } catch (e: Exception) {
            timber.log.Timber.e(e, "Local wipe: clearing ${step.store} failed")
            failures += LocalWipeFailure(step.store, e)
        }
    }
    return LocalWipeReport(failures)
}
