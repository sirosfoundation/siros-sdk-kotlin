// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

/**
 * What [SirosWallet.addPasskey] did. Every outcome the backend defines is a
 * value here; only a network failure or an unexpected response throws.
 *
 * Only [Added] changes anything: every other result leaves the account and
 * this wallet's keystore exactly as they were. A refused attempt has consumed
 * its challenge, so calling [SirosWallet.addPasskey] again starts afresh.
 */
sealed interface AddPasskeyResult {

    /** The passkey is on the account and its PRF entry is in the synced private data. */
    data class Added(val credentialId: String?) : AddPasskeyResult

    /** The backend wanted an assertion from an existing passkey and none was sent. */
    data class AuthorizationRequired(val message: String?) : AddPasskeyResult

    /** The backend rejected the authorising assertion. Try again with a passkey of this account. */
    data class AuthorizationFailed(val message: String?) : AddPasskeyResult

    /** The authorising assertion could not be obtained (declined, cancelled, no authenticator). */
    data class AuthorizerUnavailable(val message: String?) : AddPasskeyResult

    /** The new passkey could not be created (declined, cancelled, no authenticator). */
    data class PasskeyCreationUnavailable(val message: String?) : AddPasskeyResult

    /**
     * The new passkey's authenticator returned no PRF output, so it cannot unlock the wallet's
     * keystore and was not added. The passkey it created on the device is unused and may be removed.
     */
    data class PrfUnsupported(val message: String?) : AddPasskeyResult

    /** The challenge expired or was already used. Call [SirosWallet.addPasskey] again. */
    data class RetryNeeded(val reason: String?) : AddPasskeyResult

    /** The private data changed on the backend (another device) since this one read it. Sync, then try again. */
    data class PrivateDataConflict(val message: String?) : AddPasskeyResult

    /** The backend refused the new passkey (it did not verify, or its authenticator is not allowed). */
    data class RegistrationRejected(val message: String?) : AddPasskeyResult

    /** The wallet is locked: a passkey can only be added while the keystore is unlocked. */
    data class WalletLocked(val message: String?) : AddPasskeyResult

    /** The session token lacks the scope to enrol a passkey. */
    data class InsufficientScope(val message: String?) : AddPasskeyResult

    /** The session token is revoked or expired; log in again. */
    data class SessionRevoked(val message: String?) : AddPasskeyResult
}
