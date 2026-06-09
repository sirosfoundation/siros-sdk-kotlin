// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.sirosfoundation.sdk.wallet

import org.sirosfoundation.sdk.credentials.StoredCredential

/**
 * Observable wallet state. Apps collect [SirosWallet.state] to drive their UI.
 */
sealed class WalletState {

    /** Not authenticated. The user must call [SirosWallet.login] or [SirosWallet.register]. */
    data object Disconnected : WalletState()

    /** Authentication / keystore unlock in progress. Show a loading indicator. */
    data object Connecting : WalletState()

    /** Authenticated, keystore unlocked, engine connected. */
    data class Ready(
        val userId: String,
        val displayName: String?,
        val credentials: List<StoredCredential> = emptyList(),
    ) : WalletState()

    /**
     * Session resumed but the keystore is still locked (requires PRF).
     *
     * The engine is connected and the session token is valid, but
     * credentials and signing are unavailable until [SirosWallet.unlockKeystore]
     * is called (which triggers a WebAuthn assertion to obtain the PRF output).
     */
    data class KeystoreLocked(
        val userId: String,
        val displayName: String?,
    ) : WalletState()

    /** An issuance or presentation flow is in progress. */
    data class FlowActive(
        val userId: String,
        val displayName: String?,
        val flowId: String,
        val flowType: String,
        val status: String,
        val credentials: List<StoredCredential> = emptyList(),
    ) : WalletState()

    /** An error occurred. The app should show the message and offer retry / logout. */
    data class Error(val message: String) : WalletState()
}
