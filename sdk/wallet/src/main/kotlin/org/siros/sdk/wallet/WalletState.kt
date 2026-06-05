// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.siros.sdk.credentials.StoredCredential

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
