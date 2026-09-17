// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.siros.sdk.auth.WalletLifecycleRefusal
import org.siros.sdk.credentials.StoredCredential

/**
 * Observable wallet state. Apps collect [SirosWallet.state] to drive their UI.
 */
sealed class WalletState {

    /** Not authenticated. The user must call [SirosWallet.login] or [SirosWallet.register]. */
    data class Disconnected(
        /** Cached accounts that can be logged into (have PRF keys). */
        val cachedAccounts: List<CachedAccount> = emptyList(),
    ) : WalletState()

    /** Authentication / keystore unlock in progress. Show a loading indicator. */
    data object Connecting : WalletState()

    /** Authenticated, keystore unlocked, engine connected. */
    data class Ready(
        val userId: String,
        val displayName: String?,
        val credentials: List<StoredCredential> = emptyList(),
        /** All cached accounts (for the account switcher in settings). */
        val cachedAccounts: List<CachedAccount> = emptyList(),
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

    /**
     * The backend refuses this installation because of its wallet instance's
     * lifecycle (SID-AUTH-06): the instance is suspended, or the wallet has
     * been deactivated and its data erased. Terminal for this session - it is
     * not an error to retry or dismiss, but a condition that only someone
     * else (another device, the provider) can lift.
     *
     * Entered from [SirosWallet.login], [SirosWallet.unlockKeystore],
     * [SirosWallet.resumeSession] and from the SDK's own re-login after a
     * token cut-off, whenever the authorization server answers `403` with
     * `WALLET_SUSPENDED` / `WALLET_REVOKED`.
     *
     * On [WalletLifecycleRefusal.REVOKED] the cached account for this tenant
     * has already been forgotten (its server-side data is gone and its
     * passkey can never log in again), so [cachedAccounts] no longer lists
     * it and the app should offer a fresh enrollment. On
     * [WalletLifecycleRefusal.SUSPENDED] nothing local is lost and a later
     * [SirosWallet.login] succeeds once the instance is reactivated.
     */
    data class LifecycleBlocked(
        val reason: WalletLifecycleRefusal,
        /** The backend's user-facing explanation, when it sent one. */
        val message: String?,
        /** Cached accounts that can still be logged into. */
        val cachedAccounts: List<CachedAccount> = emptyList(),
    ) : WalletState()

    /** An error occurred. The app should show the message and offer retry / logout. */
    data class Error(val message: String) : WalletState()
}
