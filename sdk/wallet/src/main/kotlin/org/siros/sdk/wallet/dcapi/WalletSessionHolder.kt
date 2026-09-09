// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.dcapi

import org.siros.sdk.wallet.SirosWallet

/**
 * Process-wide holder for the currently-unlocked [SirosWallet] instance, so
 * [DCAPIGetCredentialActivity] (launched independently by the OS/Credential
 * Manager when the user picks one of the app's registered credentials from a
 * browser page - it is not necessarily started via the host app's own UI)
 * can reuse the SAME unlocked session rather than needing its own login flow.
 *
 * The host app is expected to call [update] with its wallet whenever the
 * wallet reaches a state with presentable credentials, and with null when
 * it logs out or the keystore locks - the same moments it calls
 * [SirosCredentialRegistry.refresh] and [SirosCredentialRegistry.clear].
 *
 * Known limitation: if the process was killed and no host-app-driven
 * unlock has happened yet in this process's lifetime, [wallet] is null and
 * the DC API request is declined with a clear error rather than attempting
 * a from-scratch unlock UI inside the provider activity - that's a
 * meaningfully larger follow-up (cold-start unlock from a provider
 * activity), not attempted here.
 */
object WalletSessionHolder {
    @Volatile
    var wallet: SirosWallet? = null
        private set

    fun update(wallet: SirosWallet?) {
        this.wallet = wallet
    }
}
