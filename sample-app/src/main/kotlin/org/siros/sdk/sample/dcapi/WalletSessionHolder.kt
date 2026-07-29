// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample.dcapi

import org.siros.sdk.wallet.SirosWallet

/**
 * Process-wide holder for the currently-unlocked [SirosWallet] instance, so
 * [DCAPIGetCredentialActivity] (launched independently by the OS/Credential
 * Manager when the user picks one of our registered credentials from a
 * browser page - it is not necessarily started via [org.siros.sdk.sample.MainActivity])
 * can reuse the SAME unlocked session rather than needing its own login flow.
 *
 * Known limitation: if the process was killed and no [org.siros.sdk.sample.MainActivity]-driven
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
