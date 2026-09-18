// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.auth

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * How a SID-AUTH-06 refusal resolves from the wire.
 *
 * `WALLET_REVOKED` answers both a revoked wallet instance and a deactivated
 * wallet, and only `scope` tells them apart. Since the deactivated reading is
 * the one that licenses throwing local state away, every path that is not
 * unambiguously "wallet" has to come out per-instance.
 */
class WalletLifecycleRefusalTest {

    @Test
    fun `a suspension is always per-instance`() {
        assertEquals(
            WalletLifecycleRefusal.SUSPENDED,
            WalletLifecycleRefusal.fromRefusal("WALLET_SUSPENDED", "instance"),
        )
        // Even a (malformed) wallet-wide scope must not promote a suspension:
        // suspension is reversible and nothing may be erased for it.
        assertEquals(
            WalletLifecycleRefusal.SUSPENDED,
            WalletLifecycleRefusal.fromRefusal("WALLET_SUSPENDED", "wallet"),
        )
    }

    @Test
    fun `a revocation scoped to the instance stays per-instance`() {
        assertEquals(
            WalletLifecycleRefusal.REVOKED,
            WalletLifecycleRefusal.fromRefusal("WALLET_REVOKED", "instance"),
        )
    }

    @Test
    fun `a revocation scoped to the wallet is a deactivation`() {
        assertEquals(
            WalletLifecycleRefusal.DEACTIVATED,
            WalletLifecycleRefusal.fromRefusal("WALLET_REVOKED", "wallet"),
        )
        // The wire value is case-insensitive, like every other code here.
        assertEquals(
            WalletLifecycleRefusal.DEACTIVATED,
            WalletLifecycleRefusal.fromRefusal("wallet_revoked", "WALLET"),
        )
    }

    /**
     * The two ways a scope can fail to arrive - an older backend that sends
     * none, and a newer one that sends a value this SDK does not know - must
     * both land on the conservative reading. Getting this wrong forgets an
     * account whose passkeys still work.
     */
    @Test
    fun `an absent or unknown scope reads as per-instance`() {
        assertEquals(
            WalletLifecycleRefusal.REVOKED,
            WalletLifecycleRefusal.fromRefusal("WALLET_REVOKED", null),
        )
        assertEquals(
            WalletLifecycleRefusal.REVOKED,
            WalletLifecycleRefusal.fromRefusal("WALLET_REVOKED", ""),
        )
        assertEquals(
            WalletLifecycleRefusal.REVOKED,
            WalletLifecycleRefusal.fromRefusal("WALLET_REVOKED", "solar-system"),
        )
    }

    @Test
    fun `a non-lifecycle code is not a refusal whatever the scope`() {
        assertNull(WalletLifecycleRefusal.fromRefusal("invalid_grant", "wallet"))
        assertNull(WalletLifecycleRefusal.fromRefusal(null, "wallet"))
    }

    /**
     * [WalletLifecycleRefusal.fromErrorCode] has no scope to read, so it must
     * never answer DEACTIVATED - both revoked values carry the same code, and
     * resolving to the wider one would erase on a per-instance revocation.
     */
    @Test
    fun `fromErrorCode alone never resolves to a deactivation`() {
        assertEquals(
            WalletLifecycleRefusal.REVOKED,
            WalletLifecycleRefusal.fromErrorCode("WALLET_REVOKED"),
        )
    }

    @Test
    fun `scopes parse from their wire values`() {
        assertEquals(WalletLifecycleScope.INSTANCE, WalletLifecycleScope.fromWire("instance"))
        assertEquals(WalletLifecycleScope.WALLET, WalletLifecycleScope.fromWire("wallet"))
        assertNull(WalletLifecycleScope.fromWire(null))
        assertNull(WalletLifecycleScope.fromWire("galaxy"))
    }
}
