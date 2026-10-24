// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.siros.sdk.keystore.KeystoreManager
import org.siros.sdk.keystore.Signer
import org.siros.sdk.keystore.WscdAssuranceOverride
import org.siros.sdk.keystore.WscdKeystoreAdapter

class WscdAssuranceOverridesTest {
    @Test
    fun theDefaultIsNoOverrideAtAll() {
        assertTrue(WalletConfig(backendUrl = "https://b.example").testOnlyWscdAssuranceOverrides.isEmpty())
        val adapter = WscdKeystoreAdapter(mockk<Signer>(relaxed = true))
        assertNull(adapter.testOnlyAssuranceOverride)
        assertTrue(applyWscdAssuranceOverrides(emptyMap(), mapOf("softkey" to adapter)).isEmpty())
        assertNull(adapter.testOnlyAssuranceOverride)
    }

    @Test
    fun theOverrideIsAppliedOnlyToTheAdapterRegisteredUnderThatPluginId() {
        val soft = WscdKeystoreAdapter(mockk<Signer>(relaxed = true))
        val other = WscdKeystoreAdapter(mockk<Signer>(relaxed = true))
        val notAnAdapter = mockk<KeystoreManager>(relaxed = true)
        val o = WscdAssuranceOverride("iso_18045_high", "iso_18045_moderate")
        val applied = applyWscdAssuranceOverrides(
            mapOf("softkey" to o, "absent" to o, "plain" to o),
            mapOf("softkey" to soft, "other" to other, "plain" to notAnAdapter),
        )
        assertEquals(setOf("softkey"), applied)
        assertSame(o, soft.testOnlyAssuranceOverride)
        assertNull(other.testOnlyAssuranceOverride)
    }

    @Test
    fun anInvalidTierIsRefusedWhenTheOverrideIsBuilt_soItNeverReachesAConfig() {
        for (bad in listOf("high", "iso_18045_extreme", "iso_29115_loa3", "", "ISO_18045_HIGH")) {
            try {
                WscdAssuranceOverride(bad)
                fail("accepted key storage $bad")
            } catch (_: IllegalArgumentException) {
            }
            try {
                WscdAssuranceOverride("iso_18045_high", bad)
                fail("accepted user authentication $bad")
            } catch (_: IllegalArgumentException) {
            }
        }
        WscdAssuranceOverride("iso_18045_basic")
        WscdAssuranceOverride("iso_18045_high", null)
    }

    @Test
    fun aBlankPluginIdIsRefusedByTheConfig() {
        try {
            WalletConfig(backendUrl = "https://b.example", testOnlyWscdAssuranceOverrides = mapOf(" " to WscdAssuranceOverride("iso_18045_high")))
            fail("accepted a blank plugin id")
        } catch (_: IllegalArgumentException) {
        }
    }
}
