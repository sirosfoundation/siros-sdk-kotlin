// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WscdPluginCapabilitiesTest {

    @Test
    fun tierOf_returnsNominalTier_forEachKnownPlugin() {
        assertEquals("iso_18045_basic", WscdPluginCapabilities.tierOf("softkey"))
        assertEquals("iso_18045_high", WscdPluginCapabilities.tierOf("fido2"))
        assertEquals("iso_18045_high", WscdPluginCapabilities.tierOf("r2ps"))
    }

    @Test
    fun tierOf_returnsNull_forUnknownPlugin() {
        assertNull(WscdPluginCapabilities.tierOf("some-future-plugin"))
    }

    @Test
    fun meets_isReflexive_forEachTier() {
        assertTrue(WscdPluginCapabilities.meets("iso_18045_basic", "iso_18045_basic"))
        assertTrue(WscdPluginCapabilities.meets("iso_18045_moderate", "iso_18045_moderate"))
        assertTrue(WscdPluginCapabilities.meets("iso_18045_high", "iso_18045_high"))
    }

    @Test
    fun meets_isTrue_whenActualExceedsRequired() {
        assertTrue(WscdPluginCapabilities.meets("iso_18045_high", "iso_18045_basic"))
        assertTrue(WscdPluginCapabilities.meets("iso_18045_moderate", "iso_18045_basic"))
    }

    @Test
    fun meets_isFalse_whenActualFallsShortOfRequired() {
        assertFalse(WscdPluginCapabilities.meets("iso_18045_basic", "iso_18045_high"))
        assertFalse(WscdPluginCapabilities.meets("iso_18045_moderate", "iso_18045_high"))
    }

    @Test
    fun meets_failsClosed_forUnrecognizedTierStrings() {
        assertFalse(WscdPluginCapabilities.meets("bogus", "iso_18045_basic"))
        assertFalse(WscdPluginCapabilities.meets("iso_18045_high", "bogus"))
    }
}
