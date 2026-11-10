// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The appearance setting: follow the device, or always light, or always dark. */
class ThemeModeTest {

    @Test
    fun systemFollowsTheDevice() {
        assertTrue(ThemeMode.SYSTEM.isDark(systemDark = true))
        assertFalse(ThemeMode.SYSTEM.isDark(systemDark = false))
    }

    @Test
    fun anExplicitChoiceOverridesTheDeviceBothWays() {
        assertFalse(ThemeMode.LIGHT.isDark(systemDark = true))
        assertFalse(ThemeMode.LIGHT.isDark(systemDark = false))
        assertTrue(ThemeMode.DARK.isDark(systemDark = false))
        assertTrue(ThemeMode.DARK.isDark(systemDark = true))
    }

    @Test
    fun aStoredChoiceIsReadBackAndAnythingElseMeansSystem() {
        ThemeMode.entries.forEach { assertEquals(it, ThemeMode.fromStored(it.name)) }
        assertEquals(ThemeMode.SYSTEM, ThemeMode.fromStored(null))
        assertEquals(ThemeMode.SYSTEM, ThemeMode.fromStored(""))
        assertEquals(ThemeMode.SYSTEM, ThemeMode.fromStored("dark"))
        assertEquals(ThemeMode.SYSTEM, ThemeMode.fromStored("SEPIA"))
    }
}
