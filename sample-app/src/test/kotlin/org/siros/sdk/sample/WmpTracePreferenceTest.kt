package org.siros.sdk.sample

import android.content.SharedPreferences
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Per-group trace visibility: opt-in, independent per backend, persisted. */
class WmpTracePreferenceTest {
    @Test
    fun traceIsOffByDefaultAndTogglesPerGroup() {
        val prefs = mockk<SharedPreferences>(relaxed = true) {
            every { getBoolean(any(), any()) } returns false
        }
        val trace = WmpTracePreferences(prefs)
        val engine = org.siros.sdk.wallet.WmpEndpointInfo.ORIGIN_ENGINE
        val invited = "https://relay.example.com"

        assertFalse(trace.isEnabled(engine))
        assertFalse(trace.isEnabled(invited))

        trace.setEnabled(invited, true)
        assertFalse(trace.isEnabled(engine))
        verify { prefs.edit().putBoolean("wmp.trace.$invited", true) }

        trace.setEnabled(invited, false)
        verify { prefs.edit().putBoolean("wmp.trace.$invited", false) }
    }

    @Test
    fun loadReadsOnlyTraceKeys() {
        val prefs = mockk<SharedPreferences>(relaxed = true) {
            every { all } returns mapOf(
                "wmp.trace.https://relay.example.com" to true,
                "other.preference" to false,
            )
        }
        val loaded = WmpTracePreferences(prefs).load()
        assertTrue(loaded["wmp.trace.https://relay.example.com"] == true)
        assertTrue(!loaded.containsKey("other.preference"))
    }
}
