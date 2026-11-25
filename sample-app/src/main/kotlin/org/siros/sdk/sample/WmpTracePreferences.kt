// Copyright 2026 SIROS Foundation. BSD-2-Clause License.
package org.siros.sdk.sample

import android.content.SharedPreferences

/** Per-group trace visibility: opt-in per backend, persisted across restarts. */
class WmpTracePreferences(private val prefs: SharedPreferences) {
    /** The saved toggles (default off). */
    fun load(): Map<String, Boolean> = prefs.all
        .filterKeys { it.startsWith("wmp.trace.") }
        .mapValues { (_, value) -> value as? Boolean ?: false }

    /** Whether this group's message trace is visible (default off). */
    fun isEnabled(backend: String): Boolean = prefs.getBoolean("wmp.trace.$backend", false)

    /** Turn one group's message trace on or off, persisted. */
    fun setEnabled(backend: String, enabled: Boolean) {
        prefs.edit().putBoolean("wmp.trace.$backend", enabled).apply()
    }
}
