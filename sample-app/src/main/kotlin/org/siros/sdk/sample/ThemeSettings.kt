// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import android.content.SharedPreferences
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** Which appearance the app uses: the device's, or one the user picked. */
enum class ThemeMode {
    SYSTEM,
    LIGHT,
    DARK,
    ;

    /** Whether this mode shows the dark theme on a device whose own setting is [systemDark]. */
    fun isDark(systemDark: Boolean): Boolean = when (this) {
        SYSTEM -> systemDark
        LIGHT -> false
        DARK -> true
    }

    companion object {
        /** The mode stored as [value]; [SYSTEM] when nothing, or nothing recognisable, is stored. */
        fun fromStored(value: String?): ThemeMode = entries.firstOrNull { it.name == value } ?: SYSTEM
    }
}

/**
 * The user's appearance choice, kept in the app's preferences. It is read at
 * the root of the UI, above the wallet session and its view model, so that
 * the login screen follows it too.
 */
class ThemeSettings(private val prefs: SharedPreferences) {
    private val _mode = MutableStateFlow(ThemeMode.fromStored(prefs.getString(KEY, null)))
    val mode: StateFlow<ThemeMode> = _mode

    fun setMode(mode: ThemeMode) {
        prefs.edit().putString(KEY, mode.name).apply()
        _mode.value = mode
    }

    companion object {
        const val PREFS = "siros_appearance"
        private const val KEY = "theme_mode"
    }
}

/** The app's [ThemeSettings]; null where a screen is rendered on its own (previews, tests). */
val LocalThemeSettings = staticCompositionLocalOf<ThemeSettings?> { null }

fun themeModeTestTag(mode: ThemeMode) = "theme_mode_${mode.name}"

/** Settings card: follow the device, or always light, or always dark. Renders nothing without [LocalThemeSettings]. */
@Composable
fun AppearanceSetting(modifier: Modifier = Modifier) {
    val settings = LocalThemeSettings.current ?: return
    val current by settings.mode.collectAsState()
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Column(modifier = Modifier.fillMaxWidth().padding(20.dp)) {
            Text(
                text = stringResource(R.string.settings_appearance_section),
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                color = SirosDesign.secondaryText,
            )
            Spacer(modifier = Modifier.height(12.dp))
            Row(modifier = Modifier.selectableGroup(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                ThemeMode.entries.forEach { mode ->
                    FilterChip(
                        selected = mode == current,
                        onClick = { settings.setMode(mode) },
                        label = {
                            Text(
                                stringResource(
                                    when (mode) {
                                        ThemeMode.SYSTEM -> R.string.settings_appearance_system
                                        ThemeMode.LIGHT -> R.string.settings_appearance_light
                                        ThemeMode.DARK -> R.string.settings_appearance_dark
                                    },
                                ),
                            )
                        },
                        modifier = Modifier.testTag(themeModeTestTag(mode)),
                    )
                }
            }
        }
    }
}
