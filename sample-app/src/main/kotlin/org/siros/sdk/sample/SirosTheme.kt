package org.siros.sdk.sample

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Brand colors from wallet-frontend branding/default/theme.json
// Primary: hsl(217, 66%, 32%) → #1B4587
private val SirosBrand = Color(0xFF1B4587)
private val SirosBrandLight = Color(0xFF3D66A7)
private val SirosBrandLighter = Color(0xFF7D92B4)
private val SirosOnPrimary = Color.White
private val SirosError = Color(0xFFEE4444)

// Light mode
private val SirosLightColorScheme = lightColorScheme(
    primary = SirosBrand,
    onPrimary = SirosOnPrimary,
    primaryContainer = SirosBrand,
    onPrimaryContainer = SirosOnPrimary,
    secondary = SirosBrandLight,
    onSecondary = SirosOnPrimary,
    secondaryContainer = Color(0xFFF3F4F6),
    onSecondaryContainer = Color(0xFF111621),
    background = Color(0xFFF9FAFB),
    onBackground = Color(0xFF111621),
    surface = Color.White,
    onSurface = Color(0xFF111621),
    surfaceVariant = Color(0xFFF3F4F6),
    onSurfaceVariant = Color(0xFF4B5563),
    error = SirosError,
    onError = SirosOnPrimary,
    outline = Color(0xFFE5E7EB),
    outlineVariant = Color(0xFFD1D5DB),
    // Left at lightColorScheme()'s baseline (unthemed purple) default until
    // now, which several Material3 components quietly depend on -
    // Switch's unchecked track is surfaceContainerHighest, so an unchecked
    // Switch on this brand palette rendered as a barely-visible mismatched
    // tint against our white/near-white surfaces (a real contrast bug found
    // via live testing). Tuned to a visible ascending-elevation gray scale
    // consistent with the outline colors above (surfaceContainerHighest
    // reuses outlineVariant's gray, which is already proven legible against
    // white/onSurfaceVariant text elsewhere on this screen).
    surfaceContainerLowest = Color.White,
    surfaceContainerLow = Color(0xFFF3F4F6),
    surfaceContainer = Color(0xFFEEF0F3),
    surfaceContainerHigh = Color(0xFFE5E7EB),
    surfaceContainerHighest = Color(0xFFD1D5DB),
)

// Dark mode — navy-derived from SIROS brand palette
private val SirosDarkColorScheme = darkColorScheme(
    primary = SirosBrandLight,
    onPrimary = Color.White,
    primaryContainer = SirosBrand,
    onPrimaryContainer = Color.White,
    secondary = SirosBrandLighter,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFF1C2433),
    onSecondaryContainer = Color(0xFFEEF0F3),
    background = Color(0xFF131B29),
    onBackground = Color(0xFFEEF0F3),
    surface = Color(0xFF262E3F),
    onSurface = Color(0xFFEEF0F3),
    surfaceVariant = Color(0xFF1C2433),
    onSurfaceVariant = Color(0xFFB3BBc6),
    error = Color(0xFFFF6B6B),
    onError = Color.White,
    outline = Color(0xFF333A48),
    outlineVariant = Color(0xFF2A3244),
    // See the light scheme's matching fields above for why these are
    // explicitly tuned rather than left at the default baseline palette.
    surfaceContainerLowest = Color(0xFF131B29),
    surfaceContainerLow = Color(0xFF1C2433),
    surfaceContainer = Color(0xFF222B3B),
    surfaceContainerHigh = Color(0xFF2A3244),
    surfaceContainerHighest = Color(0xFF333A48),
)

@Composable
fun SirosTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) SirosDarkColorScheme else SirosLightColorScheme,
        content = content,
    )
}
