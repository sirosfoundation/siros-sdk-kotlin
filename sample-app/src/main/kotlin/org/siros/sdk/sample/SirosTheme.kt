package org.siros.sdk.sample

import android.app.Activity
import android.content.ContextWrapper
import android.content.res.Configuration
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.material3.Typography
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

// Brand colors from wallet-frontend branding/default/theme.json
// Primary: hsl(217, 66%, 32%) → #1B4587 (the wallet design's brand blue,
// #1C4587, is the same colour to within one step of one channel).
//
// A credential card is drawn from its registry design, and where that design
// leaves something open the card falls back on this theme: primary,
// primaryContainer, error, tertiary and their "on" colours, tertiaryContainer,
// surfaceVariant, onSurfaceVariant, and the titleLarge / labelMedium /
// labelSmall type styles (see CredentialCard.kt and CredentialStatusUi.kt).
// Those values are the cards' and stay as they are; what the wallet's own
// screens need beyond them lives in [SirosDesign]. CredentialCardThemeTest
// pins them.
private val SirosBrand = Color(0xFF1B4587)
private val SirosBrandLight = Color(0xFF3D66A7)
private val SirosBrandLighter = Color(0xFF7D92B4)
private val SirosOnPrimary = Color.White
private val SirosError = Color(0xFFEE4444)

// Light mode
internal val SirosLightColorScheme = lightColorScheme(
    primary = SirosBrand,
    onPrimary = SirosOnPrimary,
    primaryContainer = SirosBrand,
    onPrimaryContainer = SirosOnPrimary,
    secondary = SirosBrandLight,
    onSecondary = SirosOnPrimary,
    secondaryContainer = Color(0xFFE5EEFD),
    onSecondaryContainer = SirosBrand,
    background = Color.White,
    onBackground = Color(0xFF0C0E11),
    surface = Color.White,
    onSurface = Color(0xFF0C0E11),
    surfaceVariant = Color(0xFFF3F4F6),
    onSurfaceVariant = Color(0xFF4B5563),
    error = SirosError,
    onError = SirosOnPrimary,
    errorContainer = Color(0xFFFBE1E0),
    onErrorContainer = Color(0xFFC61616),
    outline = Color(0xFFE0E1E4),
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
internal val SirosDarkColorScheme = darkColorScheme(
    primary = SirosBrandLight,
    onPrimary = Color.White,
    primaryContainer = SirosBrand,
    onPrimaryContainer = Color.White,
    secondary = SirosBrandLighter,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFF24365A),
    onSecondaryContainer = Color(0xFFC9D8F5),
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

/**
 * The design's type scale: 32/28/24 medium headings, 18 semibold section
 * titles, 16 body, 14 semibold labels. Set in the platform sans-serif, which
 * the design's Inter closely matches in metrics. titleLarge, labelMedium and
 * labelSmall are the Material defaults: credential cards are set in them.
 */
internal val SirosTypography = Typography().run {
    copy(
        headlineLarge = headlineLarge.copy(fontSize = 32.sp, lineHeight = 40.sp, fontWeight = FontWeight.Medium),
        headlineMedium = headlineMedium.copy(fontSize = 28.sp, lineHeight = 36.sp, fontWeight = FontWeight.Medium),
        headlineSmall = headlineSmall.copy(fontSize = 24.sp, lineHeight = 32.sp, fontWeight = FontWeight.Medium),
        titleMedium = titleMedium.copy(fontSize = 18.sp, lineHeight = 24.sp, fontWeight = FontWeight.SemiBold),
        titleSmall = titleSmall.copy(fontSize = 16.sp, lineHeight = 22.sp, fontWeight = FontWeight.SemiBold),
        bodyLarge = bodyLarge.copy(fontSize = 16.sp, lineHeight = 22.sp, letterSpacing = 0.sp),
        bodyMedium = bodyMedium.copy(fontSize = 14.sp, lineHeight = 20.sp, letterSpacing = 0.sp),
        labelLarge = labelLarge.copy(fontSize = 14.sp, lineHeight = 20.sp, fontWeight = FontWeight.SemiBold),
    )
}

/**
 * Colours of the wallet design ("Mobile Landing & Navigation") that the
 * wallet's own screens use and credential cards do not: secondary text,
 * the alternate surface #F8F9F9 and the attention amber #F9A917.
 *
 * Secondary text is #69707D, a step darker than the design's #6E7582, which
 * reaches only 4.4:1 on the alternate surface; this reads at 4.7:1 there and
 * 5.0:1 on white.
 */
object SirosDesign {
    private val dark: Boolean
        @Composable get() = MaterialTheme.colorScheme.background.luminance() < 0.5f

    val secondaryText: Color
        @Composable get() = if (dark) Color(0xFFB3BBC6) else Color(0xFF69707D)

    val altSurface: Color
        @Composable get() = if (dark) Color(0xFF1C2433) else Color(0xFFF8F9F9)

    val attention: Color = Color(0xFFF9A917)

    /** Brand-coloured text and icons on a page or card: the brand blue, lightened in the dark theme so it stays legible. */
    val brandOnPage: Color
        @Composable get() = if (dark) Color(0xFF9DB8EC) else Color(0xFF1B4587)

    /** The Scan QR button at the centre of the bottom bar: black with a white mark, inverted in the dark theme. */
    val scanButton: Color
        @Composable get() = if (dark) Color(0xFFEEF0F3) else Color.Black

    val onScanButton: Color
        @Composable get() = if (dark) Color(0xFF0C0E11) else Color.White
}


@Composable
fun SirosTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    // The status bar's icons follow the theme in use, which is the user's
    // choice (see ThemeSettings) and not necessarily the device's.
    StatusBarIcons(dark = !darkTheme)
    // Everything inside sees the theme in use as the device's: credential
    // cards pick their light or dark registry design by isSystemInDarkTheme(),
    // which reads this configuration.
    val base = LocalConfiguration.current
    val configuration = remember(base, darkTheme) {
        Configuration(base).apply { uiMode = uiModeFor(uiMode, darkTheme) }
    }
    CompositionLocalProvider(LocalConfiguration provides configuration) {
        MaterialTheme(
            colorScheme = if (darkTheme) SirosDarkColorScheme else SirosLightColorScheme,
            typography = SirosTypography,
            content = content,
        )
    }
}

/** [uiMode] with its night bits set to [dark], everything else as it was. */
internal fun uiModeFor(uiMode: Int, dark: Boolean): Int =
    (uiMode and Configuration.UI_MODE_NIGHT_MASK.inv()) or
        (if (dark) Configuration.UI_MODE_NIGHT_YES else Configuration.UI_MODE_NIGHT_NO)

/**
 * Draws the status bar's icons [dark] (for a light surface behind them) or
 * light. A screen that overrides the theme's choice passes [restoreTo], the
 * appearance to put back when it leaves the composition. Does nothing where
 * there is no window to address (previews, tests).
 */
@Composable
fun StatusBarIcons(dark: Boolean, restoreTo: Boolean? = null) {
    val view = LocalView.current
    if (view.isInEditMode) return
    fun apply(value: Boolean) {
        var context = view.context
        while (context is ContextWrapper && context !is Activity) context = context.baseContext
        val window = (context as? Activity)?.window ?: return
        WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = value
    }
    // A keyed effect at every level, so that when the theme changes under a
    // screen that overrides it, the theme's effect runs first and the
    // screen's, further down the composition, has the last word.
    DisposableEffect(view, dark, restoreTo) {
        apply(dark)
        onDispose { if (restoreTo != null) apply(restoreTo) }
    }
}
