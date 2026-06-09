package org.sirosfoundation.sdk.sample

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight

// Brand colors from wallet-frontend branding/default/theme.json
// Primary: hsl(217, 66%, 32%) → #1B4587
private val SirosBrand = Color(0xFF1B4587)
private val SirosBrandLight = Color(0xFF3D66A7)
private val SirosBrandLighter = Color(0xFF7D92B4)
private val SirosBrandDark = Color(0xFF3E6098)
private val SirosNavyDeep = Color(0xFF131B29)
private val SirosNavyMid = Color(0xFF262E3F)
private val SirosOnPrimary = Color.White
private val SirosBackground = Color(0xFFF9FAFB)
private val SirosSurface = Color.White
private val SirosSurfaceVariant = Color(0xFFF3F4F6)
private val SirosOnSurface = Color(0xFF111621)
private val SirosOnSurfaceVariant = Color(0xFF4B5563)
private val SirosError = Color(0xFFEE4444)
private val SirosBorder = Color(0xFFE5E7EB)

private val SirosColorScheme = lightColorScheme(
    primary = SirosBrand,
    onPrimary = SirosOnPrimary,
    primaryContainer = SirosBrand,
    onPrimaryContainer = SirosOnPrimary,
    secondary = SirosBrandLight,
    onSecondary = SirosOnPrimary,
    secondaryContainer = SirosSurfaceVariant,
    onSecondaryContainer = SirosOnSurface,
    background = SirosBackground,
    onBackground = SirosOnSurface,
    surface = SirosSurface,
    onSurface = SirosOnSurface,
    surfaceVariant = SirosSurfaceVariant,
    onSurfaceVariant = SirosOnSurfaceVariant,
    error = SirosError,
    onError = SirosOnPrimary,
    outline = SirosBorder,
    outlineVariant = Color(0xFFD1D5DB),
)

@Composable
fun SirosTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = SirosColorScheme,
        content = content,
    )
}
