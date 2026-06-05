package org.siros.sdk.sample

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val SirosPrimary = Color(0xFF285BA3)
private val SirosPrimaryDark = Color(0xFF1C4587)
private val SirosNavyDeep = Color(0xFF131B29)
private val SirosNavyMid = Color(0xFF262E3F)
private val SirosOnPrimary = Color.White
private val SirosBackground = Color.White
private val SirosSurface = Color(0xFFF5F7F8)
private val SirosOnSurface = Color(0xFF111621)
private val SirosError = Color(0xFFEE4444)
private val SirosBorder = Color(0xFFDBE0E4)
private val SirosSecondary = Color(0xFFEAEDEF)

private val SirosColorScheme = lightColorScheme(
    primary = SirosPrimary,
    onPrimary = SirosOnPrimary,
    primaryContainer = SirosPrimaryDark,
    onPrimaryContainer = SirosOnPrimary,
    secondary = SirosSecondary,
    onSecondary = SirosOnSurface,
    background = SirosBackground,
    onBackground = SirosOnSurface,
    surface = SirosBackground,
    onSurface = SirosOnSurface,
    surfaceVariant = SirosSurface,
    onSurfaceVariant = SirosNavyMid,
    error = SirosError,
    onError = SirosOnPrimary,
    outline = SirosBorder,
)

@Composable
fun SirosTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = SirosColorScheme,
        content = content,
    )
}
