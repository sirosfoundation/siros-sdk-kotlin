// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.material3.Typography
import androidx.compose.ui.graphics.Color
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * A credential card is drawn from its registry design; where that design
 * leaves something open, the card (CredentialCard.kt, and the status ribbon
 * in CredentialStatusUi.kt) falls back on the app theme. These are the theme
 * values it reads. They belong to the cards: restyling the wallet's own
 * screens leaves every one of them as it is.
 */
class CredentialCardThemeTest {

    @Test
    fun theLightColoursACardReadsAreTheCards() {
        with(SirosLightColorScheme) {
            assertEquals(Color(0xFF1B4587), primary)
            assertEquals(Color.White, onPrimary)
            assertEquals(Color(0xFF1B4587), primaryContainer)
            assertEquals(Color(0xFFEE4444), error)
            assertEquals(Color.White, onError)
            assertEquals(Color(0xFFF3F4F6), surfaceVariant)
            assertEquals(Color(0xFF4B5563), onSurfaceVariant)
            // Never set by this theme: the Material baseline values.
            val baseline = androidx.compose.material3.lightColorScheme()
            assertEquals(baseline.tertiary, tertiary)
            assertEquals(baseline.onTertiary, onTertiary)
            assertEquals(baseline.tertiaryContainer, tertiaryContainer)
            assertEquals(baseline.onTertiaryContainer, onTertiaryContainer)
        }
    }

    @Test
    fun theDarkColoursACardReadsAreTheCards() {
        with(SirosDarkColorScheme) {
            assertEquals(Color(0xFF3D66A7), primary)
            assertEquals(Color.White, onPrimary)
            assertEquals(Color(0xFF1B4587), primaryContainer)
            assertEquals(Color(0xFFFF6B6B), error)
            assertEquals(Color.White, onError)
            assertEquals(Color(0xFF1C2433), surfaceVariant)
            assertEquals(Color(0xFFB3BBC6), onSurfaceVariant)
            val baseline = androidx.compose.material3.darkColorScheme()
            assertEquals(baseline.tertiary, tertiary)
            assertEquals(baseline.onTertiary, onTertiary)
            assertEquals(baseline.tertiaryContainer, tertiaryContainer)
            assertEquals(baseline.onTertiaryContainer, onTertiaryContainer)
        }
    }

    @Test
    fun theTypeStylesACardIsSetInAreTheMaterialDefaults() {
        val baseline = Typography()
        assertEquals(baseline.titleLarge, SirosTypography.titleLarge)
        assertEquals(baseline.labelMedium, SirosTypography.labelMedium)
        assertEquals(baseline.labelSmall, SirosTypography.labelSmall)
    }
}
