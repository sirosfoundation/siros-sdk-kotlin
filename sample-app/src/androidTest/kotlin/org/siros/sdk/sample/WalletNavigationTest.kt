// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.material3.Text
import androidx.compose.ui.test.assertIsNotSelected
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The screens that organise the wallet - the frame with its bottom bar, Home,
 * the menu and Share In-Person - each rendered on its own over plain lambdas:
 * every control leads where the design says it leads.
 */
@RunWith(AndroidJUnit4::class)
class WalletNavigationTest {

    @get:Rule
    val composeRule = createComposeRule()

    private fun string(id: Int, vararg args: Any) =
        InstrumentationRegistry.getInstrumentation().targetContext.getString(id, *args)

    @Test
    fun theBottomBarLeadsHomeToTheScannerAndToTheMenu() {
        val taps = mutableListOf<String>()
        composeRule.setContent {
            SirosTheme {
                WalletChrome(
                    displayName = "Elisa",
                    selected = WalletNavItem.Home,
                    onHome = { taps += "home" },
                    onScanQr = { taps += "scan" },
                    onMenu = { taps += "menu" },
                    onAccount = { taps += "account" },
                ) { Text("content") }
            }
        }

        composeRule.onNodeWithText(string(R.string.header_wallet_of, "Elisa")).assertExists()
        composeRule.onNodeWithText("content").assertExists()
        // The destination in use is announced as selected, not only tinted.
        composeRule.onNodeWithTag(NAV_HOME_TAG).assertIsSelected()
        composeRule.onNodeWithTag(NAV_MENU_TAG).assertIsNotSelected()
        composeRule.onNodeWithTag(NAV_HOME_TAG).performClick()
        composeRule.onNodeWithTag(NAV_SCAN_QR_TAG).performClick()
        composeRule.onNodeWithTag(NAV_MENU_TAG).performClick()
        assertEquals(listOf("home", "scan", "menu"), taps)
    }

    @Test
    fun aFullAttentionScreenCarriesBackInPlaceOfTheBottomBar() {
        var back = 0
        composeRule.setContent {
            SirosTheme {
                WalletChrome(
                    displayName = null,
                    selected = null,
                    onHome = {},
                    onScanQr = {},
                    onMenu = {},
                    onAccount = {},
                    onBack = { back++ },
                ) { Text("content") }
            }
        }

        composeRule.onNodeWithText(string(R.string.header_my_wallet)).assertExists()
        composeRule.onNodeWithTag(NAV_HOME_TAG).assertDoesNotExist()
        composeRule.onNodeWithTag(NAV_SCAN_QR_TAG).assertDoesNotExist()
        composeRule.onNodeWithText(string(R.string.nav_back)).performClick()
        assertEquals(1, back)
    }

    private fun home(attentionCount: Int, taps: MutableList<String>, showAdd: Boolean = true) {
        composeRule.setContent {
            SirosTheme {
                HomeScreen(
                    displayName = "Elisa",
                    attentionCount = attentionCount,
                    onShowAttention = { taps += "attention" },
                    onManageCredentials = { taps += "manage" },
                    onShareInPerson = { taps += "share" },
                    showAddCredentials = showAdd,
                    onAddCredentials = { taps += "add" },
                    onDismissAddCredentials = { taps += "dismiss" },
                )
            }
        }
    }

    @Test
    fun homeGreetsTheUserAndLeadsToItsTwoTilesAndTheAttentionFilter() {
        val taps = mutableListOf<String>()
        home(attentionCount = 1, taps)

        composeRule.onNodeWithText(string(R.string.home_welcome_back_name, "Elisa")).assertExists()
        composeRule.onNodeWithText(string(R.string.home_attention_one)).assertExists()
        composeRule.onNodeWithTag(HOME_ATTENTION_TAG).performClick()
        composeRule.onNodeWithTag(HOME_MANAGE_TAG).performClick()
        composeRule.onNodeWithTag(HOME_SHARE_TAG).performClick()
        composeRule.onNodeWithText(string(R.string.home_prompt_get_started)).performClick()
        composeRule.onNode(androidx.compose.ui.test.hasContentDescription(string(R.string.home_prompt_dismiss))).performClick()
        assertEquals(listOf("attention", "manage", "share", "add", "dismiss"), taps)
    }

    @Test
    fun homeShowsNoBannerWhenNothingNeedsAttention() {
        home(attentionCount = 0, mutableListOf(), showAdd = false)

        composeRule.onNodeWithTag(HOME_ATTENTION_TAG).assertDoesNotExist()
        composeRule.onNodeWithText(string(R.string.home_prompt_get_started)).assertDoesNotExist()
        composeRule.onNodeWithTag(HOME_MANAGE_TAG).assertExists()
    }

    @Test
    fun homeCountsSeveralCredentialsNeedingAttention() {
        home(attentionCount = 3, mutableListOf())

        composeRule.onNodeWithText(string(R.string.home_attention_other, 3)).assertExists()
    }

    @Test
    fun everyMenuRowReportsItsOwnItem() {
        val selected = mutableListOf<MenuItem>()
        composeRule.setContent {
            SirosTheme { MenuScreen(current = MenuItem.Settings, onSelect = { selected += it }) }
        }

        MenuItem.entries.forEach { composeRule.onNodeWithTag(menuItemTestTag(it)).performClick() }
        assertEquals(MenuItem.entries.toList(), selected)
    }

    @Test
    fun shareInPersonOffersTapShowAndScan() {
        val taps = mutableListOf<String>()
        composeRule.setContent {
            SirosTheme {
                ShareInPersonScreen(onTap = { taps += "tap" }, onShowQr = { taps += "show" }, onScanQr = { taps += "scan" })
            }
        }

        composeRule.onNodeWithTag(SHARE_TAP_TAG).performClick()
        composeRule.onNodeWithTag(SHARE_SHOW_QR_TAG).performClick()
        composeRule.onNodeWithTag(SHARE_SCAN_QR_TAG).performClick()
        assertEquals(listOf("tap", "show", "scan"), taps)
    }

    @Test
    fun startScanWaitsForTheBiometricConsent() {
        var started = 0
        composeRule.setContent {
            SirosTheme { IDVPreparationScreen(onStartScan = { started++ }, onBack = {}) }
        }

        composeRule.onNodeWithTag(IDV_START_TAG).performScrollTo().performClick()
        assertEquals(0, started)
        composeRule.onNodeWithTag(IDV_CONSENT_TAG).performScrollTo().performClick()
        composeRule.onNodeWithTag(IDV_START_TAG).performScrollTo().performClick()
        assertEquals(1, started)
    }

    /** The Settings card stores the choice, and a later read of the same preferences starts from it. */
    @Test
    fun theAppearanceChoiceIsStoredAndReadBack() {
        val prefs = InstrumentationRegistry.getInstrumentation().targetContext
            .getSharedPreferences("siros_appearance_test", android.content.Context.MODE_PRIVATE)
        prefs.edit().clear().commit()
        val settings = ThemeSettings(prefs)
        assertEquals(ThemeMode.SYSTEM, settings.mode.value)
        composeRule.setContent {
            androidx.compose.runtime.CompositionLocalProvider(LocalThemeSettings provides settings) {
                SirosTheme { AppearanceSetting() }
            }
        }

        composeRule.onNodeWithTag(themeModeTestTag(ThemeMode.DARK)).performClick()
        assertEquals(ThemeMode.DARK, settings.mode.value)
        assertEquals(ThemeMode.DARK, ThemeSettings(prefs).mode.value)

        composeRule.onNodeWithTag(themeModeTestTag(ThemeMode.LIGHT)).performClick()
        assertEquals(ThemeMode.LIGHT, ThemeSettings(prefs).mode.value)
        prefs.edit().clear().commit()
    }
}
