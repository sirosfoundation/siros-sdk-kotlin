// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.siros.sdk.credentials.CredentialOffer

/**
 * Drives [AddCredentialScreen]'s top-level 3-way chooser (scan passport /
 * scan QR / all known credentials) - requested live during gdc e2e testing
 * to replace a single flat list that mixed the IDV row and every issuer's
 * offers into one scroll. Renders the composable directly with plain
 * lambdas, no wallet session or SDK backing it, since it's a pure composable
 * over its callback parameters.
 */
@RunWith(AndroidJUnit4::class)
class AddCredentialScreenTest {

    @get:Rule
    val composeRule = createComposeRule()

    private fun offer(name: String) = CredentialOffer(
        credentialConfigurationId = "cfg-$name",
        credentialIssuerIdentifier = "https://issuer.example",
        credentialName = name,
        issuerName = "Example Issuer",
    )

    /**
     * The chooser itself must show exactly the 3 top-level options and never
     * the flat offer catalog inline - that's the whole point of this
     * redesign. Two offers are passed in to prove they're hidden until the
     * user drills into "All known credentials", not merely absent because
     * the list happened to be empty.
     */
    @Test
    fun chooserShowsThreeOptionsNotTheFlatOfferList() {
        composeRule.setContent {
            AddCredentialScreen(
                offers = listOf(offer("Student ID"), offer("Transit Pass")),
                isLoading = false,
                onOfferSelected = {},
                onStartIDV = {},
                onScanQr = {},
            )
        }

        composeRule.onNodeWithText("Digital ID (scanned passport)").assertExists()
        composeRule.onNodeWithText("Scan QR code").assertExists()
        composeRule.onNodeWithText("All known credentials").assertExists()

        // The flat list's own rows must not be reachable without drilling in.
        composeRule.onNodeWithText("Student ID").assertDoesNotExist()
        composeRule.onNodeWithText("Transit Pass").assertDoesNotExist()
    }

    /**
     * Regression guard for task #275: a tenant whose only catalog offer is
     * the plain "siros_id" one (filtered out upstream by
     * `WalletViewModel.openAddCredential` precisely because the IDV row
     * below is the one, unified path to that same credential) must still
     * always see "Scan passport" - its visibility must depend solely on
     * [AddCredentialScreen]'s `onStartIDV` being non-null, never on `offers`
     * being empty.
     */
    @Test
    fun scanPassportSurvivesAnEmptyOfferCatalog() {
        composeRule.setContent {
            AddCredentialScreen(
                offers = emptyList(),
                isLoading = false,
                onOfferSelected = {},
                onStartIDV = {},
                onScanQr = {},
            )
        }

        composeRule.onNodeWithText("Digital ID (scanned passport)").assertExists()
        composeRule.onNodeWithText("Scan QR code").assertExists()
        composeRule.onNodeWithText("All known credentials").assertExists()
    }

    /** When IDV isn't configured for this tenant, its row simply isn't shown - the other two options still are. */
    @Test
    fun scanPassportHiddenWhenIdvUnavailable() {
        composeRule.setContent {
            AddCredentialScreen(
                offers = emptyList(),
                isLoading = false,
                onOfferSelected = {},
                onStartIDV = null,
                onScanQr = {},
            )
        }

        composeRule.onNodeWithText("Digital ID (scanned passport)").assertDoesNotExist()
        composeRule.onNodeWithText("Scan QR code").assertExists()
        composeRule.onNodeWithText("All known credentials").assertExists()
    }

    /** Tapping "Scan QR code" calls [onScanQr] directly - no intermediate sub-screen, same as Scan passport's onStartIDV. */
    @Test
    fun tappingScanQrInvokesCallback() {
        var qrTapped = 0
        composeRule.setContent {
            AddCredentialScreen(
                offers = emptyList(),
                isLoading = false,
                onOfferSelected = {},
                onStartIDV = {},
                onScanQr = { qrTapped++ },
            )
        }

        composeRule.onNodeWithText("Scan QR code").performClick()
        assertEquals(1, qrTapped)
    }

    /**
     * Tapping "All known credentials" drills into the old flat list (now the
     * sub-view) and a back control returns to the 3-option chooser without
     * leaving [AddCredentialScreen] entirely (that's still the caller's
     * separate `onStartIDV`/`onScanQr`/outer close affordance, not this
     * composable's concern).
     */
    @Test
    fun allKnownCredentialsDrillsInAndBackReturnsToChooser() {
        composeRule.setContent {
            AddCredentialScreen(
                offers = listOf(offer("Student ID")),
                isLoading = false,
                onOfferSelected = {},
                onStartIDV = {},
                onScanQr = {},
            )
        }

        composeRule.onNodeWithText("All known credentials").performClick()
        composeRule.onNodeWithText("Student ID").assertExists()
        // The chooser's own options are no longer on screen while drilled in.
        composeRule.onNodeWithText("Digital ID (scanned passport)").assertDoesNotExist()

        // The back control is an IconButton whose Icon carries this string as
        // its contentDescription, not a Text node - onNodeWithText here would
        // never match, so the earlier version of this test failed before it
        // could verify navigation back to the chooser at all.
        val backLabel = InstrumentationRegistry.getInstrumentation().targetContext
            .getString(R.string.add_credential_all_back)
        composeRule.onNodeWithContentDescription(backLabel).performClick()

        composeRule.onNodeWithText("Digital ID (scanned passport)").assertExists()
        composeRule.onNodeWithText("Student ID").assertDoesNotExist()
    }

    /** Selecting an offer from the drilled-in list still invokes [onOfferSelected], unchanged from before this redesign. */
    @Test
    fun selectingAnOfferFromTheDrilledInListInvokesCallback() {
        var selected: CredentialOffer? = null
        composeRule.setContent {
            AddCredentialScreen(
                offers = listOf(offer("Student ID")),
                isLoading = false,
                onOfferSelected = { selected = it },
                onStartIDV = {},
                onScanQr = {},
            )
        }

        composeRule.onNodeWithText("All known credentials").performClick()
        composeRule.onNodeWithText("Student ID").performClick()
        assertEquals("Student ID", selected?.credentialName)
    }
}
