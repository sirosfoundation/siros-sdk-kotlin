// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.ui.test.junit4.createComposeRule
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
 * Drives [AddCredentialScreen]: the Scan QR code and Scan Photo ID cards on
 * top and the issuers' catalog listed in place under "Available credentials".
 * Renders the composable directly with plain lambdas, no wallet session or
 * SDK backing it, since it's a pure composable over its callback parameters.
 */
@RunWith(AndroidJUnit4::class)
class AddCredentialScreenTest {

    @get:Rule
    val composeRule = createComposeRule()

    private fun string(id: Int) = InstrumentationRegistry.getInstrumentation().targetContext.getString(id)
    private val scanQr get() = string(R.string.add_credential_option_scan_qr_title)
    private val photoId get() = string(R.string.add_credential_option_photo_id_title)
    private val available get() = string(R.string.add_credential_available)

    private fun offer(name: String) = CredentialOffer(
        credentialConfigurationId = "cfg-$name",
        credentialIssuerIdentifier = "https://issuer.example",
        credentialName = name,
        issuerName = "Example Issuer",
    )

    /** Both entry cards and every offer of the catalog are on the one screen. */
    @Test
    fun showsTheEntryCardsAndTheCatalogInPlace() {
        composeRule.setContent {
            AddCredentialScreen(
                offers = listOf(offer("Student ID"), offer("Transit Pass")),
                isLoading = false,
                onOfferSelected = {},
                onStartIDV = {},
                onScanQr = {},
            )
        }

        composeRule.onNodeWithText(scanQr).assertExists()
        composeRule.onNodeWithText(photoId).assertExists()
        composeRule.onNodeWithText(available).assertExists()
        composeRule.onNodeWithText("Student ID").assertExists()
        composeRule.onNodeWithText("Transit Pass").assertExists()
    }

    /**
     * Regression guard for task #275: a tenant whose only catalog offer is
     * the plain "siros_id" one (filtered out upstream by
     * `WalletViewModel.openAddCredential` precisely because the Photo ID card
     * is the one, unified path to that same credential) must still always
     * see Scan Photo ID - its visibility depends solely on
     * [AddCredentialScreen]'s `onStartIDV` being non-null, never on `offers`
     * being empty.
     */
    @Test
    fun scanPhotoIdSurvivesAnEmptyOfferCatalog() {
        composeRule.setContent {
            AddCredentialScreen(
                offers = emptyList(),
                isLoading = false,
                onOfferSelected = {},
                onStartIDV = {},
                onScanQr = {},
            )
        }

        composeRule.onNodeWithText(photoId).assertExists()
        composeRule.onNodeWithText(scanQr).assertExists()
        composeRule.onNodeWithText(string(R.string.add_credential_empty)).assertExists()
    }

    /** When IDV isn't configured for this tenant, its card simply isn't shown - Scan QR code still is. */
    @Test
    fun scanPhotoIdHiddenWhenIdvUnavailable() {
        composeRule.setContent {
            AddCredentialScreen(
                offers = emptyList(),
                isLoading = false,
                onOfferSelected = {},
                onStartIDV = null,
                onScanQr = {},
            )
        }

        composeRule.onNodeWithText(photoId).assertDoesNotExist()
        composeRule.onNodeWithText(scanQr).assertExists()
    }

    /** Tapping "Scan QR code" calls [onScanQr] directly, and Scan Photo ID calls onStartIDV. */
    @Test
    fun tappingTheEntryCardsInvokesTheirCallbacks() {
        var qrTapped = 0
        var idvTapped = 0
        composeRule.setContent {
            AddCredentialScreen(
                offers = emptyList(),
                isLoading = false,
                onOfferSelected = {},
                onStartIDV = { idvTapped++ },
                onScanQr = { qrTapped++ },
            )
        }

        composeRule.onNodeWithText(scanQr).performClick()
        assertEquals(1, qrTapped)
        assertEquals(0, idvTapped)
        composeRule.onNodeWithText(photoId).performClick()
        assertEquals(1, idvTapped)
    }

    /** Tapping an offer of the in-place catalog selects that offer. */
    @Test
    fun tappingAnOfferSelectsIt() {
        val selected = mutableListOf<String>()
        composeRule.setContent {
            AddCredentialScreen(
                offers = listOf(offer("Student ID"), offer("Transit Pass")),
                isLoading = false,
                onOfferSelected = { selected += it.credentialName },
                onStartIDV = {},
                onScanQr = {},
            )
        }

        composeRule.onNodeWithText("Transit Pass").performClick()
        assertEquals(listOf("Transit Pass"), selected)
    }
}
