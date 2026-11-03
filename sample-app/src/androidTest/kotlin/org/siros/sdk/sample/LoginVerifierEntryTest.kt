// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.material3.SnackbarHostState
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class LoginVerifierEntryTest {
    @get:Rule
    val compose = createComposeRule()

    @Test
    fun verifierIsAvailableWithoutAnAccount() {
        var opened = false
        compose.setContent {
            LoginScreen(
                cachedAccounts = emptyList(),
                backendUrl = "https://wallet.example",
                tenantId = "default",
                engineUrl = "",
                useWmpProtocol = false,
                zkCircuitUrls = emptyList(),
                showPreLoginSettings = false,
                isLoading = false,
                snackbarHostState = SnackbarHostState(),
                onLogin = {},
                onLoginAccount = {},
                onForgetAccount = {},
                onRegister = {},
                onVerify = { opened = true },
                onUpdateBackendUrl = {},
                onUpdateTenantId = {},
                onUpdateEngineUrl = {},
                onUpdateUseWmpProtocol = {},
                onUpdateZkCircuitUrls = {},
            )
        }

        compose.onNodeWithText("Verify nearby mdoc (no account required)")
            .assertIsDisplayed()
            .performClick()

        assertTrue(opened)
    }
}
