// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample.dcapi

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetDigitalCredentialOption
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import org.siros.sdk.credentials.WalletException
import org.siros.sdk.sample.R
import timber.log.Timber

/**
 * Near-headless Activity that receives the OS's Digital Credentials API
 * `GET_CREDENTIAL` intent when the user picks one of this app's entries
 * from a browser page's `navigator.credentials.get({digital: {...}})`
 * picker (see [DCAPIProviderRegistration]).
 *
 * Not necessarily launched via [org.siros.sdk.sample.MainActivity] - the OS
 * can start this directly from the credential picker, so it must not assume
 * any existing UI state. It reuses the currently-unlocked wallet session via
 * [WalletSessionHolder] (see that class's doc comment for the cold-start
 * limitation) rather than performing its own login/unlock flow.
 *
 * All DC API protocol logic (request parsing, trust evaluation, DCQL
 * matching, signing, response encryption) runs in
 * [org.siros.sdk.wallet.SirosWallet.handleDCAPIRequest] - this Activity is
 * just the platform glue: extract the request + verified origin from the
 * Intent, call the SDK, and hand the result back via [PendingIntentHandler].
 *
 * Shows a bare spinner rather than being fully invisible/transparent:
 * [org.siros.sdk.wallet.SirosWallet.handleDCAPIRequest] does real network
 * work (trust evaluation, occasionally an engine reconnect) that can take
 * more than an instant, and a blank screen during that window reads as
 * frozen - a real test found a user swiping away what looked like a hung
 * screen, which tears down the whole host task (including the calling
 * browser, since this Activity runs in the caller's task).
 */
@OptIn(ExperimentalDigitalCredentialApi::class)
class DCAPIGetCredentialActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { LoadingSpinner() }

        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        if (request == null) {
            finishWithError("No credential request found in intent")
            return
        }

        val digitalOption = request.credentialOptions
            .filterIsInstance<GetDigitalCredentialOption>()
            .firstOrNull()
        if (digitalOption == null) {
            finishWithError("No digital credential option in request")
            return
        }

        // The verified origin the OS/browser attests, NOT anything read from
        // the request body itself - resolved against Google Password
        // Manager's openly-published privileged browser allowlist
        // (https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json,
        // bundled at res/raw/gpm_privileged_apps.json), the same allowlist
        // Chrome's own passkey/DC API origin verification is checked against.
        val origin = try {
            request.callingAppInfo.getOrigin(loadPrivilegedAllowlist())
        } catch (e: Exception) {
            Timber.w(e, "Could not resolve verified origin for DC API request")
            null
        }
        if (origin == null) {
            finishWithError("Could not verify the calling origin")
            return
        }

        val wallet = WalletSessionHolder.wallet
        if (wallet == null) {
            finishWithError("Wallet is not unlocked - open the app once first")
            return
        }

        Timber.d("DCAPI raw request (origin=$origin): ${digitalOption.requestJson}")

        lifecycleScope.launch {
            try {
                val result = wallet.handleDCAPIRequest(digitalOption.requestJson, origin)
                Timber.d("DCAPI final response: ${result.responseJson}")
                val responseIntent = Intent()
                PendingIntentHandler.setGetCredentialResponse(
                    responseIntent,
                    GetCredentialResponse(DigitalCredential(result.responseJson)),
                )
                setResult(RESULT_OK, responseIntent)
                finish()
            } catch (e: WalletException) {
                Timber.w(e, "DC API presentation declined or failed")
                finishWithError(e.message ?: "Presentation failed")
            } catch (e: Exception) {
                Timber.e(e, "DC API presentation failed unexpectedly")
                finishWithError(e.message ?: "Presentation failed")
            }
        }
    }

    private fun finishWithError(message: String) {
        val responseIntent = Intent()
        PendingIntentHandler.setGetCredentialException(responseIntent, GetCredentialUnknownException(message))
        setResult(RESULT_OK, responseIntent)
        finish()
    }

    private fun loadPrivilegedAllowlist(): String =
        resources.openRawResource(R.raw.gpm_privileged_apps).bufferedReader().use { it.readText() }
}

@Composable
private fun LoadingSpinner() {
    Box(
        modifier = Modifier.fillMaxSize().background(Color.Black.copy(alpha = 0.4f)),
        contentAlignment = Alignment.Center,
    ) {
        CircularProgressIndicator(color = Color.White)
    }
}
