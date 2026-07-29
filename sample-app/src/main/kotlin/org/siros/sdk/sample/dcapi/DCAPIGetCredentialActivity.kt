// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample.dcapi

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetDigitalCredentialOption
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import org.siros.sdk.credentials.WalletException
import timber.log.Timber

/**
 * Headless Activity that receives the OS's Digital Credentials API
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
 */
@OptIn(ExperimentalDigitalCredentialApi::class)
class DCAPIGetCredentialActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

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
        // the request body itself. TODO(#72 follow-up): the real privileged
        // browser allowlist JSON (Google's published list of privileged
        // browser package/signature pairs) needs to replace this empty
        // placeholder for getOrigin() to actually resolve a browser-supplied
        // origin - as-is this only resolves origins for privileged-allowlist
        // matches, which will legitimately be none until that's supplied.
        val origin = try {
            request.callingAppInfo.getOrigin(PRIVILEGED_ALLOWLIST_JSON)
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

        lifecycleScope.launch {
            try {
                val result = wallet.handleDCAPIRequest(digitalOption.requestJson, origin)
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

    private companion object {
        const val PRIVILEGED_ALLOWLIST_JSON = "{\"apps\":[]}"
    }
}
