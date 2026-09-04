// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample.dcapi

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetDigitalCredentialOption
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import org.siros.sdk.credentials.CredentialMatcher
import org.siros.sdk.credentials.WalletException
import org.siros.sdk.sample.R
import org.siros.sdk.wallet.dcapi.DCAPIRequestParser
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

        // Cheap, synchronous pre-check (no network/trust eval - see
        // CredentialMatcher.isZkRequest's own doc comment) so the loading UI
        // can immediately signal "this is a zero-knowledge proof, not a raw
        // disclosure" instead of a generic spinner, without waiting for
        // SirosWallet.handleDCAPIRequest's full async request handling below.
        val isZkProof = try {
            DCAPIRequestParser.parse(digitalOption.requestJson).dcqlQuery
                ?.let { CredentialMatcher.isZkRequest(it) } == true
        } catch (e: Exception) {
            false
        }
        setContent { LoadingSpinner(isZkProof = isZkProof) }

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
                // A decline (untrusted verifier, no matching/eligible
                // credential, missing encryption key, ...) is a normal
                // OpenID4VP-protocol outcome, not a platform-level failure -
                // surfacing it via setGetCredentialException makes Chrome
                // reject navigator.credentials.get() with a generic
                // "error retrieving a token", discarding our specific reason
                // before the RP's own JS ever sees it. Returning it as a
                // real (successful) DC API response whose body is an
                // OpenID4VP error object lets the RP read and display the
                // actual reason instead.
                Timber.w(e, "DC API presentation declined")
                finishWithProtocolError(e.message ?: "Presentation declined")
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

    /**
     * Finishes with a real DC API response carrying an OpenID4VP error
     * object (`{"error": "access_denied", "error_description": "..."}`) -
     * per OpenID4VP 1.0's DC API response mode, this is returned as plain
     * JSON regardless of whether the request asked for an encrypted
     * (`dc_api.jwt`) success response; there is no RP-supplied encryption
     * key to use here since trust evaluation (which is what most declines
     * happen during) runs before `client_metadata.jwks` is ever consulted.
     * `access_denied` covers every current decline reason (untrusted
     * verifier, no matching/eligible credential, missing encryption key) -
     * none of them are distinguished by [WalletException.errorCode] today,
     * and OpenID4VP doesn't define a more specific code for most of them
     * anyway.
     */
    private fun finishWithProtocolError(description: String) {
        val errorJson = buildJsonObject {
            put("error", JsonPrimitive("access_denied"))
            put("error_description", JsonPrimitive(description))
        }.toString()
        Timber.d("DCAPI error response: $errorJson")
        val responseIntent = Intent()
        PendingIntentHandler.setGetCredentialResponse(
            responseIntent,
            GetCredentialResponse(DigitalCredential(errorJson)),
        )
        setResult(RESULT_OK, responseIntent)
        finish()
    }

    private fun loadPrivilegedAllowlist(): String =
        resources.openRawResource(R.raw.gpm_privileged_apps).bufferedReader().use { it.readText() }
}

@Composable
private fun LoadingSpinner(isZkProof: Boolean = false) {
    Box(
        modifier = Modifier.fillMaxSize().background(Color.Black.copy(alpha = 0.4f)),
        contentAlignment = Alignment.Center,
    ) {
        if (isZkProof) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(
                    imageVector = Icons.Filled.Lock,
                    contentDescription = null,
                    tint = Color.White,
                    modifier = Modifier.padding(bottom = 12.dp),
                )
                CircularProgressIndicator(color = Color.White)
                Text(
                    text = stringResource(R.string.dcapi_zk_proof_status),
                    color = Color.White,
                    style = MaterialTheme.typography.bodyMedium,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(top = 16.dp, start = 24.dp, end = 24.dp),
                )
                Text(
                    text = stringResource(R.string.dcapi_zk_proof_detail),
                    color = Color.White.copy(alpha = 0.8f),
                    style = MaterialTheme.typography.bodySmall,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(top = 8.dp, start = 24.dp, end = 24.dp),
                )
            }
        } else {
            CircularProgressIndicator(color = Color.White)
        }
    }
}
