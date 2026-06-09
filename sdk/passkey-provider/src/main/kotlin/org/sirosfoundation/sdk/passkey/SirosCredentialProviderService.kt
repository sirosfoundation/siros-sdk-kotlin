package org.sirosfoundation.sdk.passkey

import android.app.PendingIntent
import android.content.Context
import android.os.Build
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.ClearCredentialUnknownException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import timber.log.Timber

/**
 * Android Credential Provider Service for SIROS passkeys.
 *
 * SDK consumers subclass this and register it in their AndroidManifest.xml
 * with the appropriate intent-filter and meta-data for credential provider.
 *
 * Override [createPasskeyStore] to provide custom storage, and
 * [getCreatePendingIntent] / [getGetPendingIntent] to provide the
 * activity that handles the actual WebAuthn ceremony UI.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
abstract class SirosCredentialProviderService : CredentialProviderService() {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    protected open fun createPasskeyStore(): PasskeyStore =
        SharedPrefsPasskeyStore(applicationContext)

    protected abstract fun getCreatePendingIntent(context: Context): PendingIntent
    protected abstract fun getGetPendingIntent(context: Context): PendingIntent

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, androidx.credentials.exceptions.CreateCredentialException>,
    ) {
        try {
            val createEntry = CreateEntry.Builder(
                "SIROS ID Wallet",
                getCreatePendingIntent(applicationContext),
            ).setDescription("Create a passkey for SIROS ID")
                .build()

            callback.onResult(
                BeginCreateCredentialResponse.Builder()
                    .addCreateEntry(createEntry)
                    .build()
            )
        } catch (e: Exception) {
            Timber.e(e, "Error in onBeginCreateCredentialRequest")
            callback.onError(
                CreateCredentialUnknownException(e.message)
            )
        }
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, androidx.credentials.exceptions.GetCredentialException>,
    ) {
        scope.launch {
            try {
                val store = createPasskeyStore()
                val responseBuilder = BeginGetCredentialResponse.Builder()

                for (option in request.beginGetCredentialOptions) {
                    if (option is BeginGetPublicKeyCredentialOption) {
                        val rpId = extractRpId(option.requestJson)
                        val passkeys = if (rpId != null) {
                            store.getByRpId(rpId)
                        } else {
                            store.getAll()
                        }

                        for (passkey in passkeys) {
                            val entry = PublicKeyCredentialEntry.Builder(
                                applicationContext,
                                passkey.userDisplayName,
                                getGetPendingIntent(applicationContext),
                                option,
                            ).build()
                            responseBuilder.addCredentialEntry(entry)
                        }
                    }
                }

                callback.onResult(responseBuilder.build())
            } catch (e: Exception) {
                Timber.e(e, "Error in onBeginGetCredentialRequest")
                callback.onError(
                    GetCredentialUnknownException(e.message)
                )
            }
        }
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, androidx.credentials.exceptions.ClearCredentialException>,
    ) {
        scope.launch {
            try {
                createPasskeyStore().clear()
                callback.onResult(null)
            } catch (e: Exception) {
                Timber.e(e, "Error clearing credential state")
                callback.onError(
                    ClearCredentialUnknownException(e.message)
                )
            }
        }
    }

    private fun extractRpId(requestJson: String): String? {
        return try {
            val element = Json.parseToJsonElement(requestJson)
            element.jsonObject["rpId"]?.jsonPrimitive?.content
        } catch (e: Exception) {
            null
        }
    }
}
