// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample.dcapi

import android.content.Context
import androidx.credentials.registry.digitalcredentials.openid4vp.OpenId4VpRegistry
import androidx.credentials.registry.provider.ClearCredentialRegistryRequest
import androidx.credentials.registry.provider.RegistryManager
import org.siros.sdk.sample.BuildConfig
import org.siros.sdk.credentials.StoredCredential
import timber.log.Timber

/**
 * Registers the wallet's stored credentials with the OS's Digital
 * Credentials API picker via [RegistryManager], so a browser page's
 * `navigator.credentials.get({digital: {...}})` call can surface this app
 * without it needing to already be in the foreground.
 *
 * Call [refresh] whenever the credential set materially changes (login,
 * logout, credential added/deleted) - the registration is a full snapshot
 * replace, not an incremental update.
 */
object DCAPIProviderRegistration {
    /** Matches the intentAction [org.siros.sdk.sample.dcapi.DCAPIGetCredentialActivity]'s manifest intent-filter declares. */
    const val REGISTRY_ID = "org.siros.sdk.sample.dcapi.registry"

    suspend fun refresh(context: Context, credentials: List<StoredCredential>) {
        if (credentials.isEmpty()) {
            clear(context)
            return
        }
        try {
            val entries = DCAPICredentialEntryBuilder.buildEntries(credentials)
            if (entries.isEmpty()) {
                clear(context)
                return
            }
            if (BuildConfig.CUSTOM_DC_MATCHER) {
                // Our own matcher, so formats the stock one refuses - notably
                // mso_mdoc_zk - can produce a picker entry at all. See
                // SirosMatcherRegistry.
                RegistryManager.create(context)
                    .registerCredentials(SirosMatcherRegistry.create(context, credentials))
                Timber.d("DC API registry updated via siros-dc-matcher (${credentials.size} credentials)")
                return
            }
            val registry = OpenId4VpRegistry(
                credentialEntries = entries,
                id = REGISTRY_ID,
                // Explicit (added in 1.0.0-alpha05) rather than relying on
                // whatever the library defaults to when omitted - this
                // wallet's DCAPIRequestParser genuinely supports all three.
                supportedProtocols = listOf(
                    OpenId4VpRegistry.PROTOCOL_OPENID4VP_1_0_SIGNED,
                    OpenId4VpRegistry.PROTOCOL_OPENID4VP_1_0_MULTISIGNED,
                    OpenId4VpRegistry.PROTOCOL_OPENID4VP_1_0_UNSIGNED,
                ),
            )
            RegistryManager.create(context).registerCredentials(registry)
            Timber.d("DC API registry updated with ${entries.size} entries")
        } catch (e: Exception) {
            // Registration failing must never break the rest of the app
            // (e.g. a device/OS without DC API support at all) - it only
            // means this credential won't be offered via the browser API.
            Timber.w(e, "Failed to register DC API credentials")
        }
    }

    suspend fun clear(context: Context) {
        try {
            RegistryManager.create(context).clearCredentialRegistry(ClearCredentialRegistryRequest(true))
        } catch (e: Exception) {
            Timber.w(e, "Failed to clear DC API credential registry")
        }
    }
}
