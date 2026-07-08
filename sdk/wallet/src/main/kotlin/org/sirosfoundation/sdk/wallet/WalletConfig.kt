// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.sirosfoundation.sdk.wallet

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.OkHttpClient
import okhttp3.Request
import org.sirosfoundation.sdk.credentials.CredentialStore
import org.sirosfoundation.sdk.keystore.KeystoreManager
import timber.log.Timber

/**
 * Configuration for [SirosWallet].
 *
 * @param backendUrl The wallet backend URL (e.g. "https://wallet.sirosid.dev").
 * @param tenantId  Tenant identifier. Defaults to "default".
 * @param redirectUri OAuth redirect URI for authorization code flows. For native
 *        apps this is typically a custom-scheme URI or an app-link URL.
 * @param useSystemCredentialManager When `true`, use the system Credential Manager
 *        picker for passkeys (requires API 34+ or a compatible provider like Google
 *        Password Manager). When `false` (default), use the SDK's built-in
 *        KeyStore-backed passkey manager that works on API 28+.
 * @param credentialStore Custom [CredentialStore] implementation. When `null`
 *        (default), the SDK uses an encrypted file-backed store. Pass your own
 *        implementation if you need custom storage (e.g. Room, SQLCipher).
 * @param httpClient Custom [OkHttpClient] for all HTTP/WS communication.
 *        Use this to configure timeouts, certificate pinning, proxy settings,
 *        or logging interceptors. When `null`, a default client is created.
 * @param urlRewriter Optional function to rewrite URLs before they are opened
 *        in the browser (e.g. to map Docker-internal hostnames to external addresses).
 *        Applied to authorization URLs in [WalletEventListener.onAuthorizationRequired].
 */
data class WalletConfig(
    val backendUrl: String,
    val tenantId: String = "default",
    /** WebSocket engine URL. Defaults to backendUrl if not set (same-port deployment). */
    val engineUrl: String = "",
    val redirectUri: String = "",
    val useSystemCredentialManager: Boolean = false,
    val credentialStore: CredentialStore? = null,
    val httpClient: OkHttpClient? = null,
    val urlRewriter: ((String) -> String)? = null,
    val requireUserAuth: Boolean = true,
    val keystore: KeystoreManager? = null,
) {
    companion object {
        private val json = Json { ignoreUnknownKeys = true }

        /**
         * Discover the engine WebSocket URL from the backend's
         * `/.well-known/wallet-configuration` endpoint and return a
         * [WalletConfig] with [engineUrl] populated.
         *
         * Falls back to the provided [engineUrl] (or empty) if discovery
         * fails — the SDK will then connect the engine on the same port
         * as the backend, which works for single-port deployments.
         */
        suspend fun discover(
            backendUrl: String,
            tenantId: String = "default",
            engineUrl: String = "",
            redirectUri: String = "",
            httpClient: OkHttpClient? = null,
            requireUserAuth: Boolean = true,
            keystore: KeystoreManager? = null,
            urlRewriter: ((String) -> String)? = null,
        ): WalletConfig {
            val resolvedEngineUrl = if (engineUrl.isNotEmpty()) engineUrl
            else discoverEngineUrl(backendUrl, httpClient) ?: ""

            return WalletConfig(
                backendUrl = backendUrl,
                tenantId = tenantId,
                engineUrl = resolvedEngineUrl,
                redirectUri = redirectUri,
                httpClient = httpClient,
                requireUserAuth = requireUserAuth,
                keystore = keystore,
                urlRewriter = urlRewriter,
            )
        }

        internal suspend fun discoverEngineUrl(
            backendUrl: String,
            httpClient: OkHttpClient?,
        ): String? = withContext(Dispatchers.IO) {
            try {
                val client = httpClient ?: OkHttpClient()
                val url = backendUrl.trimEnd('/') + "/.well-known/wallet-configuration"
                val request = Request.Builder().url(url).build()
                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) return@withContext null
                    val body = response.body?.string() ?: return@withContext null
                    val obj = json.parseToJsonElement(body).jsonObject
                    val engine = obj["engine_url"]?.jsonPrimitive?.content
                    if (engine.isNullOrEmpty()) null else engine
                }
            } catch (e: Exception) {
                Timber.d("wallet-configuration discovery failed (using default): ${e.message}")
                null
            }
        }
    }
}
