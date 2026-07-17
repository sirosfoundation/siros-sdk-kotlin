// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.OkHttpClient
import org.siros.sdk.credentials.CredentialStore
import org.siros.sdk.keystore.KeystoreManager

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
    val redirectUri: String = "",
    val useSystemCredentialManager: Boolean = false,
    val credentialStore: CredentialStore? = null,
    val httpClient: OkHttpClient? = null,
    val urlRewriter: ((String) -> String)? = null,
    val requireUserAuth: Boolean = true,
    val keystore: KeystoreManager? = null,
    /** Engine WebSocket URL. Defaults to backendUrl with port replaced by 8082. */
    val engineUrl: String? = null,
    /**
     * Use the WMP (Wallet Messaging Protocol) JSON-RPC 2.0 transport instead
     * of the legacy engine protocol. Requires go-wallet-backend with WMP support.
     */
    val useWmpProtocol: Boolean = false,
) {
    companion object {
        private val json = kotlinx.serialization.json.Json { ignoreUnknownKeys = true }

        /**
         * Discover the engine base URL from the backend's
         * `/.well-known/wallet-configuration` endpoint.
         *
         * Returns `null` if discovery fails — the caller should fall back
         * to [backendUrl] (single-port deployment).
         */
        suspend fun discoverEngineUrl(backendUrl: String): String? {
            val url = backendUrl.trimEnd('/') + "/.well-known/wallet-configuration"
            return try {
                val client = okhttp3.OkHttpClient.Builder()
                    .connectTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
                    .readTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
                    .build()
                val request = okhttp3.Request.Builder().url(url).build()
                val response = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                    client.newCall(request).execute()
                }
                response.use { resp ->
                    if (!resp.isSuccessful) return@use null
                    val body = resp.body?.string() ?: return@use null
                    val parsed = json.parseToJsonElement(body).jsonObject
                    val engineUrl = parsed["engine_url"]?.jsonPrimitive?.contentOrNull
                    if (engineUrl.isNullOrBlank()) null else engineUrl
                }
            } catch (_: Exception) {
                null
            }
        }
    }
}
