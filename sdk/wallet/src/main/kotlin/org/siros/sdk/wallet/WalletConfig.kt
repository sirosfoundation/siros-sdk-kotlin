// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.OkHttpClient
import org.siros.sdk.credentials.CredentialStore
import org.siros.sdk.keystore.KeystoreManager
import org.siros.sdk.keystore.NativeAttestationProvider

/**
 * Configuration for [SirosWallet].
 *
 * @param backendUrl The wallet backend URL (e.g. "https://wallet.sirosid.dev").
 * @param tenantId  Tenant identifier. Defaults to "default".
 * @param redirectUri OAuth redirect URI for authorization code flows. For native
 *        apps this is typically a custom-scheme URI or an app-link URL.
 * @param useSystemCredentialManager When `true` (default), use the system Credential
 *        Manager picker for passkeys — this is required for roaming authenticator
 *        support (hybrid/phone-as-authenticator, USB/NFC/BLE security keys) and
 *        handles biometric/device-credential authorization itself. Set to `false`
 *        to use the SDK's built-in KeyStore-backed passkey manager instead (local
 *        platform authenticator only, no roaming support) — mainly useful as a
 *        fallback on emulators/environments without a working Credential Manager
 *        provider.
 * @param credentialStore Custom [CredentialStore] implementation. When `null`
 *        (default), the SDK uses an encrypted file-backed store. Pass your own
 *        implementation if you need custom storage (e.g. Room, SQLCipher).
 * @param httpClient Custom [OkHttpClient] for all HTTP/WS communication.
 *        Use this to configure timeouts, certificate pinning, proxy settings,
 *        or logging interceptors. When `null`, a default client is created.
 * @param urlRewriter Optional function to rewrite URLs before they are opened
 *        in the browser (e.g. to map Docker-internal hostnames to external addresses).
 *        Applied to authorization URLs in [WalletEventListener.onAuthorizationRequired].
 * @param nativeAttestationProvider Optional platform attestation provider (e.g.
 *        [org.siros.sdk.keystore.PlayIntegrityProvider]) used to attach real device
 *        attestation evidence to Wallet Instance Attestation requests, so the backend's
 *        Key Attestation trust gate can lift its software-key clamp for genuinely
 *        Tier-1-attested instances. `SirosWallet` has no `Context` of its own (this
 *        is a plain Kotlin class, not Android-aware), so - unlike [keystore] - this
 *        can't be lazily constructed internally from a bare config value: the host
 *        app must construct it (it has the `Context`/`Activity` a provider like
 *        `PlayIntegrityProvider` needs) and inject the ready instance here. `null`
 *        (default) omits `native_attestation` entirely, matching today's behavior.
 */
data class WalletConfig(
    val backendUrl: String,
    val tenantId: String = "default",
    val redirectUri: String = "",
    val useSystemCredentialManager: Boolean = true,
    val credentialStore: CredentialStore? = null,
    val httpClient: OkHttpClient? = null,
    val urlRewriter: ((String) -> String)? = null,
    val requireUserAuth: Boolean = true,
    val keystore: KeystoreManager? = null,
    val nativeAttestationProvider: NativeAttestationProvider? = null,
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

/** See [SirosWallet.capabilities]. */
data class WalletCapabilities(
    val nativeAttestation: Boolean,
    val wscd: Boolean,
)
