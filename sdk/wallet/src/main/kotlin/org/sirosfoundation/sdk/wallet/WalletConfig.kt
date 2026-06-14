// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.sirosfoundation.sdk.wallet

import okhttp3.OkHttpClient
import org.sirosfoundation.sdk.credentials.CredentialStore

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
)
