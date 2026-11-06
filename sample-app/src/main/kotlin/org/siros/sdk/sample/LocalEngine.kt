// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.toRequestBody
import uniffi.engine_adapter_sdk.FetchPurpose
import uniffi.engine_adapter_sdk.HeaderPair
import uniffi.engine_adapter_sdk.HttpRequest
import uniffi.engine_adapter_sdk.HttpResponse
import uniffi.engine_adapter_sdk.RedirectPolicy
import uniffi.engine_adapter_sdk.SdkException

/**
 * The LOCAL engine mode's HTTP port: the engine's outgoing fetches over OkHttp -
 * the same client the app already uses for everything else (native TLS, system
 * roots, VPNs).
 *
 * The engine's other ports are the SDK's own now: the wallet's asks (the signs,
 * the consent, the match, the tx code, the authorization hand-over) are answered
 * by `WalletEngineAskHandler` inside the SDK and carried by
 * `UniFfiEngineAskHost`, exactly as the remote engine's child flows carry them -
 * see WalletViewModel's `wmpTransport` factory. The first-cut
 * `KeystoreEngineHost` (which fail-closed every ask but the named-key sign) is
 * gone with that.
 *
 * The trust ([uniffi.engine_adapter_sdk.Pdp]) is deliberately absent (null): the
 * local engine fails closed at the trust step until the app wires a trust stack,
 * exactly as the remote engine does unconfigured - the local mode is not a
 * permissive mode.
 */

/** The engine's HTTP port over OkHttp - every fetch the engine makes. */
class OkHttpEngineHttp(
    private val client: OkHttpClient = OkHttpClient.Builder().build(),
) : uniffi.engine_adapter_sdk.HttpClient {

    override suspend fun send(request: HttpRequest): HttpResponse = withContext(Dispatchers.IO) {
        val contentType = request.headers
            .firstOrNull { it.name.equals("content-type", ignoreCase = true) }
            ?.value
            ?.toMediaTypeOrNull()
        val body = request.body.takeIf { it.isNotEmpty() }?.toRequestBody(contentType)
        val builder = Request.Builder()
            .url(request.url)
            .method(request.method, body)
        for (header in request.headers) {
            builder.header(header.name, header.value)
        }
        // Redirects: the engine declares its policy; OkHttp follows them or
        // not (the engine's fetches are none-following by policy).
        val followed = client.newBuilder()
            .followRedirects(request.redirects != RedirectPolicy.None)
            .build()
        followed.newCall(builder.build()).execute().use { executed ->
            // Bound the body exactly as the engine declared: refuse the
            // response if it exceeded the limit (the engine's own port
            // rule, applied on the app's side of the adapter).
            val bytes = executed.body?.bytes() ?: ByteArray(0)
            if (bytes.size.toULong() > request.maxResponseBytes) {
                throw SdkException.Transport("response exceeded the engine's declared limit")
            }
            HttpResponse(
                status = executed.code.toUShort(),
                body = bytes,
            )
        }
    }
}
