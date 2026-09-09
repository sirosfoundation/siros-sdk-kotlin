package org.siros.sdk.keystore

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * OkHttp-based HTTP transport for R2PS protocol messages - the transport a
 * host app uses unless it has a reason to route R2PS traffic through its
 * own HTTP stack (pinning, proxying, instrumentation). Lived in the sample
 * app until every integrator would have had to copy it; the Swift SDK's
 * `URLSessionR2psTransport` is the counterpart.
 *
 * Implements [R2psTransportProvider] so the Rust R2PS client
 * can make HTTP requests through the platform's HTTP stack. Real OPAQUE
 * (RFC 9807) PAKE crypto is handled entirely in Rust (`r2ps-client`) -
 * this transport only ever moves opaque request/response bytes, same as
 * any other R2PS protocol message.
 *
 * The R2PS transport is a simple request/response pattern: the Rust side
 * serializes a protocol message, sends it here, and expects the raw
 * server response bytes back.
 */
class OkHttpR2psTransport(
    private val serverUrl: String,
    private val client: OkHttpClient = OkHttpClient(),
) : R2psTransportProvider {

    override suspend fun send(body: ByteArray): ByteArray = withContext(Dispatchers.IO) {
        val mediaType = "application/octet-stream".toMediaType()
        val request = Request.Builder()
            .url(serverUrl)
            .post(body.toRequestBody(mediaType))
            .build()
        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                throw java.io.IOException("R2PS HTTP POST failed: ${response.code} ${response.message}")
            }
            response.body?.bytes() ?: ByteArray(0)
        }
    }
}
