package org.sirosfoundation.sdk.sample

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import uniffi.siros_wscd_manager.FfiHttpTransport
import uniffi.siros_wscd_manager.FfiPakeClient
import uniffi.siros_wscd_manager.FfiWscdException

/**
 * OkHttp-based HTTP transport for R2PS protocol messages.
 *
 * Implements the [FfiHttpTransport] callback interface so the Rust
 * R2PS client can make HTTP requests through the platform's HTTP stack.
 *
 * The R2PS transport is a simple request/response pattern: the Rust side
 * serializes a protocol message, sends it here, and expects the raw
 * server response bytes back.
 */
class OkHttpR2psTransport(
    private val serverUrl: String,
    private val client: OkHttpClient = OkHttpClient(),
) : FfiHttpTransport {

    override fun send(body: ByteArray): ByteArray {
        val mediaType = "application/octet-stream".toMediaType()
        val request = Request.Builder()
            .url(serverUrl)
            .post(body.toRequestBody(mediaType))
            .build()
        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                throw FfiWscdException.Callback(
                    "R2PS HTTP POST failed: ${response.code} ${response.message}"
                )
            }
            return response.body?.bytes() ?: ByteArray(0)
        }
    }
}

/**
 * OPAQUE PAKE client implementation.
 *
 * Implements the [FfiPakeClient] callback interface for OPAQUE (RFC 9807)
 * password-authenticated key exchange. The Rust side drives the protocol
 * by calling these methods in sequence; the implementation performs the
 * client-side OPAQUE operations.
 *
 * In a production app, this would use a platform OPAQUE library (e.g.
 * libopaque JNI bindings). For the sample app, we delegate to the R2PS
 * server's built-in test endpoints that handle both sides.
 */
class SamplePakeClient : FfiPakeClient {

    override fun registrationInit(password: ByteArray): ByteArray {
        // In production: create OPAQUE RegistrationRequest from password
        // For sample/testing: the R2PS dev server accepts raw password as init
        return password
    }

    override fun registrationFinalize(serverResp: ByteArray): ByteArray {
        // In production: process RegistrationResponse, produce RegistrationRecord
        // For sample/testing: pass through the server response
        return serverResp
    }

    override fun authInit(password: ByteArray): ByteArray {
        // In production: create OPAQUE KE1 from password
        // For sample/testing: pass raw password
        return password
    }

    override fun authFinalize(serverResp: ByteArray): ByteArray {
        // In production: process KE2, produce KE3||session_key
        // For sample/testing: pass through
        return serverResp
    }
}
