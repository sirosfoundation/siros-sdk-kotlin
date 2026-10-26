// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.openid4vp

import java.io.IOException
import java.security.SecureRandom
import java.time.Clock
import java.util.Base64
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import okhttp3.Call
import okhttp3.FormBody
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import org.siros.sdk.keystore.AuthorizationResponseEncryption

/**
 * A backend-free OpenID4VP 1.0 client for cross-device and same-device requests by reference: the wallet itself fetches
 * the signed request and posts the encrypted response, with no wallet backend in between.
 *
 * 1. [fetchRequest]: parses the `openid4vp://` URI, fetches the request object from `request_uri` (POST with
 *    `wallet_metadata` and a fresh `wallet_nonce` when the verifier asks for POST, else GET), verifies it
 *    ([RequestObjectVerifier]: ES256 by the `x5c` leaf, whose dNSName SAN is the `client_id` host), asks the
 *    [trustPolicy], and checks the request is one this client answers ([AuthorizationRequest]).
 * 2. The host shows the request, gets consent and makes the presentation (for `zkp_req`: [CircuitZkResponder]).
 * 3. [sendPresentation] or [sendError]: the response (JARM, `direct_post.jwt`) encrypted to the verifier's key with
 *    [AuthorizationResponseEncryption] and posted to `response_uri` as `response`.
 *
 * Supported: `client_id` prefix `x509_san_dns`, DCQL, `response_mode` `direct_post.jwt`, ECDH-ES on P-256 with A128GCM or
 * A256GCM. Nothing else (by-value requests, `presentation_definition`, plain `direct_post`, `transaction_data`) is answered.
 * Redirects are not followed. Nothing here logs.
 *
 * @param trustPolicy whether a verifier, once its request verified, may be answered at all.
 * @param httpClient the base client (timeouts, proxies); the client's own copy follows no redirects.
 * @param allowHttp accept `http` request and response URIs. For tests against a local server only.
 */
class OpenId4VpClient(
    private val trustPolicy: VerifierTrustPolicy,
    httpClient: OkHttpClient = OkHttpClient(),
    private val clock: Clock = Clock.systemUTC(),
    private val allowHttp: Boolean = false,
) {
    private val http: OkHttpClient = httpClient.newBuilder().followRedirects(false).followSslRedirects(false).build()
    private val random = SecureRandom()

    /**
     * Fetches, verifies and checks the request [authorizationRequestUri] names (the QR code's or the link's text).
     *
     * @param walletMetadata what the wallet supports ([WalletMetadata]); sent only when the verifier asks for POST.
     * @throws OpenId4VpException [OpenId4VpException.InvalidRequestUri], [OpenId4VpException.RequestUnavailable],
     *   [OpenId4VpException.Untrusted], [OpenId4VpException.Unsupported] or [OpenId4VpException.Network].
     */
    suspend fun fetchRequest(authorizationRequestUri: String, walletMetadata: JsonObject): AuthorizationRequest {
        val uri = AuthorizationRequestUri.parse(authorizationRequestUri)
        if (!AuthorizationRequest.isWebUrl(uri.requestUri, allowHttp)) {
            throw OpenId4VpException.InvalidRequestUri("request_uri is not an https URL")
        }
        val url = uri.requestUri.toHttpUrlOrNull() ?: throw OpenId4VpException.InvalidRequestUri("request_uri is not an https URL")
        val walletNonce = if (uri.requestUriMethod == AuthorizationRequestUri.RequestUriMethod.POST) newNonce() else null
        val builder = Request.Builder().url(url).header("Accept", "application/oauth-authz-req+jwt")
        val call = if (walletNonce != null) {
            builder.post(
                FormBody.Builder()
                    .add("wallet_metadata", walletMetadata.toString())
                    .add("wallet_nonce", walletNonce)
                    .build(),
            )
        } else {
            builder.get()
        }
        val jws = execute(http.newCall(call.build())) { response ->
            if (!response.isSuccessful) throw OpenId4VpException.RequestUnavailable(response.code, errorCode(response))
            readText(response, MAX_REQUEST_OBJECT_BYTES)
        }
        val verified = RequestObjectVerifier.verify(jws, uri.clientId, walletNonce, clock.instant())
        // Where the response would go is part of who the verifier is: the policy sees it before anything else of the request is used.
        val responseUri = (verified.payload["response_uri"] as? JsonPrimitive)?.takeIf { it.isString }?.content.orEmpty()
        if (!trustPolicy.trusts(VerifierIdentity(uri.clientId, uri.requestUri, responseUri, verified.certificateChain))) {
            throw OpenId4VpException.Untrusted(UntrustedReason.NOT_TRUSTED)
        }
        return AuthorizationRequest.from(verified, uri.clientId, uri.requestUri, allowHttp)
    }

    /**
     * Posts the presentation: [vpToken] (`{queryId: [presentation, ...]}`) and the request's `state`, encrypted to the
     * verifier's key.
     *
     * @return what the verifier answered (a `redirect_uri` for a same-device flow, when it gives one).
     * @throws OpenId4VpException.ResponseRejected or [OpenId4VpException.Network]; [IllegalArgumentException] when the
     *   response cannot be encrypted to the verifier's key.
     */
    suspend fun sendPresentation(request: AuthorizationRequest, vpToken: JsonObject): ResponseResult {
        val jwe = AuthorizationResponseEncryption.encrypt(
            vpToken = vpToken,
            audience = request.clientId,
            state = request.state,
            verifierJwk = request.responseEncryptionJwk,
            alg = request.responseEncryptionAlg,
            enc = request.responseEncryptionEnc,
            nowSeconds = clock.instant().epochSecond,
        )
        return post(request, jwe)
    }

    /**
     * Posts an error response (OpenID4VP 1.0 section 8.5), encrypted like a presentation: [ERROR_ACCESS_DENIED] when the
     * user declines or the holder's data does not meet the request, [ERROR_INVALID_REQUEST] for a request the wallet
     * cannot answer for reasons independent of the holder.
     */
    suspend fun sendError(request: AuthorizationRequest, error: String): ResponseResult {
        require(ERROR_CODE.matches(error)) { "an error code is lowercase ASCII letters and underscores" }
        val jwe = AuthorizationResponseEncryption.encryptError(
            error = error,
            audience = request.clientId,
            state = request.state,
            verifierJwk = request.responseEncryptionJwk,
            alg = request.responseEncryptionAlg,
            enc = request.responseEncryptionEnc,
            nowSeconds = clock.instant().epochSecond,
        )
        return post(request, jwe)
    }

    private suspend fun post(request: AuthorizationRequest, jwe: String): ResponseResult {
        val url = request.responseUri.toHttpUrlOrNull() ?: throw OpenId4VpException.Unsupported("response_uri is not an https URL")
        val call = http.newCall(Request.Builder().url(url).post(FormBody.Builder().add("response", jwe).build()).build())
        return execute(call) { response ->
            if (!response.isSuccessful) throw OpenId4VpException.ResponseRejected(response.code, errorCode(response))
            val body = runCatching { readText(response, MAX_RESPONSE_BODY_BYTES) }.getOrNull()
            ResponseResult(redirectUri = body?.let { jsonString(it, "redirect_uri") })
        }
    }

    /** What the verifier answered a response with. */
    class ResponseResult(
        /** Where to send the user next (OpenID4VP 1.0 section 8.2), for a same-device flow; null when the verifier gave none. */
        val redirectUri: String?,
    ) {
        override fun toString() = "ResponseResult(redirect=${redirectUri != null})"
    }

    private fun newNonce(): String = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(16).also { random.nextBytes(it) })

    /** Runs [call] off the caller's dispatcher, cancelling it when the caller is cancelled. */
    private suspend fun <T> execute(call: Call, block: (Response) -> T): T = withContext(Dispatchers.IO) {
        val job = coroutineContext[Job]
        val handle = job?.invokeOnCompletion { if (it != null) call.cancel() }
        try {
            call.execute().use(block)
        } catch (e: IOException) {
            if (job?.isCancelled == true) throw CancellationException("cancelled")
            throw OpenId4VpException.Network(e)
        } finally {
            handle?.dispose()
        }
    }

    private fun readText(response: Response, limit: Long): String {
        val body = response.body ?: return ""
        val source = body.source()
        if (!source.request(limit + 1)) return source.readUtf8()
        throw OpenId4VpException.Network(IOException("the answer is larger than $limit bytes"))
    }

    /** The verifier's error code: OAuth's `{"error": …}` or community-demo's `{"data": {"error": …}}`, when it is a plain code. */
    private fun errorCode(response: Response): String? {
        val text = runCatching { readText(response, MAX_RESPONSE_BODY_BYTES) }.getOrNull() ?: return null
        val code = jsonString(text, "error") ?: jsonString(text, "data", "error")
        return code?.takeIf { ERROR_CODE.matches(it) && it.length <= 64 }
    }

    private fun jsonString(text: String, vararg path: String): String? {
        var e: JsonElement = runCatching { Json.parseToJsonElement(text) }.getOrNull() ?: return null
        for (name in path) e = (e as? JsonObject)?.get(name) ?: return null
        return (e as? JsonPrimitive)?.takeIf { it.isString }?.content
    }

    companion object {
        /** The user declined, or the holder's data does not meet the request. */
        const val ERROR_ACCESS_DENIED = "access_denied"

        /** The request cannot be answered for reasons independent of the holder's data. */
        const val ERROR_INVALID_REQUEST = "invalid_request"

        private val ERROR_CODE = Regex("^[a-z_]+$")
        private const val MAX_REQUEST_OBJECT_BYTES = 256L * 1024
        private const val MAX_RESPONSE_BODY_BYTES = 64L * 1024
    }
}
