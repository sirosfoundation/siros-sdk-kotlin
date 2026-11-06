// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.toRequestBody
import org.siros.sdk.keystore.KeystoreManager
import uniffi.engine_adapter_sdk.AttestationParams
import uniffi.engine_adapter_sdk.AttestationResult
import uniffi.engine_adapter_sdk.ConsentParams
import uniffi.engine_adapter_sdk.ConsentResult
import uniffi.engine_adapter_sdk.CredentialSelectionParams
import uniffi.engine_adapter_sdk.CredentialSelectionResult
import uniffi.engine_adapter_sdk.DpopProofParams
import uniffi.engine_adapter_sdk.DpopProofResult
import uniffi.engine_adapter_sdk.FetchPurpose
import uniffi.engine_adapter_sdk.HeaderPair
import uniffi.engine_adapter_sdk.Host
import uniffi.engine_adapter_sdk.HttpClient
import uniffi.engine_adapter_sdk.HttpRequest
import uniffi.engine_adapter_sdk.HttpResponse
import uniffi.engine_adapter_sdk.MatchParams
import uniffi.engine_adapter_sdk.MatchResult
import uniffi.engine_adapter_sdk.RedirectPolicy
import uniffi.engine_adapter_sdk.SdkException
import uniffi.engine_adapter_sdk.SignParams
import uniffi.engine_adapter_sdk.SignResult
import uniffi.engine_adapter_sdk.SigningKeyParams
import uniffi.engine_adapter_sdk.SigningKeyResult
import uniffi.engine_adapter_sdk.VpParams
import uniffi.engine_adapter_sdk.VpResult

/**
 * The LOCAL engine mode's ports: the sample app's adapters over the engine's
 * UniFFI callbacks (`WmpUniFFITransport`'s constructor takes these).
 *
 * - [OkHttpEngineHttp]: the engine's outgoing fetches over OkHttp - the same
 *   client the app already uses for everything else (native TLS, system
 *   roots, VPNs).
 * - [KeystoreEngineHost]: the engine's wallet asks. FIRST CUT: `requestSign`
 *   delegates to the app's [KeystoreManager] when the ask names its key (a
 *   proof over raw bytes - the keystore's own signature), and every other
 *   ask fails closed with a clear reason ([SdkException.Cannot]). The
 *   remaining asks (the unnamed-key proof, the credential selection, the
 *   presentation match, the consents) ride the app's UI flows and land in
 *   the follow-up: until then, a local-mode flow that needs one refuses
 *   rather than silently skipping it - the engine's own default behavior
 *   for an ask the host cannot answer.
 *
 * The trust ([uniffi.engine_adapter_sdk.Pdp]) is deliberately absent
 * (null): the local engine fails closed at the trust step until the app
 * wires a trust stack, exactly as the remote engine does unconfigured -
 * the local mode is not a permissive mode.
 */

/** The engine's HTTP port over OkHttp - every fetch the engine makes. */
class OkHttpEngineHttp(
    private val client: OkHttpClient = OkHttpClient.Builder().build(),
) : HttpClient {

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

/** The engine's wallet-ask port over the app's keystore - the first cut. */
class KeystoreEngineHost(
    private val keystore: KeystoreManager?,
) : Host {

    override suspend fun requestSign(params: SignParams): SignResult {
        val keystore = keystore
            ?: throw SdkException.Cannot("no keystore wired to the local engine")
        val keyId = params.keyId
            ?: throw SdkException.Cannot(
                "the local engine's unnamed-key proof is not bridged yet - the engine signs without a kid header",
            )
        return SignResult(
            keystore.sign(
                keyId = keyId,
                payload = params.toSign,
                algorithm = params.algorithm.ifEmpty { "ES256" },
            ),
        )
    }

    override suspend fun requestMatch(params: MatchParams): MatchResult =
        throw SdkException.Cannot(
            "the local engine's credential match is not bridged yet - use the remote engine mode",
        )

    override suspend fun requestVp(params: VpParams): VpResult =
        throw SdkException.Cannot(
            "the local engine's presentation ask is not bridged yet - use the remote engine mode",
        )

    override suspend fun requestDpopProof(params: DpopProofParams): DpopProofResult =
        throw SdkException.Cannot(
            "the local engine's client-held DPoP is not bridged yet - the engine falls back to its own key",
        )

    override suspend fun requestConsent(params: ConsentParams): ConsentResult =
        throw SdkException.Cannot(
            "the local engine's consent ask is not bridged yet - use the remote engine mode",
        )

    override suspend fun requestTxCode(flowId: String): String =
        throw SdkException.Cannot(
            "the local engine's transaction-code ask is not bridged yet - use the remote engine mode",
        )

    override suspend fun openAuthorization(flowId: String, url: String) {
        throw SdkException.Cannot(
            "the local engine's authorization navigation is not bridged yet - use the remote engine mode",
        )
    }

    override suspend fun requestSigningKey(params: SigningKeyParams): SigningKeyResult =
        throw SdkException.Cannot(
            "the local engine's named-key ask is not bridged yet - the proofs sign without a kid",
        )

    override suspend fun requestAttestation(params: AttestationParams): AttestationResult =
        // No client attestation in the sample app: the flow proceeds without
        // it (the engine's own rule for a host that cannot answer).
        throw SdkException.Cannot("no Wallet Instance Attestation in the sample app")

    override suspend fun requestCredentialSelection(
        params: CredentialSelectionParams,
    ): CredentialSelectionResult =
        throw SdkException.Cannot(
            "the local engine's credential selection is not bridged yet - a single-configuration offer never asks",
        )

    override fun progress(flowId: String, step: String, detail: String?) {
        // The sample app surfaces the engine's flow progress through its
        // own WMP layer in the remote modes; the local transport's
        // takeNotifications carries the same messages. Nothing here.
    }
}