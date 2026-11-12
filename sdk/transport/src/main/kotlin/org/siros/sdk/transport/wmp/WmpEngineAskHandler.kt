// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

package org.siros.sdk.transport.wmp

import kotlinx.serialization.json.JsonObject
import org.siros.sdk.transport.wmp.openid4x.EngineAttestationParams
import org.siros.sdk.transport.wmp.openid4x.EngineAttestationResult
import org.siros.sdk.transport.wmp.openid4x.EngineAvailableCredential
import org.siros.sdk.transport.wmp.openid4x.EngineConsentParams
import org.siros.sdk.transport.wmp.openid4x.EngineDpopProofParams
import org.siros.sdk.transport.wmp.openid4x.EngineDpopProofResult
import org.siros.sdk.transport.wmp.openid4x.EngineSignParams
import org.siros.sdk.transport.wmp.openid4x.EngineSigningKeyResult
import org.siros.sdk.transport.wmp.openid4x.EngineVpParams
import org.siros.sdk.transport.wmp.openid4x.EngineVpResult
import org.siros.sdk.transport.wmp.openid4x.MatchResult

/**
 * The SDK-level port for the LOCAL engine's asks - the one seam the wallet's
 * handlers plug into for the in-process engine (docs/engine-switching.md: "the
 * SDK's `Host` is the native UI").
 *
 * The ask VOCABULARY is the engine's own (engine-ports' `Host`), the same one
 * the REMOTE engine bridges onto the wire as typed child flows - so a wallet
 * implements its asks ONCE:
 *
 * - remote (HTTP_SSE): the asks arrive as `wmp.flow.start` children and are
 *   answered through the [org.siros.sdk.transport.wmp.openid4x.OpenID4xProfile]
 *   callbacks;
 * - local (LOCAL): the asks arrive through this port - the app hands the
 *   engine a [uniffi.engine_adapter_sdk.Host] built from it
 *   ([UniFfiEngineAskHost]) when it constructs [WmpUniFFITransport].
 *
 * The carrier differs; the handlers behind it are the same wallet code.
 *
 * A null/absent answer is the same "unavailable" the engine defines per ask
 * (no key, no DPoP proof, no attestation); [requestCredentialSelection]'s
 * null is the engine-ports default REFUSAL. A thrown exception is a generic
 * refusal (the flow fails closed) - exactly what a `wmp.flow.error` on a
 * remote ask means.
 */
interface WmpEngineAskHandler {

    /** The bare `sign` ask: sign the raw bytes with the named key (null = the wallet's default proof key). */
    suspend fun requestSign(flowId: String, toSign: ByteArray, keyId: String?, algorithm: String): ByteArray

    /** The `signing_key` ask: the named key's public JWK, or null for "no such key". */
    suspend fun requestSigningKey(flowId: String, keyId: String?): EngineSigningKeyResult

    /**
     * The `match` ask: the wallet's DCQL match. The payload is the profile-shaped
     * object (the `dcql_query` member among others) so one matcher serves both carriers.
     */
    suspend fun requestMatch(flowId: String, params: JsonObject?): MatchResult

    /** The `consent` ask: the user's YES/NO. `false` is the decline path, never an error. */
    suspend fun requestConsent(flowId: String, params: EngineConsentParams): Boolean

    /** The `tx_code` ask: the transaction code the user entered. */
    suspend fun requestTxCode(flowId: String): String

    /** The `authorization` ask: hand the user to the URL (open the browser). */
    suspend fun openAuthorization(flowId: String, url: String)

    /** The `presentation` ask: build and sign the VP token, or answer the structured refusal. */
    suspend fun requestVp(flowId: String, params: EngineVpParams): EngineVpResult

    /** The `dpop_proof` ask: the client-held DPoP proof, or null for "unavailable" (the engine falls back). */
    suspend fun requestDpopProof(flowId: String, params: EngineDpopProofParams): EngineDpopProofResult

    /** The `attestation` ask: the WIA + PoP pair, or nulls for "no attestation". */
    suspend fun requestAttestation(flowId: String, params: EngineAttestationParams): EngineAttestationResult

    /**
     * The credential-selection ask: the configuration id the user chose, or null to
     * refuse (the engine-ports default: the flow fails closed rather than guessing).
     */
    suspend fun requestCredentialSelection(flowId: String, available: List<EngineAvailableCredential>): String? = null

    /**
     * The engine's progress relay (the local carrier has no SSE stream for the wallet's
     * own UI - the Host port is the only channel). Non-suspending: the engine calls it
     * synchronously and expects nothing back.
     */
    fun onProgress(flowId: String, step: String, detail: String?) {}
}

/**
 * [uniffi.engine_adapter_sdk.Host] over a [WmpEngineAskHandler]: the class the
 * app hands `WmpUniFFITransport` in LOCAL mode, so the wallet's ask handlers
 * answer the in-process engine exactly as they answer the remote one.
 */
class UniFfiEngineAskHost(
    private val handler: WmpEngineAskHandler,
) : uniffi.engine_adapter_sdk.Host {

    private val json = kotlinx.serialization.json.Json { ignoreUnknownKeys = true }

    override suspend fun requestSign(params: uniffi.engine_adapter_sdk.SignParams): uniffi.engine_adapter_sdk.SignResult =
        uniffi.engine_adapter_sdk.SignResult(
            signature = handler.requestSign(params.flowId, params.toSign, params.keyId, params.algorithm),
        )

    override suspend fun requestMatch(params: uniffi.engine_adapter_sdk.MatchParams): uniffi.engine_adapter_sdk.MatchResult {
        // The profile-shaped payload: the wallet's one matcher reads `dcql_query`
        // (and the verifier members, informational) whatever the carrier.
        val payload = kotlinx.serialization.json.buildJsonObject {
            params.dcqlQuery?.let { raw ->
                put(
                    "dcql_query",
                    try {
                        json.parseToJsonElement(raw)
                    } catch (e: Exception) {
                        // A query the wallet cannot read is one it cannot match:
                        // an explicit null (the "offer every credential" branch),
                        // never a crash on the engine's callback thread.
                        kotlinx.serialization.json.JsonNull
                    },
                )
            }
            put("scope", kotlinx.serialization.json.JsonPrimitive(params.scope))
            put(
                "verifier",
                kotlinx.serialization.json.buildJsonObject {
                    put("name", kotlinx.serialization.json.JsonPrimitive(params.verifier.name))
                    put("client_id", kotlinx.serialization.json.JsonPrimitive(params.verifier.clientId))
                    put("trusted", kotlinx.serialization.json.JsonPrimitive(params.verifier.trusted))
                    // The DOMAIN extracted from the client_id (the engine's
                    // VerifierInfo.domain): a consent UI's human-facing label
                    // when the metadata carried no client_name - the raw
                    // x509_hash/did identifier belongs in a details view, not
                    // the title sentence (found on-device: the dialog read
                    // "x509_hash:… is asking you to share").
                    if (params.verifier.domain.isNotBlank()) {
                        put("domain", kotlinx.serialization.json.JsonPrimitive(params.verifier.domain))
                    }
                    params.verifier.framework.takeIf { it.isNotBlank() }
                        ?.let { put("framework", kotlinx.serialization.json.JsonPrimitive(it)) }
                    params.verifier.reason.takeIf { it.isNotBlank() }
                        ?.let { put("reason", kotlinx.serialization.json.JsonPrimitive(it)) }
                },
            )
            put(
                "transaction_data",
                kotlinx.serialization.json.buildJsonArray {
                    params.transactionData.forEach { add(kotlinx.serialization.json.JsonPrimitive(it)) }
                },
            )
        }
        val result = handler.requestMatch(params.flowId, payload)
        return uniffi.engine_adapter_sdk.MatchResult(
            selections = result.matches.map { m ->
                uniffi.engine_adapter_sdk.VpSelection(
                    credentialQueryId = m.credentialQueryId ?: "",
                    credentialId = m.credentialId,
                    disclosedClaims = m.disclosedClaims ?: emptyList(),
                )
            },
            handle = null,
        )
    }

    override suspend fun requestVp(params: uniffi.engine_adapter_sdk.VpParams): uniffi.engine_adapter_sdk.VpResult {
        val result = handler.requestVp(
            params.flowId,
            org.siros.sdk.transport.wmp.openid4x.EngineVpParams(
                flowId = params.flowId,
                audience = params.audience,
                nonce = params.nonce,
                selections = params.selections.map {
                    org.siros.sdk.transport.wmp.openid4x.EngineVpSelection(
                        credentialQueryId = it.credentialQueryId,
                        credentialId = it.credentialId,
                        disclosedClaims = it.disclosedClaims,
                    )
                },
                responseUri = params.responseUri,
                verifierJwkThumbprint = params.verifierJwkThumbprint,
                verifierSessionId = params.verifierSessionId,
                transactionData = params.transactionData,
                selectionHandle = params.selectionHandle,
            ),
        )
        return uniffi.engine_adapter_sdk.VpResult(
            vpToken = result.vpToken ?: "",
            refusal = result.refusalCode?.let {
                uniffi.engine_adapter_sdk.SignRefusal(code = it)
            },
        )
    }

    override suspend fun requestDpopProof(params: uniffi.engine_adapter_sdk.DpopProofParams): uniffi.engine_adapter_sdk.DpopProofResult =
        uniffi.engine_adapter_sdk.DpopProofResult(
            proof = handler.requestDpopProof(
                params.flowId,
                org.siros.sdk.transport.wmp.openid4x.EngineDpopProofParams(
                    flowId = params.flowId,
                    keyId = params.keyId,
                    htm = params.htm,
                    htu = params.htu,
                    accessToken = params.accessToken,
                    nonce = params.nonce,
                ),
            ).proof ?: "",
        )

    override suspend fun requestConsent(params: uniffi.engine_adapter_sdk.ConsentParams): uniffi.engine_adapter_sdk.ConsentResult =
        uniffi.engine_adapter_sdk.ConsentResult(
            consented = handler.requestConsent(
                params.flowId,
                org.siros.sdk.transport.wmp.openid4x.EngineConsentParams(
                    flowId = params.flowId,
                    purpose = params.purpose,
                    requestedClaims = params.requestedClaims,
                    transactionData = params.transactionData,
                ),
            ),
        )

    override suspend fun requestTxCode(flowId: String): String = handler.requestTxCode(flowId)

    override suspend fun openAuthorization(flowId: String, url: String) = handler.openAuthorization(flowId, url)

    override suspend fun requestSigningKey(params: uniffi.engine_adapter_sdk.SigningKeyParams): uniffi.engine_adapter_sdk.SigningKeyResult =
        uniffi.engine_adapter_sdk.SigningKeyResult(
            jwk = handler.requestSigningKey(params.flowId, params.keyId)?.jwk?.toString()
                // The JWK travels as a JSON string over UniFFI; "no key" is the empty string.
                ?: "",
        )

    override suspend fun requestAttestation(params: uniffi.engine_adapter_sdk.AttestationParams): uniffi.engine_adapter_sdk.AttestationResult {
        val result = handler.requestAttestation(
            params.flowId,
            org.siros.sdk.transport.wmp.openid4x.EngineAttestationParams(
                flowId = params.flowId,
                audience = params.audience,
                clientId = params.clientId,
                challenge = params.challenge,
            ),
        )
        return uniffi.engine_adapter_sdk.AttestationResult(
            wia = result.wia ?: "",
            pop = result.pop ?: "",
        )
    }

    override suspend fun requestCredentialSelection(
        params: uniffi.engine_adapter_sdk.CredentialSelectionParams,
    ): uniffi.engine_adapter_sdk.CredentialSelectionResult {
        val chosen = handler.requestCredentialSelection(
            params.flowId,
            params.available.map {
                org.siros.sdk.transport.wmp.openid4x.EngineAvailableCredential(
                    id = it.id,
                    display = it.display,
                    format = it.format,
                    vct = it.vct,
                )
            },
        ) ?: throw uniffi.engine_adapter_sdk.SdkException.Cannot("credential selection is not supported by this wallet")
        return uniffi.engine_adapter_sdk.CredentialSelectionResult(credentialConfigurationId = chosen)
    }

    override fun progress(flowId: String, step: String, detail: String?) = handler.onProgress(flowId, step, detail)
}
