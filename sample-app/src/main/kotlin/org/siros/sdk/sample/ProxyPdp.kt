// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

package org.siros.sdk.sample

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import uniffi.engine_adapter_sdk.EvaluationRequest
import uniffi.engine_adapter_sdk.EvaluationResponse
import uniffi.engine_adapter_sdk.Pdp
import uniffi.engine_adapter_sdk.ResolveRequest
import uniffi.engine_adapter_sdk.ResolveResponse

/**
 * The LOCAL engine's trust stack: the backend proxy's PDP routes
 * (`/v1/evaluate`, `/v1/resolve`) - the same routes the REMOTE engine's
 * deployment trusts through server-side (its `ENGINE_PDP_URL`). The local
 * engine evaluates in-process, so its trust crosses this port: the sample
 * app's own answer to the question "is this issuer/verifier trusted".
 *
 * The routes are TAC-gated: a `wallet-backend`-audience bearer with `tac`
 * covering `r` passes - exactly the wallet's own backend token, carried by
 * [bearerProvider] (a fresh mint per call, the wallet's cached-until-expired
 * manager behind it).
 *
 * The wire shape mirrors siros-wallet-core's server adapter
 * (`engine-adapter-server/ports.rs`): subject `{type: "key", id}`,
 * resource `{type: jwk|x5c|kid, id, key}`, action `{name: credential-issuer
 * | credential-verifier}` - the backend proxy's allowed set. Fail closed: a
 * route error or an unparseable answer is a refusal, never a permit.
 */
class ProxyPdp(
    private val client: OkHttpClient,
    private val baseUrl: String,
    private val bearerProvider: suspend () -> String?,
) : Pdp {

    override suspend fun evaluate(request: EvaluationRequest): EvaluationResponse =
        withContext(Dispatchers.IO) {
            val bearer = bearerProvider() ?: return@withContext EvaluationResponse(
                trusted = false,
                decision = "no bearer for the PDP routes",
            )
            val body = kotlinx.serialization.json.buildJsonObject {
                put("subject", kotlinx.serialization.json.buildJsonObject {
                    put("type", kotlinx.serialization.json.JsonPrimitive("key"))
                    put("id", kotlinx.serialization.json.JsonPrimitive(request.subject))
                })
                put("resource", kotlinx.serialization.json.buildJsonObject {
                    put("type", kotlinx.serialization.json.JsonPrimitive(keyMaterialType(request.keyMaterial)))
                    put("id", kotlinx.serialization.json.JsonPrimitive(request.subject))
                    put("key", keyMaterialValue(request.keyMaterial))
                })
                put("action", kotlinx.serialization.json.buildJsonObject {
                    put(
                        "name",
                        kotlinx.serialization.json.JsonPrimitive(
                            request.resourceType ?: "credential-issuer",
                        ),
                    )
                })
                // The evaluation's context as the engine serialized it
                // (raw JSON text; an empty string is the empty context).
                if (request.context.isNotBlank()) {
                    put(
                        "context",
                        runCatching {
                            kotlinx.serialization.json.Json.parseToJsonElement(request.context)
                        }.getOrNull() ?: return@buildJsonObject,
                    )
                }
            }.toString()
            val response = client.newCall(
                Request.Builder()
                    .url("${baseUrl.trimEnd('/')}/v1/evaluate")
                    .header("Authorization", "Bearer $bearer")
                    .post(body.toRequestBody("application/json".toMediaType()))
                    .build(),
            ).execute()
            val answer = runCatching {
                response.use { resp ->
                    check(resp.isSuccessful) { "evaluate answered ${resp.code}" }
                    resp.body?.string()
                }
            }.getOrNull() ?: return@withContext EvaluationResponse(
                trusted = false,
                decision = "the PDP route did not answer",
            )
            val parsed = runCatching {
                kotlinx.serialization.json.Json.parseToJsonElement(answer).jsonObject
            }.getOrNull() ?: return@withContext EvaluationResponse(trusted = false, decision = "an unparseable PDP answer")
            EvaluationResponse(
                trusted = parsed["decision"]?.jsonPrimitive?.booleanOrNull ?: false,
                decision = parsed["context"]?.jsonObject?.get("reason")?.jsonArray?.firstOrNull()
                    ?.jsonObject?.get("message")?.jsonPrimitive?.contentOrNull
                    ?: parsed["context"]?.jsonObject?.get("reason")?.jsonObject?.get("message")?.jsonPrimitive?.contentOrNull,
            )
        }

    override suspend fun resolve(request: ResolveRequest): ResolveResponse =
        withContext(Dispatchers.IO) {
            val bearer = bearerProvider() ?: return@withContext ResolveResponse(
                metadata = ByteArray(0),
                trustInfo = null,
            )
            val body = kotlinx.serialization.json.buildJsonObject {
                put("subject_id", kotlinx.serialization.json.JsonPrimitive(request.uri))
                put(
                    "subject_type",
                    kotlinx.serialization.json.JsonPrimitive(if (request.resourceType == "did_document") "key" else "url"),
                )
                put("resource_type", kotlinx.serialization.json.JsonPrimitive(request.resourceType))
            }.toString()
            val response = client.newCall(
                Request.Builder()
                    .url("${baseUrl.trimEnd('/')}/v1/resolve")
                    .header("Authorization", "Bearer $bearer")
                    .post(body.toRequestBody("application/json".toMediaType()))
                    .build(),
            ).execute()
            val answer = runCatching {
                response.use { resp ->
                    check(resp.isSuccessful) { "resolve answered ${resp.code}" }
                    resp.body?.string()
                }
            }.getOrNull() ?: return@withContext ResolveResponse(ByteArray(0), null)
            val parsed = runCatching {
                kotlinx.serialization.json.Json.parseToJsonElement(answer).jsonObject
            }.getOrNull() ?: return@withContext ResolveResponse(ByteArray(0), null)
            val metadata = parsed["context"]?.jsonObject?.get("trust_metadata")
                ?: parsed["metadata"]
            ResolveResponse(
                metadata = metadata?.toString()?.toByteArray() ?: ByteArray(0),
                trustInfo = null,
            )
        }

    /**
     * The proxy has no entitlement route (the backend's PDP surface is
     * evaluate + resolve): answer the engine's NOT-EVALUATED decision -
     * allowed, OFF mode, nothing checked - the same shape a PdpError
     * NotImplemented maps to (ARF 6.6.2.3's grace: no answer is no
     * evaluation, nothing refused).
     */
    override suspend fun evaluateEntitlement(
        request: uniffi.engine_adapter_sdk.EntitlementRequest,
    ): uniffi.engine_adapter_sdk.EntitlementDecision =
        uniffi.engine_adapter_sdk.EntitlementDecision(
            allowed = true,
            mode = uniffi.engine_adapter_sdk.EntitlementMode.OFF,
            evaluated = false,
            findings = emptyList(),
            findingsTruncated = false,
        )

    /** The resource type the proxy accepts (its allowed set): a JSON object is a `jwk`, a `did:` string a `kid`, anything else `x5c`. */
    private fun keyMaterialType(keyMaterial: ByteArray): String {
        val value = runCatching {
            kotlinx.serialization.json.Json.parseToJsonElement(String(keyMaterial)).jsonObject
        }.getOrNull()
        return when {
            value != null -> "jwk"
            String(keyMaterial).trimStart().startsWith("did:") -> "kid"
            else -> "x5c"
        }
    }

    /** The resource key: the parsed JSON as-is (a JWK), or the raw material. */
    private fun keyMaterialValue(keyMaterial: ByteArray): kotlinx.serialization.json.JsonElement {
        val raw = String(keyMaterial)
        return runCatching { kotlinx.serialization.json.Json.parseToJsonElement(raw) }.getOrElse {
            kotlinx.serialization.json.JsonPrimitive(raw)
        }
    }

    private val kotlinx.serialization.json.JsonElement.jsonObject: kotlinx.serialization.json.JsonObject
        get() = this as? kotlinx.serialization.json.JsonObject
            ?: throw IllegalArgumentException("expected an object")

    private val kotlinx.serialization.json.JsonElement.jsonPrimitive: kotlinx.serialization.json.JsonPrimitive
        get() = this as? kotlinx.serialization.json.JsonPrimitive
            ?: throw IllegalArgumentException("expected a primitive")

    private val kotlinx.serialization.json.JsonElement.jsonArray: kotlinx.serialization.json.JsonArray
        get() = this as? kotlinx.serialization.json.JsonArray
            ?: throw IllegalArgumentException("expected an array")

    private val kotlinx.serialization.json.JsonElement.booleanOrNull: Boolean?
        get() = (this as? kotlinx.serialization.json.JsonPrimitive)?.booleanOrNull

    private val kotlinx.serialization.json.JsonElement.contentOrNull: String?
        get() = (this as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull
}