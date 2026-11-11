// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

package org.siros.sdk.sample

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
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
            // The ask, verbatim: found driving the GDC diploma issuance, where
            // the only visible failure was the engine's refusal code and the
            // actual binding under question had to be reconstructed by hand.
            timber.log.Timber.d(
                "ProxyPdp evaluate: subject=%s resourceType=%s material=%dB materialHead=%.60s",
                request.subject, request.resourceType, request.keyMaterial.size,
                String(request.keyMaterial, Charsets.UTF_8).replace('\n', ' '),
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
                    check(resp.isSuccessful) { "evaluate answered ${resp.code}" }.also {
                        timber.log.Timber.d("ProxyPdp evaluate: the proxy answered ${resp.code}")
                    }
                    resp.body?.string()
                }
            }.getOrNull() ?: return@withContext EvaluationResponse(
                trusted = false,
                decision = "the PDP route did not answer",
            )
            val parsed = runCatching {
                kotlinx.serialization.json.Json.parseToJsonElement(answer).jsonObject
            }.getOrNull() ?: return@withContext EvaluationResponse(trusted = false, decision = "an unparseable PDP answer")
            // TOTAL parse, no throwing casts: a callback that throws kills the
            // whole evaluate (the engine surfaces it as InternalException and
            // the flow refuses) - the decision bool is what the engine
            // consumes, and a shape surprise in the reason text must never
            // take it down (found: go-trust's context.reason is an OBJECT
            // {user, admin}, and the throwing jsonArray cast died on it).
            val decisionText = when (val reason = (parsed as? JsonObject)?.get("context")?.let { it as? JsonObject }?.get("reason")) {
                is JsonObject ->
                    (reason["user"] as? JsonPrimitive)?.contentOrNull
                        ?: (reason["admin"] as? JsonPrimitive)?.contentOrNull
                        ?: (reason["message"] as? JsonPrimitive)?.contentOrNull
                is JsonArray ->
                    ((reason.firstOrNull() as? JsonObject)?.get("message") as? JsonPrimitive)?.contentOrNull
                else -> null
            }
            EvaluationResponse(
                trusted = (parsed as? JsonObject)?.get("decision")?.let { it as? JsonPrimitive }?.booleanOrNull ?: false,
                decision = decisionText,
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
            // TOTAL parse, the evaluate block's own rule: a throwing cast in
            // this callback kills the resolve (InternalException, the flow
            // refuses) - an answer shape surprise answers empty metadata,
            // which the engine treats as "nothing resolved" (fail closed).
            val metadata = (parsed as? JsonObject)?.get("context")?.let { it as? JsonObject }
                ?.get("trust_metadata")
                ?: (parsed as? JsonObject)?.get("metadata")
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

    /**
     * The resource key: the profile's shape is an ARRAY (go-trust's golden
     * testdata: `key: [ {...the JWK...} ]`, `key: ["<x5c cert>", ...]`) -
     * the bind is `[]interface{}` and a bare object fails it with a 400
     * (found driving the GDC diploma issuance: every evaluate fail-closed
     * "untrusted issuer" because the route never even answered).
     *
     * - EMPTY material rides as NULL: go-trust treats a null/empty key as a
     *   RESOLUTION-ONLY request (the registry question - "is this subject
     *   trusted", the PDP resolving its own material), which is exactly the
     *   reference adapter's shape (ports.rs answers Null for unparseable
     *   material). A fabricated `[""]` turns it into a key-binding
     *   evaluation against an empty key, which the PDP correctly denies -
     *   found on the mdoc diploma issuer (no inline JWKs; its material
     *   lives at mdoc_iacas_uri, which the engine's resolve carries
     *   server-side).
     * - a parsed ARRAY (the x5c chain) rides as-is;
     * - a parsed OBJECT (a JWK) rides one-element-wrapped;
     * - anything else (raw material, a did: kid) rides as a one-element
     *   string array.
     */
    private fun keyMaterialValue(keyMaterial: ByteArray): kotlinx.serialization.json.JsonElement {
        if (keyMaterial.isEmpty()) return kotlinx.serialization.json.JsonNull
        val raw = String(keyMaterial)
        val parsed = runCatching { kotlinx.serialization.json.Json.parseToJsonElement(raw) }.getOrNull()
        return when {
            parsed is kotlinx.serialization.json.JsonArray -> parsed
            parsed != null -> kotlinx.serialization.json.JsonArray(listOf(parsed))
            else -> kotlinx.serialization.json.JsonArray(
                listOf(kotlinx.serialization.json.JsonPrimitive(raw)),
            )
        }
    }
}