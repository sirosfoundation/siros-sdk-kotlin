// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.trust

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException

private val JSON_MEDIA_TYPE = "application/json".toMediaType()

/**
 * Unauthenticated HTTP AuthZEN client for a standalone go-trust endpoint.
 *
 * [endpoint] is the complete evaluation URL, not a base URL: no path is
 * appended. The request body is sent byte-for-byte as UTF-8 without parsing or
 * re-serializing it. Each POST carries [tenantId] in `X-Tenant-ID`; this class
 * never adds an `Authorization` or `Cookie` header and has no account, login,
 * or wallet-authentication dependency.
 *
 * Only a top-level JSON boolean `"decision": true` is a permit. Explicit deny,
 * a missing or non-boolean decision, malformed JSON, non-2xx statuses, and
 * network failures all fail closed with an [AuthZenException].
 */
class HttpAuthZenPdp(
    endpoint: String,
    private val tenantId: String,
    private val httpClient: OkHttpClient = OkHttpClient(),
) : AuthZenPdp {
    private val endpoint: HttpUrl = endpoint.toHttpUrl()
    private val json = Json

    init {
        require(tenantId.isNotBlank()) { "tenantId must not be blank" }
    }

    override suspend fun evaluate(requestJson: String): Boolean {
        val request = Request.Builder()
            .url(endpoint)
            .header("X-Tenant-ID", tenantId)
            .post(requestJson.toRequestBody(JSON_MEDIA_TYPE))
            .build()

        return try {
            withContext(Dispatchers.IO) {
                httpClient.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) {
                        throw AuthZenHttpException(response.code)
                    }
                    val body = response.body?.string()
                        ?: throw AuthZenResponseException("The policy decision point returned an empty response")
                    when (decision(body)) {
                        true -> true
                        false -> throw AuthZenDeniedException()
                    }
                }
            }
        } catch (e: IOException) {
            throw AuthZenNetworkException(e)
        }
    }

    private fun decision(body: String): Boolean {
        val response = try {
            json.parseToJsonElement(body)
        } catch (e: SerializationException) {
            throw AuthZenResponseException("The policy decision point returned malformed JSON", e)
        } catch (e: IllegalArgumentException) {
            throw AuthZenResponseException("The policy decision point returned malformed JSON", e)
        }
        val responseObject = response as? JsonObject
            ?: throw AuthZenResponseException("The AuthZEN response must be a JSON object")
        rejectDuplicateDecisions(body)
        val decision = responseObject["decision"]
            ?: throw AuthZenResponseException("The AuthZEN response is missing a decision")
        if (decision !is JsonPrimitive || decision.isString ||
            (decision.content != "true" && decision.content != "false")
        ) {
            throw AuthZenResponseException("The AuthZEN decision must be a JSON boolean")
        }
        return decision.content == "true"
    }

    /** JsonObject keeps the last duplicate member, which could turn an ambiguous deny into a permit. */
    private fun rejectDuplicateDecisions(body: String) {
        var count = 0
        var index = body.indexOf('{') + 1
        while (true) {
            index = skipWhitespace(body, index)
            if (body[index] == '}') return
            val keyEnd = skipString(body, index)
            val key = (json.parseToJsonElement(body.substring(index, keyEnd)) as JsonPrimitive).content
            if (key == "decision") {
                count++
                if (count > 1) throw AuthZenResponseException("The AuthZEN response contains duplicate decisions")
            }
            index = skipWhitespace(body, keyEnd) + 1 // colon
            index = skipValue(body, skipWhitespace(body, index))
            index = skipWhitespace(body, index)
            if (body[index] == '}') return
            index++ // comma
        }
    }

    private fun skipWhitespace(value: String, start: Int): Int {
        var index = start
        while (value[index].isWhitespace()) index++
        return index
    }

    private fun skipString(value: String, start: Int): Int {
        var index = start + 1
        while (value[index] != '"') {
            if (value[index] == '\\') index++
            index++
        }
        return index + 1
    }

    /** Called only after kotlinx.serialization has established that [value] is valid JSON. */
    private fun skipValue(value: String, start: Int): Int {
        var index = start
        var depth = 0
        while (index < value.length) {
            when (value[index]) {
                '"' -> index = skipString(value, index)
                '{', '[' -> {
                    depth++
                    index++
                }
                '}', ']' -> {
                    if (depth == 0) return index
                    depth--
                    index++
                }
                ',' -> {
                    if (depth == 0) return index
                    index++
                }
                else -> index++
            }
        }
        return index
    }
}
