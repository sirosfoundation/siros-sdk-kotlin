package org.siros.sdk.transport.wmp

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import java.util.UUID

/**
 * JSON-RPC 2.0 codec for WMP messages.
 * Handles serialization/deserialization and message ID generation.
 */
class WmpCodec(
    @PublishedApi internal val json: Json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    },
) {
    fun encodeRequest(method: String, params: JsonObject?, id: String? = UUID.randomUUID().toString()): ByteArray {
        val request = JsonRpcRequest(
            id = id,
            method = method,
            params = params,
        )
        return json.encodeToString(JsonRpcRequest.serializer(), request).toByteArray(Charsets.UTF_8)
    }

    fun encodeNotification(method: String, params: JsonObject?): ByteArray {
        return encodeRequest(method, params, id = null)
    }

    fun decodeResponse(data: ByteArray): JsonRpcResponse {
        return json.decodeFromString(JsonRpcResponse.serializer(), data.toString(Charsets.UTF_8))
    }

    fun decodeRequest(data: ByteArray): JsonRpcRequest {
        return json.decodeFromString(JsonRpcRequest.serializer(), data.toString(Charsets.UTF_8))
    }

    fun decodeMessage(data: ByteArray): WmpMessage {
        val text = data.toString(Charsets.UTF_8)
        val element = json.parseToJsonElement(text).jsonObject

        return if (element.containsKey("method")) {
            val request = json.decodeFromString(JsonRpcRequest.serializer(), text)
            if (request.id != null) {
                WmpMessage.Request(request)
            } else {
                WmpMessage.Notification(request)
            }
        } else {
            val response = json.decodeFromString(JsonRpcResponse.serializer(), text)
            WmpMessage.Response(response)
        }
    }

    /** Encode a typed params object into a JsonObject for inclusion in a request. */
    inline fun <reified T> encodeParams(value: T): JsonObject {
        return json.encodeToJsonElement(value).jsonObject
    }
}

/** Discriminated union of incoming WMP messages. */
sealed class WmpMessage {
    data class Request(val request: JsonRpcRequest) : WmpMessage()
    data class Notification(val notification: JsonRpcRequest) : WmpMessage()
    data class Response(val response: JsonRpcResponse) : WmpMessage()
}
