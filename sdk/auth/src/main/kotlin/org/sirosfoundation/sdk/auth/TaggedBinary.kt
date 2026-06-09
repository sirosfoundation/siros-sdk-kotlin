package org.sirosfoundation.sdk.auth

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive

/**
 * Utilities for handling tagged binary encoding used by the wallet backend.
 *
 * Binary data (byte arrays) is encoded in JSON as `{"$b64u": "base64url-string"}`.
 * This is the wire format convention between the frontend/SDK and the Go backend,
 * mirroring [wallet-frontend/src/util.ts] `jsonParseTaggedBinary` /
 * `jsonStringifyTaggedBinary` and [go-wallet-backend/pkg/taggedbinary].
 */
object TaggedBinary {

    private const val TAG_KEY = "\$b64u"

    /**
     * Recursively decode a [JsonElement], converting any `{"$b64u": "..."}` objects
     * into plain [JsonPrimitive] strings. All other values pass through unchanged.
     */
    fun decode(element: JsonElement): JsonElement = when (element) {
        is JsonObject -> {
            val b64u = element[TAG_KEY]
            if (b64u != null && element.size == 1 && b64u is JsonPrimitive) {
                // Tagged binary → unwrap to plain string
                b64u
            } else {
                // Regular object → recurse into values
                JsonObject(element.mapValues { (_, v) -> decode(v) })
            }
        }
        is JsonArray -> JsonArray(element.map { decode(it) })
        else -> element
    }

    /**
     * Extract a base64url string from a [JsonElement] that may be either:
     *  - a plain string: `"dGVzdA"`
     *  - a tagged binary object: `{"$b64u": "dGVzdA"}`
     *
     * Returns the base64url string content in both cases.
     */
    fun extractBase64Url(element: JsonElement): String = when (element) {
        is JsonPrimitive -> element.content
        is JsonObject -> element[TAG_KEY]?.jsonPrimitive?.content
            ?: throw IllegalArgumentException("Expected \$b64u key in object: $element")
        else -> throw IllegalArgumentException("Unexpected JSON element for base64url: $element")
    }
}
