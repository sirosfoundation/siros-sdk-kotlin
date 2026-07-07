// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

package org.sirosfoundation.sdk.auth

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull

/**
 * Recursively converts a [JsonElement] to plain Kotlin types:
 * - [JsonObject] → `Map<String, Any?>`
 * - [JsonArray] → `List<Any?>`
 * - [JsonPrimitive] → `String`, `Boolean`, `Int`, `Long`, `Double`, or the content string
 * - [JsonNull] → `null`
 *
 * This bridges kotlinx.serialization's typed JSON tree with code that
 * expects plain `Map`/`String` (e.g. WebAuthn challenge parsing).
 */
fun JsonElement.toPlainValue(): Any? = when (this) {
    is JsonNull -> null
    is JsonPrimitive -> {
        if (isString) content
        else booleanOrNull ?: intOrNull ?: longOrNull ?: doubleOrNull ?: content
    }
    is JsonObject -> entries.associate { (k, v) -> k to v.toPlainValue() }
    is JsonArray -> map { it.toPlainValue() }
}

/**
 * Convenience: convert a [JsonObject] to `Map<String, Any?>`.
 */
@Suppress("UNCHECKED_CAST")
fun JsonObject.toPlainMap(): Map<String, Any?> = toPlainValue() as Map<String, Any?>
