package org.siros.sdk.transport.wmp

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

/** WMP metadata envelope present in every request/response. */
@Serializable
data class WmpMeta(
    val version: String = WMP_VERSION,
    @SerialName("session_id") val sessionId: String? = null,
    val sender: String? = null,
    val timestamp: String? = null,
    @SerialName("trace_id") val traceId: String? = null,
    val encrypted: Boolean? = null,
) {
    companion object {
        const val WMP_VERSION = "0.1"
    }
}

/** JSON-RPC 2.0 request. */
@Serializable
data class JsonRpcRequest(
    val jsonrpc: String = "2.0",
    val id: String? = null,
    val method: String,
    val params: JsonObject? = null,
)

/** JSON-RPC 2.0 response. */
@Serializable
data class JsonRpcResponse(
    val jsonrpc: String = "2.0",
    val id: String? = null,
    val result: JsonObject? = null,
    val error: JsonRpcError? = null,
)

@Serializable
data class JsonRpcError(
    val code: Int,
    val message: String,
    val data: JsonElement? = null,
)

/** WMP session creation parameters. */
@Serializable
data class SessionCreateParams(
    val wmp: WmpMeta,
    val participants: List<String>? = null,
    @SerialName("capabilities_offered") val capabilitiesOffered: JsonObject? = null,
    val security: JsonObject? = null,
    val ttl: Int? = null,
    val auth: SessionAuth? = null,
)

@Serializable
data class SessionAuth(
    val type: String,
    val token: String,
)

/** WMP session creation result. */
@Serializable
data class SessionCreateResult(
    val wmp: WmpMeta,
    val capabilities: JsonObject? = null,
    val security: JsonObject? = null,
    val challenge: String? = null,
    @SerialName("resumption_token") val resumptionToken: String? = null,
)

/** WMP session resume parameters. */
@Serializable
data class SessionResumeParams(
    val wmp: WmpMeta,
    @SerialName("session_id") val sessionId: String,
    @SerialName("resumption_token") val resumptionToken: String,
    @SerialName("last_received_id") val lastReceivedId: String? = null,
)

/** WMP session resume result. */
@Serializable
data class SessionResumeResult(
    val wmp: WmpMeta,
    val resumed: Boolean,
    @SerialName("resumption_token") val resumptionToken: String? = null,
    @SerialName("missed_messages") val missedMessages: Int? = null,
)

/** WMP session close parameters. */
@Serializable
data class SessionCloseParams(
    val wmp: WmpMeta,
    val reason: String? = null,
)
