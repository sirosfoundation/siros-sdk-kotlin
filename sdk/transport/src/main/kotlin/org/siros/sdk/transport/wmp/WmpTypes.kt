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

// ---------------------------------------------------------------------------
// WMP Method Constants
// ---------------------------------------------------------------------------

object WmpMethods {
    const val SESSION_CREATE = "wmp.session.create"
    const val SESSION_RESUME = "wmp.session.resume"
    const val SESSION_CLOSE = "wmp.session.close"
    const val SESSION_AUTHENTICATE = "wmp.session.authenticate"

    const val FLOW_START = "wmp.flow.start"
    const val FLOW_PROGRESS = "wmp.flow.progress"
    const val FLOW_ACTION = "wmp.flow.action"
    const val FLOW_COMPLETE = "wmp.flow.complete"
    const val FLOW_ERROR = "wmp.flow.error"
    const val FLOW_CANCEL = "wmp.flow.cancel"

    const val MESSAGE_DELIVER = "wmp.message.deliver"
    const val MESSAGE_ACK = "wmp.message.ack"

    const val CAPABILITY_UPDATE = "wmp.capability.update"

    const val RESOLVE = "wmp.resolve"

    const val CREDENTIAL_NOTIFICATION = "wmp.credential.notification"
}

/** Standard JSON-RPC error codes used by WMP. */
object WmpErrorCodes {
    const val PARSE_ERROR = -32700
    const val INVALID_REQUEST = -32600
    const val METHOD_NOT_FOUND = -32601
    const val INVALID_PARAMS = -32602
    const val INTERNAL_ERROR = -32603

    // WMP-specific error codes (application range)
    const val SESSION_ERROR = -32000
    const val AUTH_REQUIRED = -32001
    const val AUTH_FAILED = -32002
    const val FLOW_ERROR = -32010
    const val FLOW_NOT_FOUND = -32011
    const val FLOW_CANCELLED = -32012
    const val CAPABILITY_ERROR = -32020
    const val RELAY_ERROR = -32030
    const val ENCRYPTION_ERROR = -32040
    const val RESOLVE_ERROR = -32050
}

// ---------------------------------------------------------------------------
// Flow Types
// ---------------------------------------------------------------------------

/** Parameters for wmp.flow.start. */
@Serializable
data class FlowStartParams(
    val wmp: WmpMeta,
    @SerialName("flow_id") val flowId: String,
    @SerialName("flow_type") val flowType: String,
    val params: JsonObject? = null,
)

/** Result for wmp.flow.start. */
@Serializable
data class FlowStartResult(
    val wmp: WmpMeta? = null,
    @SerialName("flow_id") val flowId: String,
    @SerialName("flow_type") val flowType: String,
)

/** Parameters for wmp.flow.progress (notification). */
@Serializable
data class FlowProgressParams(
    val wmp: WmpMeta? = null,
    @SerialName("flow_id") val flowId: String,
    val step: String,
    val payload: JsonObject? = null,
)

/** Parameters for wmp.flow.action (request). */
@Serializable
data class FlowActionParams(
    val wmp: WmpMeta? = null,
    @SerialName("flow_id") val flowId: String,
    val action: String,
    val params: JsonObject? = null,
)

/** Result for wmp.flow.action. */
@Serializable
data class FlowActionResult(
    val wmp: WmpMeta? = null,
    @SerialName("flow_id") val flowId: String,
    val accepted: Boolean = true,
)

/** Parameters for wmp.flow.complete (notification). */
@Serializable
data class FlowCompleteParams(
    val wmp: WmpMeta? = null,
    @SerialName("flow_id") val flowId: String,
    val result: JsonObject? = null,
)

/** Parameters for wmp.flow.error (notification). */
@Serializable
data class FlowErrorParams(
    val wmp: WmpMeta? = null,
    @SerialName("flow_id") val flowId: String,
    val code: String? = null,
    val message: String? = null,
    val data: JsonElement? = null,
)

/** Parameters for wmp.flow.cancel. */
@Serializable
data class FlowCancelParams(
    val wmp: WmpMeta? = null,
    @SerialName("flow_id") val flowId: String,
    val reason: String? = null,
)

/** Parameters for wmp.resolve. */
@Serializable
data class ResolveParams(
    val wmp: WmpMeta? = null,
    val type: String,
    val identifier: String,
    val params: JsonObject? = null,
)

/** Result for wmp.resolve. */
@Serializable
data class ResolveResult(
    val wmp: WmpMeta? = null,
    val type: String,
    val data: JsonObject? = null,
)
