// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

package org.siros.sdk.transport.wmp

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

/**
 * A pluggable extension to WMP. Profiles define additional capabilities,
 * flow types, resolve handlers, and custom methods.
 *
 * Register profiles with [WmpPeer.use] before connecting.
 */
interface WmpProfile {
    /** Profile identifier (e.g., "openid4x"). */
    val name: String

    /** Capability names this profile provides for session negotiation. */
    val capabilities: List<String>

    /** Called when the profile is registered with a Peer. */
    fun init(ctx: WmpPeerContext)
}

/**
 * Provides profiles with the ability to send messages and access session state.
 */
interface WmpPeerContext {
    /** Send a JSON-RPC 2.0 notification (fire-and-forget). */
    suspend fun notify(method: String, params: JsonObject?)

    /**
     * Send a notification only while [wanted] still holds, checked at the last moment: an implementation that serialises its
     * sends (a lock around the transport) checks again once it holds the lock, so a message queued behind another send is not
     * sent after what it answers has ended. Returns whether it was sent. The default checks once, then sends.
     */
    suspend fun notifyIf(method: String, params: JsonObject?, wanted: () -> Boolean): Boolean {
        if (!wanted()) return false
        notify(method, params)
        return true
    }

    /**
     * Forget everything the peer tracks for [flowId] (which handler a later frame for it is routed to), without sending anything.
     * A handler calls it for a flow it stopped itself, one that will never send the terminal frame that clears it. The default
     * does nothing.
     */
    fun forgetFlow(flowId: String) {}

    /** Send a JSON-RPC 2.0 request and wait for the response. */
    suspend fun call(method: String, params: JsonObject?): JsonRpcResponse

    /** The codec used for encoding/decoding messages. */
    val codec: WmpCodec
}

/**
 * Handles profile-specific flow types. The Peer dispatches flow operations
 * to the handler whose [flowTypes] contains the incoming flow_type.
 */
interface WmpFlowHandler {
    /** Flow type identifiers this handler manages (e.g., "oid4vci", "oid4vp"). */
    val flowTypes: List<String>

    /** Called for wmp.flow.start with a matching flow_type. */
    suspend fun startFlow(params: FlowStartParams): FlowStartResult

    /** Called for wmp.flow.action on a flow managed by this handler. */
    suspend fun handleAction(params: FlowActionParams): FlowActionResult

    /** Called for wmp.flow.progress on a flow managed by this handler. */
    suspend fun handleProgress(params: FlowProgressParams)

    /** Called for wmp.flow.complete on a flow managed by this handler. */
    suspend fun handleComplete(params: FlowCompleteParams)

    /** Called for wmp.flow.error on a flow managed by this handler. */
    suspend fun handleError(params: FlowErrorParams)

    /** Called for wmp.flow.cancel on a flow managed by this handler. */
    suspend fun handleCancel(params: FlowCancelParams)

    /**
     * Called when this peer itself ends [flowId] (a local cancel), before it releases the flow's state, so work the handler
     * started for the flow can stop first. Inbound terminal frames reach [handleComplete], [handleError] and [handleCancel].
     */
    fun flowEnded(flowId: String) {}
}

/**
 * Handles custom JSON-RPC methods defined by a profile.
 */
interface WmpMethodHandler {
    /** Method names this handler supports. */
    val methods: List<String>

    /** Process an incoming method call. Returns the result or throws. */
    suspend fun handleMethod(method: String, params: JsonObject?): JsonObject?
}

/**
 * Handles profile-specific resolution types for wmp.resolve.
 */
interface WmpResolveHandler {
    /** Resolution type identifiers this handler supports. */
    val resolveTypes: List<String>

    /** Process a resolve request for a supported type. */
    suspend fun handleResolve(params: ResolveParams): ResolveResult
}

/**
 * Thrown from [WmpFlowHandler.startFlow] to refuse a `wmp.flow.start` request outright (for example when the handler has no room):
 * [WmpPeer] answers the request with an error response carrying [message] and starts nothing, so a refusal needs no flow of its own
 * and nothing that could be sent after the flow it concerns has ended.
 */
class FlowStartRefusedException(message: String) : Exception(message)
