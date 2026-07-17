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
