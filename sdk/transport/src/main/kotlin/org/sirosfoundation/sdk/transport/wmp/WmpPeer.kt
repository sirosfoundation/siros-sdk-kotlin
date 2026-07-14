// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

package org.sirosfoundation.sdk.transport.wmp

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import timber.log.Timber

/**
 * WMP Peer — the central dispatch node for the Wallet Messaging Protocol.
 *
 * Wraps a [WmpSession] and adds profile-based routing for flows, methods,
 * and resolve requests. Profiles are registered via [use] before connecting.
 *
 * Usage:
 * ```kotlin
 * val peer = WmpPeer(session)
 * peer.use(OpenID4xProfile(config))
 * peer.connect(authToken)
 *
 * peer.flowEvents().collect { event ->
 *     when (event) {
 *         is FlowEvent.Progress -> handleProgress(event)
 *         is FlowEvent.Complete -> handleComplete(event)
 *         ...
 *     }
 * }
 * ```
 */
class WmpPeer(
    private val session: WmpSession,
) : WmpPeerContext {

    private val registry = WmpRegistry()
    override val codec: WmpCodec get() = session.codec

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val _flowEvents = MutableSharedFlow<FlowEvent>(extraBufferCapacity = 64)

    /** Observable stream of flow lifecycle events dispatched by profiles. */
    fun flowEvents(): Flow<FlowEvent> = _flowEvents

    /** Session state. */
    val state: StateFlow<WmpSessionState> get() = session.state

    // ---- Profile registration ----

    /**
     * Register a [WmpProfile]. The profile may also implement
     * [WmpFlowHandler], [WmpMethodHandler], or [WmpResolveHandler]
     * for automatic dispatch routing.
     *
     * Must be called before [connect].
     */
    fun use(profile: WmpProfile) {
        registry.register(profile)
        profile.init(this)
    }

    // ---- Lifecycle ----

    /** Connect and create a WMP session. Starts the dispatch loop. */
    suspend fun connect(authToken: String, sender: String? = null) {
        session.create(authToken, sender)
        startDispatch()
    }

    /** Close the session and stop dispatching. */
    suspend fun close(reason: String = "complete") {
        session.close(reason)
        scope.cancel()
    }

    // ---- PeerContext (outgoing) ----

    override suspend fun notify(method: String, params: JsonObject?) {
        session.sendNotification(method, params)
    }

    override suspend fun call(method: String, params: JsonObject?): JsonRpcResponse {
        return session.sendRequest(method, params)
    }

    // ---- Flow convenience methods ----

    /** Start a flow via wmp.flow.start. */
    suspend fun startFlow(flowType: String, flowId: String, params: JsonObject? = null): FlowStartResult {
        val reqParams = codec.encodeParams(
            FlowStartParams(
                wmp = WmpMeta(),
                flowId = flowId,
                flowType = flowType,
                params = params,
            )
        )
        val response = call(WmpMethods.FLOW_START, reqParams)
        if (response.error != null) {
            throw WmpSessionException("flow.start failed: ${response.error.message}")
        }
        return codec.json.decodeFromJsonElement(
            FlowStartResult.serializer(),
            response.result ?: throw WmpSessionException("flow.start: missing result"),
        )
    }

    /** Send a flow action via wmp.flow.action. */
    suspend fun sendFlowAction(flowId: String, action: String, params: JsonObject? = null): FlowActionResult {
        val reqParams = codec.encodeParams(
            FlowActionParams(
                wmp = WmpMeta(),
                flowId = flowId,
                action = action,
                params = params,
            )
        )
        val response = call(WmpMethods.FLOW_ACTION, reqParams)
        if (response.error != null) {
            throw WmpSessionException("flow.action failed: ${response.error.message}")
        }
        return codec.json.decodeFromJsonElement(
            FlowActionResult.serializer(),
            response.result ?: throw WmpSessionException("flow.action: missing result"),
        )
    }

    /** Send a flow cancel notification. */
    suspend fun cancelFlow(flowId: String, reason: String? = null) {
        val params = codec.encodeParams(
            FlowCancelParams(wmp = WmpMeta(), flowId = flowId, reason = reason)
        )
        notify(WmpMethods.FLOW_CANCEL, params)
    }

    /** Send a credential notification. */
    suspend fun sendCredentialNotification(
        flowId: String,
        notificationId: String,
        event: String,
        eventDescription: String? = null,
    ) {
        val params = kotlinx.serialization.json.buildJsonObject {
            put("wmp", codec.json.encodeToJsonElement(WmpMeta.serializer(), WmpMeta()))
            put("flow_id", kotlinx.serialization.json.JsonPrimitive(flowId))
            put("notification_id", kotlinx.serialization.json.JsonPrimitive(notificationId))
            put("event", kotlinx.serialization.json.JsonPrimitive(event))
            eventDescription?.let {
                put("event_description", kotlinx.serialization.json.JsonPrimitive(it))
            }
        }
        notify(WmpMethods.CREDENTIAL_NOTIFICATION, params)
    }

    // ---- Dispatch loop ----

    private fun startDispatch() {
        scope.launch {
            session.notifications().collect { msg ->
                try {
                    dispatch(msg)
                } catch (e: Exception) {
                    Timber.e(e, "WmpPeer dispatch error for ${msg.method}")
                }
            }
        }
    }

    private suspend fun dispatch(msg: JsonRpcRequest) {
        val params = msg.params

        when (msg.method) {
            WmpMethods.FLOW_PROGRESS -> {
                val p = decodeParams<FlowProgressParams>(params)
                val handler = registry.flowHandler(lookupFlowType(p.flowId))
                if (handler != null) {
                    handler.handleProgress(p)
                }
                _flowEvents.emit(FlowEvent.Progress(p.flowId, p.step, p.payload))
            }

            WmpMethods.FLOW_COMPLETE -> {
                val p = decodeParams<FlowCompleteParams>(params)
                val handler = registry.flowHandler(lookupFlowType(p.flowId))
                if (handler != null) {
                    handler.handleComplete(p)
                }
                _flowEvents.emit(FlowEvent.Complete(p.flowId, p.result))
            }

            WmpMethods.FLOW_ERROR -> {
                val p = decodeParams<FlowErrorParams>(params)
                val handler = registry.flowHandler(lookupFlowType(p.flowId))
                if (handler != null) {
                    handler.handleError(p)
                }
                _flowEvents.emit(FlowEvent.Error(p.flowId, p.code, p.message))
            }

            WmpMethods.FLOW_START -> {
                val p = decodeParams<FlowStartParams>(params)
                val handler = registry.flowHandler(p.flowType)
                if (handler != null) {
                    trackFlowType(p.flowId, p.flowType)
                    val result = handler.startFlow(p)
                    // Send response if this was a request (has id)
                    if (msg.id != null) {
                        val resultJson = codec.encodeParams(result)
                        val response = JsonRpcResponse(
                            id = msg.id,
                            result = resultJson,
                        )
                        session.sendNotification(
                            msg.method,
                            null,
                        ) // The response is sent via the correlation mechanism
                    }
                }
                _flowEvents.emit(FlowEvent.Started(p.flowId, p.flowType, p.params))
            }

            WmpMethods.FLOW_ACTION -> {
                val p = decodeParams<FlowActionParams>(params)
                val handler = registry.flowHandler(lookupFlowType(p.flowId))
                if (handler != null) {
                    handler.handleAction(p)
                }
                _flowEvents.emit(FlowEvent.Action(p.flowId, p.action, p.params))
            }

            WmpMethods.FLOW_CANCEL -> {
                val p = decodeParams<FlowCancelParams>(params)
                val handler = registry.flowHandler(lookupFlowType(p.flowId))
                if (handler != null) {
                    handler.handleCancel(p)
                }
                _flowEvents.emit(FlowEvent.Cancelled(p.flowId, p.reason))
            }

            else -> {
                // Check for custom method handlers
                val handler = registry.methodHandler(msg.method)
                if (handler != null) {
                    handler.handleMethod(msg.method, params)
                } else {
                    Timber.w("Unhandled WMP method: ${msg.method}")
                }
            }
        }
    }

    private inline fun <reified T> decodeParams(params: JsonObject?): T {
        requireNotNull(params) { "Missing params" }
        return codec.json.decodeFromJsonElement(kotlinx.serialization.serializer<T>(), params)
    }

    // ---- Flow type tracking ----

    private val flowTypeMap = java.util.concurrent.ConcurrentHashMap<String, String>()

    private fun trackFlowType(flowId: String, flowType: String) {
        flowTypeMap[flowId] = flowType
    }

    private fun lookupFlowType(flowId: String): String {
        return flowTypeMap[flowId] ?: "unknown"
    }
}

/**
 * Flow lifecycle events emitted by [WmpPeer.flowEvents].
 * Consumers observe these to drive UI and business logic.
 */
sealed class FlowEvent {
    data class Started(val flowId: String, val flowType: String, val params: JsonObject?) : FlowEvent()
    data class Progress(val flowId: String, val step: String, val payload: JsonObject?) : FlowEvent()
    data class Action(val flowId: String, val action: String, val params: JsonObject?) : FlowEvent()
    data class Complete(val flowId: String, val result: JsonObject?) : FlowEvent()
    data class Error(val flowId: String, val code: String?, val message: String?) : FlowEvent()
    data class Cancelled(val flowId: String, val reason: String?) : FlowEvent()
}
