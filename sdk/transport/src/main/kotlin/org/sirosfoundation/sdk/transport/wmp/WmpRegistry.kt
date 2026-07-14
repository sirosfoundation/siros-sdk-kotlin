// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

package org.sirosfoundation.sdk.transport.wmp

import java.util.concurrent.ConcurrentHashMap

/**
 * Internal registry that maps flow types, methods, and resolve types
 * to their respective handlers. Used by [WmpPeer] for dispatch.
 */
internal class WmpRegistry {
    private val profiles = mutableListOf<WmpProfile>()
    private val flowHandlers = ConcurrentHashMap<String, WmpFlowHandler>()
    private val methodHandlers = ConcurrentHashMap<String, WmpMethodHandler>()
    private val resolveHandlers = ConcurrentHashMap<String, WmpResolveHandler>()

    /** Register a profile and index its handlers. */
    fun register(profile: WmpProfile) {
        profiles.add(profile)

        if (profile is WmpFlowHandler) {
            for (ft in profile.flowTypes) {
                check(!flowHandlers.containsKey(ft)) {
                    "Flow type '$ft' already registered by another profile"
                }
                flowHandlers[ft] = profile
            }
        }
        if (profile is WmpMethodHandler) {
            for (m in profile.methods) {
                check(!methodHandlers.containsKey(m)) {
                    "Method '$m' already registered by another profile"
                }
                methodHandlers[m] = profile
            }
        }
        if (profile is WmpResolveHandler) {
            for (rt in profile.resolveTypes) {
                check(!resolveHandlers.containsKey(rt)) {
                    "Resolve type '$rt' already registered by another profile"
                }
                resolveHandlers[rt] = profile
            }
        }
    }

    /** Lookup the flow handler for a given flow type. */
    fun flowHandler(flowType: String): WmpFlowHandler? = flowHandlers[flowType]

    /** Lookup the method handler for a custom method. */
    fun methodHandler(method: String): WmpMethodHandler? = methodHandlers[method]

    /** Lookup the resolve handler for a resolve type. */
    fun resolveHandler(resolveType: String): WmpResolveHandler? = resolveHandlers[resolveType]

    /** All registered profiles. */
    fun profiles(): List<WmpProfile> = profiles.toList()

    /** Aggregate capabilities from all registered profiles. */
    fun allCapabilities(): List<String> = profiles.flatMap { it.capabilities }
}
