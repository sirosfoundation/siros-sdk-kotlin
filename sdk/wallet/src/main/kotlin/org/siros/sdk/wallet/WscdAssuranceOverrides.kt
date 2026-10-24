// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.siros.sdk.keystore.KeystoreManager
import org.siros.sdk.keystore.WscdAssuranceOverride
import org.siros.sdk.keystore.WscdKeystoreAdapter

/**
 * TEST FACILITY ONLY: puts each plugin's [WscdAssuranceOverride] on the [WscdKeystoreAdapter] registered under that plugin id.
 * A plugin id with no such adapter is ignored (nothing is applied to a keystore that cannot attest). Returns the plugin ids applied.
 */
internal fun applyWscdAssuranceOverrides(
    overrides: Map<String, WscdAssuranceOverride>,
    keystores: Map<String, KeystoreManager>?,
): Set<String> {
    val applied = LinkedHashSet<String>()
    for ((pluginId, override) in overrides) {
        val adapter = keystores?.get(pluginId) as? WscdKeystoreAdapter ?: continue
        adapter.testOnlyAssuranceOverride = override
        applied += pluginId
    }
    return applied
}
