// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

/**
 * Phase-1 static key-storage capability table for the three WSCD plugin IDs
 * known to `siros-wscd-manager`'s `FfiWscdConfig.defaultPlugin` today
 * (`"softkey"`, `"fido2"`, `"r2ps"` - see the sample app's plugin chooser,
 * `WscaDeveloperScreen.kt`).
 *
 * Deliberately NOT a live capability query against a real plugin instance:
 * there is no per-plugin "what tier are you" call in `siros-wscd-manager`
 * today, and adding one is out of scope for this phase (see
 * `WscdSelectionPolicy`'s doc comment). This is a nominal, best-guess
 * mapping the wallet SDK uses to decide, BEFORE generating any keys,
 * whether a plugin the host app has already constructed is worth trying for
 * a credential type that declared a required tier - not a guarantee the
 * issuer will accept the resulting Key Attestation.
 *
 * Vocabulary is ISO 18045 (Common Criteria evaluation assurance
 * methodology) `AVA_VAN`-flavored tiers, matching the wire's
 * `attestation_los` field (see [org.siros.sdk.credentials.Vctm.requiredKeyStorage]):
 * `"iso_18045_basic"` < `"iso_18045_moderate"` < `"iso_18045_high"`.
 */
object WscdPluginCapabilities {

    /** Tiers in ascending assurance order - index is used for comparison in [meets]. */
    private val TIER_ORDER = listOf(
        "iso_18045_basic",
        "iso_18045_moderate",
        "iso_18045_high",
    )

    /**
     * Nominal tier for each known plugin ID.
     *
     * - `"softkey"` -> basic: a plain in-memory/KeyStore-file-backed key, no
     *   hardware backing claim.
     * - `"fido2"` -> high: a real CTAP2 authenticator's hardware-backed key,
     *   assessed against FIDO Alliance's authenticator certification levels.
     * - `"r2ps"` -> high, but **best-effort/config-dependent**: R2PS is a
     *   remote-HSM-backed plugin, so its actual assurance depends entirely
     *   on which HSM a given deployment's R2PS server is backed by - "high"
     *   here is a Phase-1 placeholder assumption, not a guarantee. A future
     *   phase that queries real per-deployment capability (see this object's
     *   class doc) is the fix for this, not a bigger static table.
     */
    val NOMINAL_TIER: Map<String, String> = mapOf(
        "softkey" to "iso_18045_basic",
        "fido2" to "iso_18045_high",
        "r2ps" to "iso_18045_high",
    )

    /** The nominal tier for [pluginId], or `null` if it's not a known plugin ID. */
    fun tierOf(pluginId: String): String? = NOMINAL_TIER[pluginId]

    /**
     * True if [actual] is at least as strong an assurance tier as
     * [required] (per [TIER_ORDER]). Unknown tier strings (typos, a future
     * tier this table hasn't been updated for) never satisfy anything -
     * fails closed rather than silently treating an unrecognized string as
     * sufficient.
     */
    fun meets(actual: String, required: String): Boolean {
        val actualIndex = TIER_ORDER.indexOf(actual)
        val requiredIndex = TIER_ORDER.indexOf(required)
        if (actualIndex < 0 || requiredIndex < 0) return false
        return actualIndex >= requiredIndex
    }
}
