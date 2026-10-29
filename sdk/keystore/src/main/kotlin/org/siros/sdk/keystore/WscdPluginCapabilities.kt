// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

/**
 * Phase-1 static key-storage capability facade for the WSCD plugin IDs known
 * to `siros-wscd-manager` today (`"softkey"`, `"fido2"`, `"r2ps"`,
 * `"android-keystore"` - see the sample app's plugin chooser,
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
 * As of this type, the actual mapping data lives on [Iso18045AssuranceScheme]
 * ([scheme], fixed to [Iso18045AssuranceScheme.DEFAULT]) rather than a table
 * hardcoded here - see [WscdAssuranceScheme]'s doc comment for why: a
 * previous version of this object hardcoded its own `NOMINAL_TIER` table,
 * independently from [WscdKeystoreAdapter]'s own (also now-removed)
 * ISO-18045 guess, and the two silently disagreed.
 *
 * This object's static methods are kept only as a read-only convenience
 * facade over [Iso18045AssuranceScheme.DEFAULT] for callers that predate
 * [WscdAssuranceScheme] (the sample app's plugin chooser). It is
 * deliberately NOT configurable itself (no process-wide "set the default"
 * knob here) - a deployment wanting a different mapping (or a wholly
 * different [WscdAssuranceScheme] implementation) passes its own instance to
 * [WscdSelectionPolicy]'s (or [WscdKeystoreAdapter]'s) constructor instead,
 * which is the ONE place such a choice actually takes effect. A second,
 * independent "configure the default here too" surface on this object would
 * recreate exactly the two-places-to-configure-the-same-thing problem this
 * type exists to fix.
 *
 * Vocabulary is ISO 18045 (Common Criteria evaluation assurance
 * methodology) `AVA_VAN`-flavored tiers, matching the wire's
 * `attestation_los` field (see [org.siros.sdk.credentials.Vctm.requiredKeyStorage]):
 * `"iso_18045_basic"` < `"iso_18045_moderate"` < `"iso_18045_high"`.
 */
object WscdPluginCapabilities {

    /** The [Iso18045AssuranceScheme] instance this facade's static methods delegate to. */
    val scheme: Iso18045AssuranceScheme get() = Iso18045AssuranceScheme.DEFAULT

    /** Tiers in ascending assurance order - see [Iso18045AssuranceScheme.rankOf]. */
    val TIER_ORDER: List<String> get() = Iso18045AssuranceScheme.DEFAULT_TIER_ORDER

    /**
     * Nominal tier for each known plugin ID, as [scheme] currently maps it -
     * see [Iso18045AssuranceScheme.DEFAULT_NOMINAL_PLUGIN_LABELS] for the
     * default values and their rationale.
     */
    val NOMINAL_TIER: Map<String, String>
        get() = Iso18045AssuranceScheme.DEFAULT_NOMINAL_PLUGIN_LABELS

    /** The nominal tier for [pluginId] under [scheme], or `null` if it's not a known plugin ID. */
    fun tierOf(pluginId: String): String? = scheme.nominalLabelFor(pluginId)

    /**
     * [tier]'s position in [scheme]'s tier order (higher = stronger assurance), or -1
     * for an unrecognized tier string. Lets a caller rank multiple plugins
     * by assurance - e.g. to pick the cheapest plugin that still satisfies a
     * credential's required tier, rather than defaulting to whichever
     * plugin happens to be otherwise selected (a real bug found in the
     * sample app's TS11 discovery flow: filtering by "does the currently
     * open tab's plugin meet this tier" trivially matched every credential
     * whenever that tab's own nominal tier was already the highest one,
     * silently routing everything - including basic-tier credentials that
     * softkey would satisfy just fine - to that one plugin).
     */
    fun rankOf(tier: String): Int = scheme.rankOf(tier)

    /**
     * True if [actual] is at least as strong an assurance tier as
     * [required] under [scheme]. Unknown tier strings (typos, a future
     * tier this table hasn't been updated for) never satisfy anything -
     * fails closed rather than silently treating an unrecognized string as
     * sufficient.
     */
    fun meets(actual: String, required: String): Boolean = scheme.meets(actual, required)
}
