// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

/**
 * TEST FACILITY ONLY. Replaces the `key_storage` (and optionally `user_authentication`) assurance a WSCD plugin attests, and the tier
 * the wallet's plugin selection assumes for it, so a flow that requires a high tier (PID issuance) can be exercised with a software
 * WSCA. It is a lie told to the wallet's own gating and to whoever reads the attestation: an issuer MUST NOT trust a self-attested
 * key for real issuance, and the wallet provider backend independently lowers an assertion it cannot back (see the wallet
 * configuration's `testOnlyWscdAssuranceOverrides`). Never read from remote configuration or from the engine.
 *
 * @property keyStorage the `iso_18045_*` tier to attest and assume for key storage.
 * @property userAuthentication the `iso_18045_*` tier to attest for user authentication, or null to leave the plugin's own.
 * @throws IllegalArgumentException when a value is not one of [TIERS].
 */
class WscdAssuranceOverride(val keyStorage: String, val userAuthentication: String? = null) {
    init {
        require(keyStorage in TIERS) { "keyStorage must be one of $TIERS" }
        require(userAuthentication == null || userAuthentication in TIERS) { "userAuthentication must be one of $TIERS" }
    }

    override fun toString() = "WscdAssuranceOverride(keyStorage=$keyStorage, userAuthentication=$userAuthentication)"

    companion object {
        /** The valid values: the tiers [WscdPluginCapabilities] can rank, so the override is meaningful to plugin selection. */
        val TIERS: List<String> = listOf("iso_18045_basic", "iso_18045_moderate", "iso_18045_high")
    }
}
