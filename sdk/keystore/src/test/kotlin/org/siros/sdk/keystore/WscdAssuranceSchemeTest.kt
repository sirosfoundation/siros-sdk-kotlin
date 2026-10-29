// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [Iso18045AssuranceScheme] is the single configurable source
 * [WscdPluginCapabilities] and [WscdKeystoreAdapter] both now read through -
 * see [WscdAssuranceScheme]'s doc comment for the bug (two independently-
 * guessed tables silently disagreeing) this collapses. These tests prove
 * two things: (a) [Iso18045AssuranceScheme.DEFAULT]'s practical values match
 * what the two tables it replaces used to produce (except the one
 * deliberate, documented fix - the stray `"iso_18045_enhanced-basic"`
 * string), and (b) a deployment can genuinely override every axis with its
 * own data, not just read a hardcoded default under a new name.
 */
class WscdAssuranceSchemeTest {

    // ── DEFAULT matches the previous (now-removed) tables' practical values ──

    @Test
    fun default_nominalPluginLabels_matchPreviousNominalTierTable() {
        val scheme = Iso18045AssuranceScheme.DEFAULT
        assertEquals("iso_18045_basic", scheme.nominalLabelFor("softkey"))
        assertEquals("iso_18045_high", scheme.nominalLabelFor("fido2"))
        assertEquals("iso_18045_high", scheme.nominalLabelFor("r2ps"))
        assertNull(scheme.nominalLabelFor("some-future-plugin"))
    }

    @Test
    fun default_keyStorageTypeLabels_matchPreviousAttackPotentialMapping_exceptTheDocumentedFix() {
        val scheme = Iso18045AssuranceScheme.DEFAULT
        // Unchanged from the previous `toIso18045AttackPotential` table:
        assertEquals("iso_18045_basic", scheme.labelForKeyStorageType("software"))
        assertEquals("iso_18045_moderate", scheme.labelForKeyStorageType("hardware"))
        assertEquals("iso_18045_high", scheme.labelForKeyStorageType("remote_hsm"))
        // The deliberate fix: "trusted_execution" used to map to the stray,
        // non-canonical "iso_18045_enhanced-basic" string (never part of the
        // 3-tier vocabulary anywhere else in this codebase or the OID4VCI
        // wire format) - now resolved to "iso_18045_moderate", the most
        // defensible of the three REAL tiers (see this class's doc comment).
        assertEquals("iso_18045_moderate", scheme.labelForKeyStorageType("trusted_execution"))
        // Already-spec-compliant strings pass through unchanged.
        assertEquals("iso_18045_high", scheme.labelForKeyStorageType("iso_18045_high"))
        // Unrecognized raw strings (a typo, or a userAuthentication method
        // name like "pin"/"biometric" sharing this entry point) fail closed
        // to the lowest tier, same as before.
        assertEquals("iso_18045_basic", scheme.labelForKeyStorageType("pin"))
    }

    @Test
    fun default_certificationLevelLabels_rankWscdCertificationLevelsAscending() {
        val scheme = Iso18045AssuranceScheme.DEFAULT
        assertEquals("iso_18045_basic", scheme.labelFor(WscdCertificationLevel.NONE))
        assertEquals("iso_18045_basic", scheme.labelFor(WscdCertificationLevel.BASELINE))
        assertEquals("iso_18045_moderate", scheme.labelFor(WscdCertificationLevel.SUBSTANTIAL))
        assertEquals("iso_18045_high", scheme.labelFor(WscdCertificationLevel.HIGH))
    }

    @Test
    fun default_meets_isReflexiveAndFailsClosedForUnrecognizedTiers() {
        val scheme = Iso18045AssuranceScheme.DEFAULT
        assertTrue(scheme.meets("iso_18045_basic", "iso_18045_basic"))
        assertTrue(scheme.meets("iso_18045_high", "iso_18045_basic"))
        assertFalse(scheme.meets("iso_18045_basic", "iso_18045_high"))
        assertFalse(scheme.meets("bogus", "iso_18045_basic"))
        assertFalse(scheme.meets("iso_18045_high", "bogus"))
    }

    // ── WscdPluginCapabilities facade delegates to the DEFAULT scheme ────────

    @Test
    fun wscdPluginCapabilitiesFacade_delegatesToDefaultScheme() {
        assertEquals("iso_18045_high", WscdPluginCapabilities.tierOf("fido2"))
        assertTrue(WscdPluginCapabilities.meets("iso_18045_high", "iso_18045_basic"))
        assertEquals(1, WscdPluginCapabilities.rankOf("iso_18045_moderate"))
    }

    // ── Genuinely deployment-configurable: NOT still hardcoded anywhere ──────

    @Test
    fun customScheme_overridesNominalPluginLabel_fido2ToSubstantial() {
        // One deployment's audit: "fido2" should count as iso_18045_moderate
        // (NOT this class's own default of iso_18045_high) - leifj's own
        // example of why this mapping had to become deployment data rather
        // than a single compiled-in guess.
        val lenient = Iso18045AssuranceScheme(
            nominalPluginLabels = mapOf("fido2" to Iso18045AssuranceScheme.HIGH),
        )
        val strict = Iso18045AssuranceScheme(
            nominalPluginLabels = mapOf("fido2" to Iso18045AssuranceScheme.MODERATE),
        )

        assertEquals("iso_18045_high", lenient.nominalLabelFor("fido2"))
        assertEquals("iso_18045_moderate", strict.nominalLabelFor("fido2"))
        // Each instance is independent - overriding one does not mutate the
        // shared DEFAULT or the other custom instance.
        assertEquals("iso_18045_high", Iso18045AssuranceScheme.DEFAULT.nominalLabelFor("fido2"))
    }

    @Test
    fun customScheme_overridesKeyStorageTypeLabel() {
        val custom = Iso18045AssuranceScheme(
            keyStorageTypeLabels = mapOf("hardware" to Iso18045AssuranceScheme.HIGH),
        )
        assertEquals("iso_18045_high", custom.labelForKeyStorageType("hardware"))
        assertEquals("iso_18045_moderate", Iso18045AssuranceScheme.DEFAULT.labelForKeyStorageType("hardware"))
    }

    @Test
    fun customScheme_overridesCertificationLevelLabel() {
        val custom = Iso18045AssuranceScheme(
            certificationLevelLabels = mapOf(WscdCertificationLevel.SUBSTANTIAL to Iso18045AssuranceScheme.HIGH),
        )
        assertEquals("iso_18045_high", custom.labelFor(WscdCertificationLevel.SUBSTANTIAL))
        // Unmapped levels fail closed to the lowest tier rather than throwing.
        assertEquals("iso_18045_basic", custom.labelFor(WscdCertificationLevel.HIGH))
    }

    @Test
    fun customScheme_overridesTierOrder_changesMeetsResult() {
        // A deployment using a different (or reordered) label set entirely -
        // meets() must compare through whatever order THIS instance was
        // configured with, not a fixed internal constant.
        val custom = Iso18045AssuranceScheme(tierOrder = listOf("low", "mid", "crit"))
        assertTrue(custom.meets("crit", "low"))
        assertFalse(custom.meets("low", "crit"))
        // The DEFAULT instance's own order is untouched.
        assertFalse(Iso18045AssuranceScheme.DEFAULT.meets("crit", "low"))
    }

    /** A non-ISO-18045 vocabulary entirely: proves the interface itself is scheme-agnostic, not just the data within one scheme. */
    private class FixedLabelScheme(private val label: String) : WscdAssuranceScheme {
        override fun labelFor(level: WscdCertificationLevel): String = label
        override fun labelForKeyStorageType(rawKeyStorageType: String): String = label
        override fun nominalLabelFor(pluginId: String): String? = label
        override fun meets(actual: String, required: String): Boolean = actual == required
    }

    @Test
    fun wscdAssuranceScheme_isNotIso18045Specific_aDifferentVocabularyImplementationWorksToo() {
        val nistStyle = FixedLabelScheme("aal2")
        assertEquals("aal2", nistStyle.nominalLabelFor("fido2"))
        assertEquals("aal2", nistStyle.labelFor(WscdCertificationLevel.HIGH))
        assertTrue(nistStyle.meets("aal2", "aal2"))
        assertFalse(nistStyle.meets("aal2", "iso_18045_high"))
    }
}
