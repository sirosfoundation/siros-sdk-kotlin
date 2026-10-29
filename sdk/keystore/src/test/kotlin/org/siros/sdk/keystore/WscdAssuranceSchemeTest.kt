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
 * what the two tables it replaces used to produce (except
 * `"android-keystore"`'s nominal tier, a deliberate, documented safety fix -
 * see [Iso18045AssuranceScheme.DEFAULT_NOMINAL_PLUGIN_LABELS]'s doc comment),
 * and (b) a deployment can genuinely override every axis with its own data,
 * not just read a hardcoded default under a new name.
 */
class WscdAssuranceSchemeTest {

    // ── DEFAULT matches the previous (now-removed) tables' practical values ──

    @Test
    fun default_nominalPluginLabels_matchPreviousNominalTierTable_exceptAndroidKeystoreSafetyFix() {
        val scheme = Iso18045AssuranceScheme.DEFAULT
        assertEquals("iso_18045_basic", scheme.nominalLabelFor("softkey"))
        assertEquals("iso_18045_high", scheme.nominalLabelFor("fido2"))
        assertEquals("iso_18045_high", scheme.nominalLabelFor("r2ps"))
        // Deliberately BASIC, not MODERATE: the v0.13.0 Android Keystore
        // plugin's non-StrongBox fallback can accept a software/unknown
        // security level, so registering it alone does not guarantee the TEE
        // floor a higher nominal tier would claim BEFORE any key is
        // generated and confirmed - see this value's doc comment.
        assertEquals("iso_18045_basic", scheme.nominalLabelFor("android-keystore"))
        assertNull(scheme.nominalLabelFor("some-future-plugin"))
    }

    @Test
    fun default_keyStorageTypeLabels_matchPreviousAttackPotentialMapping() {
        val scheme = Iso18045AssuranceScheme.DEFAULT
        // Unchanged from the previous `toIso18045AttackPotential` table:
        assertEquals("iso_18045_basic", scheme.labelForKeyStorageType("software"))
        assertEquals("iso_18045_moderate", scheme.labelForKeyStorageType("hardware"))
        assertEquals("iso_18045_high", scheme.labelForKeyStorageType("remote_hsm"))
        // Also unchanged: "iso_18045_enhanced-basic" is a REAL, registered
        // OID4VCI value (Appendix D.2, VAN.3) - not a stray string, contrary
        // to this test's own earlier (incorrect) assumption. A TEE shares
        // silicon with the main CPU, so it is precisely enhanced-basic, not
        // the coarser "moderate" a dedicated secure element ("hardware")
        // reads as.
        assertEquals("iso_18045_enhanced-basic", scheme.labelForKeyStorageType("trusted_execution"))
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
    fun misconfiguredKeyStorageTypeLabel_fallsBackToBasic_notTheUnsupportedValue() {
        // Regression test for a real Copilot finding: a deployment
        // misconfiguring Iso18045AssuranceScheme with a non-ISO-18045 value
        // (a typo, or a label copied from a different vocabulary) must never
        // reach the OID4VCI Key Attestation JWT as an unrecognized
        // key_storage value - validated() clamps it to BASIC instead.
        val misconfigured = Iso18045AssuranceScheme(keyStorageTypeLabels = mapOf("hardware" to "aal2"))
        assertEquals("iso_18045_basic", misconfigured.labelForKeyStorageType("hardware"))
    }

    @Test
    fun misconfiguredCertificationLevelLabel_fallsBackToBasic() {
        val misconfigured = Iso18045AssuranceScheme(
            certificationLevelLabels = mapOf(WscdCertificationLevel.HIGH to "not_a_real_tier"),
        )
        assertEquals("iso_18045_basic", misconfigured.labelFor(WscdCertificationLevel.HIGH))
    }

    @Test
    fun aRawStringAlreadyClaimingIso18045PrefixIsStillValidated() {
        // The "already spec-compliant, pass through" fast path must not
        // trust an arbitrary "iso_18045_"-prefixed string blindly - only one
        // of the four REAL, OID4VCI-registered tiers passes through
        // unchanged; a made-up one (even with the right prefix) does not.
        val scheme = Iso18045AssuranceScheme.DEFAULT
        assertEquals("iso_18045_basic", scheme.labelForKeyStorageType("iso_18045_bogus"))
        // "enhanced-basic" IS one of the four real tiers (OID4VCI Appendix
        // D.2, VAN.3) - it passes through unchanged, not clamped to basic.
        assertEquals("iso_18045_enhanced-basic", scheme.labelForKeyStorageType("iso_18045_enhanced-basic"))
        assertEquals("iso_18045_high", scheme.labelForKeyStorageType("iso_18045_high"))
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
