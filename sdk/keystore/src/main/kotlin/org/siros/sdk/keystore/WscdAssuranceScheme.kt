// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

/**
 * A pluggable assurance-label VOCABULARY the wallet SDK (never
 * `siros-wscd-manager`, which stays label-agnostic forever - see
 * [WscdCertificationLevel]'s doc comment) uses to express wscd-manager's
 * objective, scheme-agnostic facts - a [WscdCertificationLevel], or the raw
 * key-storage-type string [Signer.securityProperties] reports for an
 * already-generated key - in whatever vocabulary a given deployment's
 * compliance posture / issuer ecosystem actually speaks.
 *
 * This interface exists because, before it, TWO independently-authored
 * static tables silently disagreed about what the same underlying hardware
 * fact meant - a real bug found during the TEE/Secure-Enclave plugin work,
 * not a hypothetical one: [WscdPluginCapabilities]'s plugin-id table and
 * [WscdKeystoreAdapter]'s now-removed private `toIso18045AttackPotential`
 * switch. Collapsing both into calls through exactly one injected
 * [WscdAssuranceScheme] instance eliminates that drift risk: there is now
 * exactly one place a deployment decides what an objective WSCD fact means
 * for assurance-labeling purposes, supplied as data (constructor
 * parameters on [Iso18045AssuranceScheme], or a wholly different
 * implementation of this interface) rather than compiled into the SDK.
 *
 * **wscd-manager itself never sees a label, ISO 18045 or otherwise** - its
 * own `CertificationLevel`/`FfiCertificationLevel` enum (mirrored here as
 * [WscdCertificationLevel]) stays in its own objective, purely STRUCTURAL
 * three-point vocabulary (`unattested`/`attested_shared_environment`/
 * `attested_dedicated_hardware` - whether an attestation artifact is present
 * and structurally complete, and whether the hardware class it claims is a
 * shared execution environment or a dedicated one; never who evaluated the
 * hardware or by what process) and knows nothing about any label scheme. This
 * interface - and everything that calls through it
 * ([WscdSelectionPolicy], [WscdPluginCapabilities]) - lives entirely on the
 * SDK side, by design: different deployments auditing the SAME wallet
 * (SDK + wscd-manager together) may legitimately reach different
 * conclusions about what a given hardware fact is worth, so that judgment
 * must not be baked into wscd-manager, which is shared by every deployment.
 *
 * [Iso18045AssuranceScheme] ships as the DEFAULT implementation because ISO
 * 18045 is the vocabulary today's credential catalogs
 * (`Vctm.requiredKeyStorage`/`MddlSchema.requiredKeyStorage`, wire field
 * `attestation_los`) and the OID4VCI Key Attestation JWT's registered
 * `key_storage`/`user_authentication` claims actually use - but nothing in
 * [WscdSelectionPolicy] or [WscdPluginCapabilities] hardcodes ISO 18045 as
 * THE vocabulary: a deployment whose issuer ecosystem speaks a different
 * one (NIST SP 800-63 AAL, eIDAS LoA, an internal scale) implements this
 * interface itself and passes an instance to `WscdSelectionPolicy`'s
 * constructor; candidate selection keeps working unchanged, since it only
 * ever compares two labels via [meets] and never assumes what they look
 * like.
 *
 * The OID4VCI Key Attestation JWT is the one call site that is NOT free to
 * swap vocabularies: `key_storage`/`user_authentication` are a registered
 * external wire format whose values ARE the four ISO 18045 AVA_VAN tiers
 * `iso_18045_basic`/`iso_18045_enhanced-basic`/`iso_18045_moderate`/
 * `iso_18045_high` (OID4VCI Appendix D.2, "Attack Potential Resistance") by
 * spec, not a deployment's choice - so [WscdKeystoreAdapter] always builds
 * those two claims through an [Iso18045AssuranceScheme] specifically (never
 * an arbitrary [WscdAssuranceScheme] a deployment might otherwise be using
 * for plugin selection), even though exactly which
 * [WscdCertificationLevel]/key-storage type maps to which of those four real
 * ISO 18045 tiers remains deployment-configurable DATA on that class.
 * [Iso18045AssuranceScheme.DEFAULT_TIER_ORDER] (plugin SELECTION's own
 * ranking) includes enhanced-basic too, for a different reason: a credential
 * catalog here never REQUIRES it, but [WscdCertificationLevel.ATTESTED_SHARED_ENVIRONMENT]
 * DOES get reported as it by default, and [meets] must be able to rank that
 * reported value correctly against whatever IS required.
 */
interface WscdAssuranceScheme {

    /**
     * This scheme's label for wscd-manager's objective, scheme-agnostic
     * [level] fact (`unattested`/`attested_shared_environment`/
     * `attested_dedicated_hardware` - see [WscdCertificationLevel]), as confirmed by
     * [WscdManager.generateKeyForLevel] or reported in
     * [org.siros.sdk.credentials.SignerSecurityProperties.certification] for an
     * already-generated key.
     */
    fun labelFor(level: WscdCertificationLevel): String

    /**
     * This scheme's label for the raw key-storage-type string
     * [Signer.securityProperties] reports (`"software"`/`"hardware"`/
     * `"trusted_execution"`/`"remote_hsm"` - see
     * [org.siros.sdk.credentials.SignerSecurityProperties.keyStorage]), the real,
     * per-key, confirmed storage classification wscd-manager reports for an
     * already-generated key.
     *
     * A separate entry point from [labelFor] because, as of this writing,
     * not every [Signer] implementation populates
     * [org.siros.sdk.credentials.SignerSecurityProperties.certification] with a
     * real [WscdCertificationLevel] yet (e.g. [AndroidKeystoreSigner] always
     * reports [org.siros.sdk.credentials.CertificationInfo.None] there) - `keyStorage`
     * is the one signal every [Signer] implementation reports meaningfully
     * today, so it is what the Key Attestation JWT's `key_storage` claim is
     * actually built from. A raw type string already in this scheme's own
     * vocabulary (e.g. already `"iso_18045_*"`) is returned unchanged.
     */
    fun labelForKeyStorageType(rawKeyStorageType: String): String

    /**
     * This scheme's a-priori (BEFORE any key is generated) label for a known
     * plugin id - used by [WscdSelectionPolicy] to decide which registered
     * plugins are even worth trying for a credential type's declared
     * requirement. `null` for a plugin id this scheme has no opinion on (an
     * unrecognized/future plugin id), distinct from "the lowest tier",  so a
     * caller can tell "no data" from "known and weak."
     */
    fun nominalLabelFor(pluginId: String): String?

    /**
     * True if [actual] (one of this scheme's own labels) is at least as
     * strong an assurance claim as [required] (also this scheme's own
     * vocabulary). MUST fail closed: a label either side doesn't recognize
     * (a typo, a future tier this scheme's own table hasn't been updated
     * for) never satisfies anything.
     */
    fun meets(actual: String, required: String): Boolean
}

/**
 * The DEFAULT [WscdAssuranceScheme]: ISO 18045 (Common Criteria evaluation
 * assurance methodology) `AVA_VAN`-flavored tiers, ascending
 * [BASIC] < [MODERATE] < [HIGH], matching the wire's `attestation_los` field
 * (see [org.siros.sdk.credentials.Vctm.requiredKeyStorage]) and the OID4VCI Key
 * Attestation JWT's registered `key_storage`/`user_authentication` values.
 *
 * Every mapping table here is a CONSTRUCTOR PARAMETER, not a compiled-in
 * constant: a deployment whose audit should treat e.g. `"fido2"` as merely
 * [MODERATE] (not this class's own default of [HIGH]) constructs
 * `Iso18045AssuranceScheme(nominalPluginLabels = Iso18045AssuranceScheme.DEFAULT_NOMINAL_PLUGIN_LABELS + ("fido2" to Iso18045AssuranceScheme.MODERATE))`
 * and passes that instance wherever a [WscdAssuranceScheme] is accepted. [DEFAULT]
 * is this class's own best-effort, documented default, used automatically
 * unless a deployment supplies its own instance.
 */
class Iso18045AssuranceScheme(
    private val certificationLevelLabels: Map<WscdCertificationLevel, String> = DEFAULT_CERTIFICATION_LEVEL_LABELS,
    private val keyStorageTypeLabels: Map<String, String> = DEFAULT_KEY_STORAGE_TYPE_LABELS,
    private val nominalPluginLabels: Map<String, String> = DEFAULT_NOMINAL_PLUGIN_LABELS,
    private val tierOrder: List<String> = DEFAULT_TIER_ORDER,
) : WscdAssuranceScheme {

    override fun labelFor(level: WscdCertificationLevel): String =
        validated(certificationLevelLabels[level])

    override fun labelForKeyStorageType(rawKeyStorageType: String): String {
        val candidate = if (rawKeyStorageType.startsWith("iso_18045_")) {
            rawKeyStorageType // already claims to be spec-compliant - still validated below, not trusted blindly
        } else {
            keyStorageTypeLabels[rawKeyStorageType.lowercase()]
        }
        return validated(candidate)
    }

    /**
     * [candidate] if it is one of the three real, registered ISO-18045 wire
     * labels ([BASIC]/[MODERATE]/[HIGH]), else [BASIC].
     *
     * This type ALWAYS emits one of exactly those three strings, however
     * [certificationLevelLabels]/[keyStorageTypeLabels] were configured -
     * [WscdKeystoreAdapter] builds the OID4VCI Key Attestation JWT's
     * `key_storage`/`user_authentication` claims from this type specifically
     * (never the generic [WscdAssuranceScheme] interface) precisely because
     * that wire format's registered values ARE these four strings
     * ([BASIC]/[ENHANCED_BASIC]/[MODERATE]/[HIGH] - OID4VCI Appendix D.2,
     * "Attack Potential Resistance") by spec, not a deployment's free choice
     * (see [WscdAssuranceScheme]'s doc comment) - a misconfigured map entry
     * (a typo, or a value copied from a different vocabulary entirely) must
     * never reach an issuer as an unrecognized `key_storage` value, which a
     * real conformance-test issuer has already been confirmed to reject once
     * (see [DEFAULT_KEY_STORAGE_TYPE_LABELS]'s doc comment).
     */
    private fun validated(candidate: String?): String = if (candidate in WIRE_LABELS) candidate!! else BASIC

    override fun nominalLabelFor(pluginId: String): String? = nominalPluginLabels[pluginId]

    override fun meets(actual: String, required: String): Boolean {
        val actualIndex = tierOrder.indexOf(actual)
        val requiredIndex = tierOrder.indexOf(required)
        if (actualIndex < 0 || requiredIndex < 0) return false
        return actualIndex >= requiredIndex
    }

    /** [tier]'s position in [tierOrder] (higher = stronger assurance), or -1 for an unrecognized tier string. */
    fun rankOf(tier: String): Int = tierOrder.indexOf(tier)

    companion object {
        const val BASIC = "iso_18045_basic"
        const val ENHANCED_BASIC = "iso_18045_enhanced-basic"
        const val MODERATE = "iso_18045_moderate"
        const val HIGH = "iso_18045_high"

        /**
         * Ascending assurance order for plugin-SELECTION eligibility
         * ([meets]/[rankOf]). [ENHANCED_BASIC] - between [BASIC] and
         * [MODERATE] - IS included here, even though no credential catalog
         * in this ecosystem ever REQUIRES it (see [WscdPluginCapabilities]'s
         * original, deliberate scope): [DEFAULT_CERTIFICATION_LEVEL_LABELS]
         * maps [WscdCertificationLevel.ATTESTED_SHARED_ENVIRONMENT] to
         * exactly this label, so [labelFor] can hand `meets()` an ACTUAL
         * value of [ENHANCED_BASIC] - omitting it from this list would make
         * [meets] treat that perfectly valid [labelFor] output as
         * unrecognized and fail closed, rejecting an attested-TEE key
         * against even a bare [BASIC] requirement while an [UNATTESTED] key
         * (correctly ranked at index 0) would pass the same check. The
         * "never a REQUIREMENT" fact about catalog data stays true on its
         * own; this list existing to rank `actual` values correctly is a
         * separate concern from what a catalog is ever observed to request.
         */
        val DEFAULT_TIER_ORDER = listOf(BASIC, ENHANCED_BASIC, MODERATE, HIGH)

        /**
         * The full OID4VCI-registered ISO 18045 AVA_VAN wire vocabulary
         * (Appendix D.2, "Attack Potential Resistance") [labelFor]/
         * [labelForKeyStorageType] are allowed to emit - see [validated].
         * Happens to contain the same four strings as [DEFAULT_TIER_ORDER]
         * today, but the two exist for different, independent reasons and
         * must not be conflated: this is a fixed membership check mandated
         * by the OID4VCI spec itself, used by [validated] alone, and NEVER a
         * constructor parameter - unlike [DEFAULT_TIER_ORDER] (an ordered,
         * deployment-configurable list a custom [Iso18045AssuranceScheme]
         * instance may narrow, reorder, or replace entirely for its own
         * plugin-SELECTION ranking).
         */
        private val WIRE_LABELS: Set<String> = setOf(BASIC, ENHANCED_BASIC, MODERATE, HIGH)

        /**
         * wscd-manager's own objective, structural tiers, as this DEFAULT
         * scheme reads them for [labelFor]:
         *
         * - [WscdCertificationLevel.UNATTESTED] -> [BASIC]: no attestation
         *   evidence at all, same floor as an unrecognized/absent fact.
         * - [WscdCertificationLevel.ATTESTED_SHARED_ENVIRONMENT] ->
         *   [ENHANCED_BASIC]: a real attestation artifact backs this key, but
         *   the hardware class it claims shares silicon/attack surface with
         *   the main application processor (e.g. a TEE) - exactly the same
         *   reasoning [DEFAULT_KEY_STORAGE_TYPE_LABELS] already applies to
         *   the raw `"trusted_execution"` key-storage string (see its own
         *   doc comment): real isolation above pure software, but not a
         *   dedicated element, so [ENHANCED_BASIC] is the precise fit, not a
         *   compromise between [BASIC] and [MODERATE].
         * - [WscdCertificationLevel.ATTESTED_DEDICATED_HARDWARE] ->
         *   [MODERATE], deliberately NOT [HIGH]: a real attestation artifact
         *   claims a physically separate, dedicated secure element, which is
         *   real hardware-backing evidence worth crediting above
         *   [ENHANCED_BASIC] - but wscd-manager's structural check alone
         *   (attestation present + hardware-class claim, chain-to-root
         *   verification explicitly NOT done by wscd-manager - see
         *   `CertificationLevel`'s own Rust doc comment) is not the same
         *   thing as a genuine third-party certification evaluation, so this
         *   default does not reach for the wire format's strongest tier
         *   without one. A deployment with real, out-of-band evaluation
         *   evidence for its specific hardware (e.g. a confirmed StrongBox
         *   chip model, or - mirroring [DEFAULT_NOMINAL_PLUGIN_LABELS]'s
         *   `"r2ps"` entry - a specific known HSM) may override this default
         *   to [HIGH] via the constructor parameter.
         */
        val DEFAULT_CERTIFICATION_LEVEL_LABELS: Map<WscdCertificationLevel, String> = mapOf(
            WscdCertificationLevel.UNATTESTED to BASIC,
            WscdCertificationLevel.ATTESTED_SHARED_ENVIRONMENT to ENHANCED_BASIC,
            WscdCertificationLevel.ATTESTED_DEDICATED_HARDWARE to MODERATE,
        )

        /**
         * The raw key-storage-type strings [Signer.securityProperties] reports
         * (`software`/`hardware`/`trusted_execution`/`remote_hsm` - mirrors
         * `FfiKeyStorageType`), as this DEFAULT scheme reads them for the Key
         * Attestation JWT's `key_storage`/`user_authentication` claims.
         * Unrecognized strings (a typo, or a real but non-hardware-class value
         * like a `userAuthentication` method name, e.g. `"pin"`/`"biometric"`)
         * fall through to [BASIC] via [labelForKeyStorageType]'s `?:` default -
         * the same conservative behavior the table this replaced had, since
         * overclaiming resistance this scheme can't back up is worse than
         * underclaiming it.
         *
         * `"trusted_execution"` reads as [ENHANCED_BASIC] here - a REAL,
         * registered OID4VCI tier (VAN.3, between [BASIC]/VAN.2 and
         * [MODERATE]/VAN.4 - see [WIRE_LABELS]'s doc comment), not a stray
         * string: a TEE-backed key is real hardware isolation from the OS,
         * clearly above a pure software key, but (unlike a dedicated secure
         * element) a TEE shares silicon with the main CPU and has its own
         * attack surface, so this default does not overclaim it as fully
         * [MODERATE] either - [ENHANCED_BASIC] is the precise, correct fit,
         * not a compromise between two coarser choices.
         */
        val DEFAULT_KEY_STORAGE_TYPE_LABELS: Map<String, String> = mapOf(
            "software" to BASIC,
            "hardware" to MODERATE,
            "trusted_execution" to ENHANCED_BASIC,
            "remote_hsm" to HIGH,
        )

        /**
         * Nominal (pre-key-generation) tier for each known plugin id - see
         * [WscdPluginCapabilities]'s original doc comment for the per-plugin
         * rationale this preserves: `"softkey"` -> [BASIC] (no hardware-backing
         * claim); `"fido2"` -> [HIGH] (CTAP2 hardware-backed, a real per-key
         * attestation statement from the authenticator); `"r2ps"` -> [HIGH],
         * best-effort/config-dependent (a remote-HSM-backed plugin, so its
         * real assurance depends entirely on which HSM a given deployment's
         * R2PS server is backed by - this is a nominal ceiling, not a
         * guarantee); `"android-keystore"` -> [BASIC], deliberately
         * conservative (NOT [MODERATE]): per a real Copilot review finding,
         * the v0.13.0 Android Keystore plugin's non-StrongBox fallback can
         * accept a software/unknown security level, so merely registering
         * this plugin does not guarantee the TEE floor its name suggests -
         * admitting it as [MODERATE] here, BEFORE any key exists to confirm
         * that, would let [WscdSelectionPolicy] select it for a moderate
         * requirement without ever having verified the generated key's real
         * assurance. [BASIC] is the only nominal claim this table can make
         * safely until a real per-key confirmation path (`generateKeyForLevel`/
         * [WscdManager.generateKeyForLevel]'s confirm-after-generate contract)
         * is actually wired into production issuance - see that method's doc
         * comment. A deployment that has verified its fleet's StrongBox/TEE
         * availability out of band may configure this higher.
         */
        val DEFAULT_NOMINAL_PLUGIN_LABELS: Map<String, String> = mapOf(
            "softkey" to BASIC,
            "fido2" to HIGH,
            "r2ps" to HIGH,
            "android-keystore" to BASIC,
        )

        /** This scheme's own default instance - see the class doc comment. */
        val DEFAULT: Iso18045AssuranceScheme = Iso18045AssuranceScheme()
    }
}
