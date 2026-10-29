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
 * [WscdCertificationLevel]) stays in its own objective, four-point
 * vocabulary (`none`/`baseline`/`substantial`/`high`, based on real
 * verifiable facts: hardware class, attestation presence, key
 * non-exportability) and knows nothing about any label scheme. This
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
 * external wire format whose values ARE `iso_18045_basic`/
 * `iso_18045_moderate`/`iso_18045_high` by spec, not a deployment's choice -
 * so [WscdKeystoreAdapter] always builds those two claims through an
 * [Iso18045AssuranceScheme] specifically (never an arbitrary
 * [WscdAssuranceScheme] a deployment might otherwise be using for plugin
 * selection), even though exactly which [WscdCertificationLevel]/key-storage
 * type maps to which of the three real ISO 18045 tiers remains
 * deployment-configurable DATA on that class.
 */
interface WscdAssuranceScheme {

    /**
     * This scheme's label for wscd-manager's objective, scheme-agnostic
     * [level] fact (`none`/`baseline`/`substantial`/`high` - see
     * [WscdCertificationLevel]), as confirmed by
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
        certificationLevelLabels[level] ?: BASIC

    override fun labelForKeyStorageType(rawKeyStorageType: String): String {
        if (rawKeyStorageType.startsWith("iso_18045_")) return rawKeyStorageType // already spec-compliant, pass through
        return keyStorageTypeLabels[rawKeyStorageType.lowercase()] ?: BASIC
    }

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
        const val MODERATE = "iso_18045_moderate"
        const val HIGH = "iso_18045_high"

        /** Ascending assurance order for [meets]/[rankOf]. */
        val DEFAULT_TIER_ORDER = listOf(BASIC, MODERATE, HIGH)

        /**
         * wscd-manager's own objective tiers, as this DEFAULT scheme reads
         * them for [labelFor]: `NONE`/`BASELINE` both read as [BASIC]
         * (neither represents meaningful hardware backing); `SUBSTANTIAL` as
         * [MODERATE]; `HIGH` as [HIGH].
         */
        val DEFAULT_CERTIFICATION_LEVEL_LABELS: Map<WscdCertificationLevel, String> = mapOf(
            WscdCertificationLevel.NONE to BASIC,
            WscdCertificationLevel.BASELINE to BASIC,
            WscdCertificationLevel.SUBSTANTIAL to MODERATE,
            WscdCertificationLevel.HIGH to HIGH,
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
         * `"trusted_execution"` reads as [MODERATE] here - NOT the stray
         * `"iso_18045_enhanced-basic"` string the mapping this replaced used:
         * that string was never part of the three-tier `iso_18045_basic`/
         * `moderate`/`high` vocabulary used anywhere else in this codebase or
         * registered for the OID4VCI Key Attestation JWT's `key_storage`
         * claim, so a strict validator has no meaning for it at all - the
         * exact class of bug a real conformance-test issuer already caught
         * once for the `"software"` case (see this class's git history). A
         * TEE-backed key is real hardware isolation from the OS, clearly
         * above a pure software key, so [BASIC] would underclaim it; [MODERATE] -
         * the same tier `"hardware"` reads as - is the most defensible of the
         * three REAL tiers for it (not [HIGH]: unlike a dedicated secure
         * element, a TEE shares silicon with the main CPU and has its own
         * attack surface, so this default does not overclaim resistance a TEE
         * cannot back up).
         */
        val DEFAULT_KEY_STORAGE_TYPE_LABELS: Map<String, String> = mapOf(
            "software" to BASIC,
            "hardware" to MODERATE,
            "trusted_execution" to MODERATE,
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
         * guarantee); `"android-keystore"` -> [MODERATE] (Android Key
         * Attestation is real and hardware-rooted, but this default does not
         * assume every device reaches StrongBox - only the TEE floor every
         * device with this plugin registered is guaranteed to have; a
         * deployment that verifies StrongBox/the attestation security level
         * per device can configure this higher).
         */
        val DEFAULT_NOMINAL_PLUGIN_LABELS: Map<String, String> = mapOf(
            "softkey" to BASIC,
            "fido2" to HIGH,
            "r2ps" to HIGH,
            "android-keystore" to MODERATE,
        )

        /** This scheme's own default instance - see the class doc comment. */
        val DEFAULT: Iso18045AssuranceScheme = Iso18045AssuranceScheme()
    }
}
