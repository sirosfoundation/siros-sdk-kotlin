package org.siros.sdk.sample

/**
 * The 2026-11-16 settings-coverage bundles: the values + callbacks the
 * restructured Settings tab's new sections need, grouped so [SettingsTab]'s
 * parameter list stays finite. Each bundle is pure state + callbacks - the
 * same pattern the tab's individual parameters follow, just packed.
 */

/** The Security & Trust section's knobs (RICAL + VICAL, mode-first). */
data class TrustSettings(
    /** Reader (RICAL) trust evaluation mode - the deprecated boolean's full form. */
    val readerMode: org.siros.sdk.wallet.MdocTrustEvaluationMode = org.siros.sdk.wallet.MdocTrustEvaluationMode.REMOTE_WITH_LOCAL_FALLBACK,
    val onReaderMode: (org.siros.sdk.wallet.MdocTrustEvaluationMode) -> Unit = {},
    /** RICAL local-fallback root, single PEM. */
    val readerRootPem: String = "",
    val onReaderRootPem: (String) -> Unit = {},
    /** Issuer (VICAL) trust evaluation mode - previously unexposed entirely. */
    val issuerMode: org.siros.sdk.wallet.MdocTrustEvaluationMode = org.siros.sdk.wallet.MdocTrustEvaluationMode.REMOTE_WITH_LOCAL_FALLBACK,
    val onIssuerMode: (org.siros.sdk.wallet.MdocTrustEvaluationMode) -> Unit = {},
    /** VICAL local-fallback root, single PEM. */
    val issuerRootPem: String = "",
    val onIssuerRootPem: (String) -> Unit = {},
)

/** The Connection section's knobs (beyond the backend registry card). */
data class ConnectionSettings(
    /** TS11 registry base URL; blank = the SDK's derived default. */
    val registryUrl: String = "",
    val onRegistryUrl: (String) -> Unit = {},
    /** Validity/status clock-skew leeway, seconds. */
    val clockToleranceSeconds: Long = 60,
    val onClockToleranceSeconds: (Long) -> Unit = {},
    /** Trust-decision cache TTL, seconds; 0 disables. */
    val trustDecisionCacheTtlSeconds: Long = 300,
    val onTrustDecisionCacheTtlSeconds: (Long) -> Unit = {},
    /** Connect attempts per engine provider before failover. */
    val engineConnectRetries: Int = 2,
    val onEngineConnectRetries: (Int) -> Unit = {},
    /** The TS11 credential-tier catalog (the F.18 baseline-tier mechanism). */
    val tierCatalogEnabled: Boolean = false,
    val onTierCatalogEnabled: (Boolean) -> Unit = {},
    /** The catalog snapshot's TTL, minutes. */
    val tierCatalogTtlMinutes: Long = 60,
    val onTierCatalogTtlMinutes: (Long) -> Unit = {},
    /** How stale a failed refresh may be before Unavailable, hours. */
    val tierCatalogMaxStaleHours: Long = 24,
    val onTierCatalogMaxStaleHours: (Long) -> Unit = {},
)

/** The Credentials section's extra knobs (consumption policy stays separate). */
data class CredentialExtrasSettings(
    /** vct values handled as blind BBS credentials, one per line. */
    val bbsCredentialTypes: List<String> = emptyList(),
    val onBbsCredentialTypes: (List<String>) -> Unit = {},
    /** TS12 transaction_data handling (moved from the Account card, 2026-11-16). */
    val transactionDataEnabled: Boolean = false,
    val onTransactionDataEnabled: (Boolean) -> Unit = {},
    val onShowTransactionLog: (() -> Unit)? = null,
)

/** The Diagnostics section's knobs (moved out of the Account card + journal cap, 2026-11-16). */
data class DiagnosticsSettings(
    /** Credential-detail visibility on the credential cards. */
    val showCredentialDetails: Boolean = false,
    val onShowCredentialDetails: (Boolean) -> Unit = {},
    /** Diagnostic snackbar messages (the journal's ERROR/INFO feed). */
    val showDiagnosticMessages: Boolean = true,
    val onShowDiagnosticMessages: (Boolean) -> Unit = {},
    /** VEGA proof profiling JSONL diagnostics. */
    val vegaProfilingEnabled: Boolean = false,
    val onVegaProfilingEnabled: (Boolean) -> Unit = {},
    /** The journal's cap (previously a hard-coded 10 - the audit's unexposed knob). */
    val journalMaxEntries: Int = 10,
    val onJournalMaxEntries: (Int) -> Unit = {},
)