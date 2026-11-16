package org.siros.sdk.sample

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

/**
 * The Security & Trust section: reader (RICAL) and issuer (VICAL) trust
 * evaluation, mode-first. The mode dropdown supersedes the deprecated
 * "evaluate locally" boolean - LOCAL_ONLY is what that toggle meant, and
 * the other two modes were previously unreachable from the UI entirely.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TrustSection(settings: TrustSettings) {
    SectionCard(title = "Security & Trust") {
        TrustModeRow(
            label = "Reader trust (RICAL)",
            description = "How proximity-reader trust is evaluated.",
            mode = settings.readerMode,
            onMode = settings.onReaderMode,
        )
        Spacer(modifier = Modifier.height(8.dp))
        OutlinedTextField(
            value = settings.readerRootPem,
            onValueChange = settings.onReaderRootPem,
            label = { Text("RICAL root certificate (PEM)") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = false,
        )
        Spacer(modifier = Modifier.height(16.dp))
        TrustModeRow(
            label = "Issuer trust (VICAL)",
            description = "How attestation-issuer trust is evaluated - independent of reader trust.",
            mode = settings.issuerMode,
            onMode = settings.onIssuerMode,
        )
        Spacer(modifier = Modifier.height(8.dp))
        OutlinedTextField(
            value = settings.issuerRootPem,
            onValueChange = settings.onIssuerRootPem,
            label = { Text("VICAL root certificate (PEM)") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = false,
        )
    }
}

/** One trust-mode dropdown row with its label and description. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TrustModeRow(
    label: String,
    description: String,
    mode: org.siros.sdk.wallet.MdocTrustEvaluationMode,
    onMode: (org.siros.sdk.wallet.MdocTrustEvaluationMode) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    Column {
        Text(label, style = MaterialTheme.typography.bodyLarge)
        Text(
            description,
            style = MaterialTheme.typography.bodySmall,
            color = SirosDesign.secondaryText,
        )
        Spacer(modifier = Modifier.height(4.dp))
        ExposedDropdownMenuBox(
            expanded = expanded,
            onExpandedChange = { expanded = it },
            modifier = Modifier.fillMaxWidth(),
        ) {
            OutlinedTextField(
                value = modeLabel(mode),
                onValueChange = {},
                readOnly = true,
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                modifier = Modifier.menuAnchor().fillMaxWidth(),
            )
            ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                org.siros.sdk.wallet.MdocTrustEvaluationMode.entries.forEach { option ->
                    DropdownMenuItem(
                        text = { Text(modeLabel(option)) },
                        onClick = {
                            onMode(option)
                            expanded = false
                        },
                    )
                }
            }
        }
    }
}

/** A trust mode's human label. */
private fun modeLabel(mode: org.siros.sdk.wallet.MdocTrustEvaluationMode): String =
    when (mode) {
        org.siros.sdk.wallet.MdocTrustEvaluationMode.REMOTE_WITH_LOCAL_FALLBACK ->
            "Remote, fall back to local roots when unreachable"
        org.siros.sdk.wallet.MdocTrustEvaluationMode.REMOTE_ONLY ->
            "Remote only (fail closed)"
        org.siros.sdk.wallet.MdocTrustEvaluationMode.LOCAL_ONLY ->
            "Local roots only (never ask remote)"
    }

/**
 * The Connection section's fine-grained knobs (the backend registry card
 * above it owns the backends themselves; this card holds the per-connection
 * tuning that was previously unreachable from the UI).
 */
@Composable
fun ConnectionTuningSection(settings: ConnectionSettings) {
    var registryUrl by remember(settings.registryUrl) { mutableStateOf(settings.registryUrl) }
    var clockTolerance by remember(settings.clockToleranceSeconds) {
        mutableStateOf(settings.clockToleranceSeconds.toString())
    }
    var trustTtl by remember(settings.trustDecisionCacheTtlSeconds) {
        mutableStateOf(settings.trustDecisionCacheTtlSeconds.toString())
    }
    var retries by remember(settings.engineConnectRetries) {
        mutableStateOf(settings.engineConnectRetries.toString())
    }
    SectionCard(title = "Connection Tuning") {
        OutlinedTextField(
            value = registryUrl,
            onValueChange = {
                registryUrl = it
                settings.onRegistryUrl(it)
            },
            label = { Text("TS11 registry URL (blank = derived)") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
        )
        Spacer(modifier = Modifier.height(8.dp))
        OutlinedTextField(
            value = clockTolerance,
            onValueChange = {
                clockTolerance = it
                it.toLongOrNull()?.let(settings.onClockToleranceSeconds)
            },
            label = { Text("Clock tolerance (seconds)") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
        )
        Spacer(modifier = Modifier.height(8.dp))
        OutlinedTextField(
            value = trustTtl,
            onValueChange = {
                trustTtl = it
                it.toLongOrNull()?.let(settings.onTrustDecisionCacheTtlSeconds)
            },
            label = { Text("Trust decision cache TTL (seconds, 0 = off)") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
        )
        Spacer(modifier = Modifier.height(8.dp))
        OutlinedTextField(
            value = retries,
            onValueChange = {
                retries = it
                it.toIntOrNull()?.let(settings.onEngineConnectRetries)
            },
            label = { Text("Engine connect retries per provider") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
        )
        Spacer(modifier = Modifier.height(16.dp))
        // The TS11 credential-tier catalog (2026-11-16): the baseline
        // key-storage tier at issuance - the F.18 tier-forcing mechanism's
        // driving catalog, previously entirely unexposed
        // (WalletConfig.credentialTierCatalog). ON builds a
        // Ts11CredentialTierCatalog over the registry; the cache windows
        // follow (the snapshot's TTL, and how stale a failed refresh may be
        // before the answer is Unavailable - never trusted indefinitely).
        ToggleRow(
            label = "Credential tier catalog (TS11)",
            description = "Ask the TS11 registry for each credential type's baseline key-storage tier at issuance.",
            checked = settings.tierCatalogEnabled,
            onCheckedChange = settings.onTierCatalogEnabled,
        )
        if (settings.tierCatalogEnabled) {
            var ttl by remember(settings.tierCatalogTtlMinutes) {
                mutableStateOf(settings.tierCatalogTtlMinutes.toString())
            }
            var stale by remember(settings.tierCatalogMaxStaleHours) {
                mutableStateOf(settings.tierCatalogMaxStaleHours.toString())
            }
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = ttl,
                onValueChange = {
                    ttl = it
                    it.toLongOrNull()?.let(settings.onTierCatalogTtlMinutes)
                },
                label = { Text("Snapshot TTL (minutes)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = stale,
                onValueChange = {
                    stale = it
                    it.toLongOrNull()?.let(settings.onTierCatalogMaxStaleHours)
                },
                label = { Text("Max stale after failed refresh (hours)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
        }
    }
}

/**
 * The Credentials section's extras: the BBS blind-credential type list and
 * the TS12 transaction-data handling (moved from the Account card,
 * 2026-11-16 - they are credential-behavior settings, not account facts).
 */
@Composable
fun CredentialExtrasSection(settings: CredentialExtrasSettings) {
    var text by remember(settings.bbsCredentialTypes) {
        mutableStateOf(settings.bbsCredentialTypes.joinToString("\n"))
    }
    SectionCard(title = "Credential Types") {
        Text(
            "Credential types (vct values) handled as blind BBS credentials - " +
                "a deployment decision; one per line. Takes effect at the next " +
                "wallet construction.",
            style = MaterialTheme.typography.bodySmall,
            color = SirosDesign.secondaryText,
        )
        Spacer(modifier = Modifier.height(8.dp))
        OutlinedTextField(
            value = text,
            onValueChange = {
                text = it
                settings.onBbsCredentialTypes(
                    it.lines().map(String::trim).filter(String::isNotEmpty),
                )
            },
            label = { Text("BBS credential types") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = false,
        )
        Spacer(modifier = Modifier.height(16.dp))
        ToggleRow(
            label = "Transaction data (EC TS12 SCA)",
            description = "Handle transaction_data requests in presentations.",
            checked = settings.transactionDataEnabled,
            onCheckedChange = settings.onTransactionDataEnabled,
        )
        settings.onShowTransactionLog?.let { showLog ->
            Spacer(modifier = Modifier.height(8.dp))
            androidx.compose.material3.OutlinedButton(
                onClick = showLog,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Transaction log") }
        }
    }
}

/**
 * The Diagnostics section: the message/diagnostic toggles (moved from the
 * Account card - they are diagnostics, not account facts) and the error
 * journal's cap (previously a hard-coded 10, the audit's one unexposed
 * journal knob). The journal's severity filters (errors/info/all) already
 * live on the journal screen itself.
 */
@Composable
fun DiagnosticsSection(settings: DiagnosticsSettings) {
    var capText by remember(settings.journalMaxEntries) {
        mutableStateOf(settings.journalMaxEntries.toString())
    }
    SectionCard(title = "Diagnostics") {
        ToggleRow(
            label = "Credential details",
            description = "Show the credential's technical details on its card.",
            checked = settings.showCredentialDetails,
            onCheckedChange = settings.onShowCredentialDetails,
        )
        Spacer(modifier = Modifier.height(8.dp))
        ToggleRow(
            label = "Diagnostic messages",
            description = "Snackbar + journal feed for informational events, not just errors.",
            checked = settings.showDiagnosticMessages,
            onCheckedChange = settings.onShowDiagnosticMessages,
        )
        Spacer(modifier = Modifier.height(8.dp))
        ToggleRow(
            label = "VEGA proof profiling",
            description = "prep_prove/prove timing JSONL diagnostics (vega_profiling.jsonl).",
            checked = settings.vegaProfilingEnabled,
            onCheckedChange = settings.onVegaProfilingEnabled,
        )
        Spacer(modifier = Modifier.height(16.dp))
        OutlinedTextField(
            value = capText,
            onValueChange = {
                capText = it
                it.toIntOrNull()?.let(settings.onJournalMaxEntries)
            },
            label = { Text("Error journal capacity (entries)") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
        )
    }
}

/** A label/description/switch row, the section toggles' shared shape. */
@Composable
private fun ToggleRow(
    label: String,
    description: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.bodyLarge)
            Text(
                description,
                style = MaterialTheme.typography.bodySmall,
                color = SirosDesign.secondaryText,
            )
        }
        androidx.compose.material3.Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

/** One titled card, the shared chrome of every settings section. */
@Composable
private fun SectionCard(title: String, content: @Composable () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Column(modifier = Modifier.fillMaxWidth().padding(20.dp)) {
            Text(
                title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                color = SirosDesign.secondaryText,
            )
            Spacer(modifier = Modifier.height(12.dp))
            content()
        }
    }
}
/**
 * The Profiles section (2026-11-16 review): the presentation-behavior
 * profiles - TS12 transaction data today. Its own sub-menu so the
 * credential-policy sections stay about credentials, not flows.
 */
@Composable
fun ProfileSection(
    transactionDataEnabled: Boolean,
    onTransactionDataEnabled: (Boolean) -> Unit,
    onShowTransactionLog: (() -> Unit)?,
) {
    SectionCard(title = "Profiles") {
        Text(
            "How presentations behave per flow - the TS12 transaction-data " +
                "(SCA) profile today.",
            style = MaterialTheme.typography.bodySmall,
            color = SirosDesign.secondaryText,
        )
        Spacer(modifier = Modifier.height(12.dp))
        ToggleRow(
            label = "Transaction data (EC TS12 SCA)",
            description = "Handle transaction_data requests in presentations.",
            checked = transactionDataEnabled,
            onCheckedChange = onTransactionDataEnabled,
        )
        onShowTransactionLog?.let { showLog ->
            Spacer(modifier = Modifier.height(8.dp))
            androidx.compose.material3.OutlinedButton(
                onClick = showLog,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Transaction log") }
        }
    }
}

/**
 * The BBS blind-credential types card (2026-11-16 review: moved from the
 * Credentials section to ZKP & Proofs - which credentials the BBS prover
 * may present is a ZKP-prover concern).
 */
@Composable
fun BbsCredentialTypesCard(
    types: List<String>,
    onTypes: (List<String>) -> Unit,
) {
    var text by remember(types) { mutableStateOf(types.joinToString("\n")) }
    SectionCard(title = "BBS credentials") {
        Text(
            "Credential types (vct values) handled as blind BBS credentials - " +
                "a deployment decision; one per line. Takes effect at the next " +
                "wallet construction.",
            style = MaterialTheme.typography.bodySmall,
            color = SirosDesign.secondaryText,
        )
        Spacer(modifier = Modifier.height(8.dp))
        OutlinedTextField(
            value = text,
            onValueChange = {
                text = it
                onTypes(it.lines().map(String::trim).filter(String::isNotEmpty))
            },
            label = { Text("BBS credential types") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = false,
        )
    }
}
