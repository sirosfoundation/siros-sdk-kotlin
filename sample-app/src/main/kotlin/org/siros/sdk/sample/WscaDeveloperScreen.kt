package org.siros.sdk.sample

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.siros.sdk.credentials.CertificationInfo
import org.siros.sdk.credentials.SignerSecurityProperties
import org.siros.sdk.keystore.DestroyMode
import org.siros.sdk.keystore.DetailedKeyInfo
import org.siros.sdk.keystore.LifecycleState
import org.siros.sdk.keystore.LifecycleStatus
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Developer screen for inspecting and controlling the WSCA/WSCD.
 * In production this would be hidden behind a developer mode gate.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WscaDeveloperScreen(
    lifecycleState: LifecycleState?,
    lifecycleStatus: LifecycleStatus?,
    keys: List<DetailedKeyInfo>,
    keySecurityProps: Map<String, SignerSecurityProperties>,
    selectedPluginId: String,
    r2psServerUrl: String,
    defaultWscdMappingText: String,
    onSelectPlugin: (String) -> Unit,
    onR2psServerUrlChange: (String) -> Unit,
    onDefaultWscdMappingTextChange: (String) -> Unit,
    onEnroll: () -> Unit,
    onRotate: () -> Unit,
    onDestroy: (DestroyMode) -> Unit,
    onRefresh: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("WSCA Developer") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        modifier = modifier,
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(padding)
                .padding(horizontal = 16.dp, vertical = 12.dp),
        ) {
            // ── Build Info ──────────────────────────────────────────
            SectionHeader("Build Info")
            InfoCard {
                InfoRow("App Version", BuildConfig.VERSION_NAME)
                InfoRow("Build Type", BuildConfig.BUILD_TYPE)
                InfoRow("WSCD Manager", "siros-wscd-manager (UniFFI)")
            }

            Spacer(modifier = Modifier.height(16.dp))

            // ── Plugin Selection ────────────────────────────────────
            SectionHeader("Plugin")
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                listOf("softkey", "r2ps", "fido2").forEach { pluginId ->
                    FilterChip(
                        selected = selectedPluginId == pluginId,
                        onClick = { onSelectPlugin(pluginId) },
                        label = { Text(pluginId) },
                    )
                }
            }
            if (selectedPluginId == "r2ps") {
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = r2psServerUrl,
                    onValueChange = onR2psServerUrlChange,
                    label = { Text("R2PS Server URL") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    shape = RoundedCornerShape(12.dp),
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            // ── Default WSCD Mapping (WscdSelectionPolicy dev config) ──
            SectionHeader("Default WSCD Mapping (dev)")
            Text(
                text = "Pre-populates WalletConfig.defaultWscdMapping: one \"issuer|credentialType=pluginId\" " +
                    "entry per line. Lets WscdSelectionPolicy skip the choice dialog for pairs listed here. " +
                    "Host-app/dev config, not persisted across restarts.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = defaultWscdMappingText,
                onValueChange = onDefaultWscdMappingTextChange,
                label = { Text("issuer|credentialType=pluginId (one per line)") },
                modifier = Modifier.fillMaxWidth(),
                minLines = 3,
                shape = RoundedCornerShape(12.dp),
            )

            Spacer(modifier = Modifier.height(16.dp))

            // ── Lifecycle Status ────────────────────────────────────
            SectionHeader("Lifecycle Status")
            InfoCard {
                InfoRow("State", lifecycleState?.name ?: "Not enrolled")
                if (lifecycleStatus != null) {
                    InfoRow("Context ID", lifecycleStatus.contextId)
                    InfoRow("Plugin", lifecycleStatus.pluginId)
                    InfoRow("Factor Kind", lifecycleStatus.factorKind.name)
                    InfoRow("Updated", formatTimestamp(lifecycleStatus.updatedAt))
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // ── Lifecycle Actions ───────────────────────────────────
            Button(
                onClick = onEnroll,
                enabled = lifecycleState == null || lifecycleState == LifecycleState.Destroyed,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
            ) {
                Text("Enroll ($selectedPluginId)")
            }
            Spacer(modifier = Modifier.height(8.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Button(
                    onClick = onRotate,
                    enabled = lifecycleState == LifecycleState.Active,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(12.dp),
                ) {
                    Text("Rotate Keys")
                }
                OutlinedButton(
                    onClick = { onDestroy(DestroyMode.LocalOnly) },
                    enabled = lifecycleState != null && lifecycleState != LifecycleState.Destroyed,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = MaterialTheme.colorScheme.error,
                    ),
                ) {
                    Text("Destroy (Local)")
                }
            }
            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedButton(
                    onClick = { onDestroy(DestroyMode.RemoteRevokeIfSupported) },
                    enabled = lifecycleState != null && lifecycleState != LifecycleState.Destroyed,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = MaterialTheme.colorScheme.error,
                    ),
                ) {
                    Text("Destroy + Revoke")
                }
                OutlinedButton(
                    onClick = onRefresh,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(12.dp),
                ) {
                    Text("Refresh")
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            // ── Keys ────────────────────────────────────────────────
            SectionHeader("Stored Keys (${keys.size})")
            if (keys.isEmpty()) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                ) {
                    Text(
                        text = "No keys stored",
                        modifier = Modifier.padding(16.dp),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            } else {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        keys.forEachIndexed { index, key ->
                            if (index > 0) {
                                HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                            }
                            KeyInfoRow(key, keySecurityProps[key.keyId])
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(32.dp))
        }
    }
}

@Composable
private fun SectionHeader(title: String) {
    Text(
        text = title,
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.SemiBold,
        modifier = Modifier.padding(bottom = 8.dp),
    )
}

@Composable
private fun InfoCard(content: @Composable () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            content()
        }
    }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(modifier = Modifier.width(16.dp))
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium,
        )
    }
}

@Composable
private fun KeyInfoRow(key: DetailedKeyInfo, securityProps: SignerSecurityProperties?) {
    Column {
        Text(
            text = key.keyId,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            maxLines = 1,
        )
        Row(
            modifier = Modifier.fillMaxWidth().padding(top = 2.dp),
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                text = key.algorithm,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.primary,
            )
            Text(
                text = key.pluginId,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.secondary,
            )
            Text(
                text = formatTimestamp(key.createdAt),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (securityProps != null) {
            Spacer(modifier = Modifier.height(4.dp))
            InfoRow("Key Storage", securityProps.keyStorage.joinToString(", "))
            val certText = when (val cert = securityProps.certification) {
                is CertificationInfo.None -> "none"
                is CertificationInfo.Certified -> "${cert.scheme} (${cert.assuranceLevel})"
            }
            InfoRow("Certification", certText)
            if (securityProps.userAuthentication.isNotEmpty()) {
                InfoRow("Auth Methods", securityProps.userAuthentication.joinToString(", "))
            }
            if (securityProps.amr.isNotEmpty()) {
                InfoRow("AMR", securityProps.amr.joinToString(", "))
            }
        }
    }
}

private fun formatTimestamp(epochMs: Long): String {
    if (epochMs == 0L) return "—"
    val sdf = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault())
    return sdf.format(Date(epochMs))
}
