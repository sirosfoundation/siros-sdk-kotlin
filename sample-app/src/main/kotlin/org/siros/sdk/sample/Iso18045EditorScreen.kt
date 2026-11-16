package org.siros.sdk.sample

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.siros.sdk.keystore.Iso18045AssuranceScheme
import org.siros.sdk.keystore.WscdCertificationLevel

/**
 * The editor's working state: the four mapping tables, as the sample app
 * persists them (JSON in the overrides prefs) and materializes them into an
 * [Iso18045AssuranceScheme] for [org.siros.sdk.wallet.WalletConfig.wscdAssuranceScheme]
 * at wallet construction. Defaults = the SDK's own documented defaults, so
 * "Reset" is a return to the ecosystem baseline, never an invention.
 *
 * DEMO-ONLY by design: a production deployment fixes the scheme at
 * integration time and exposes no editor at all - the mappings are policy,
 * not preference. This type exists so the sample app can demonstrate the
 * mechanism live.
 */
@kotlinx.serialization.Serializable
data class Iso18045EditorState(
    val certificationLevelLabels: Map<org.siros.sdk.keystore.WscdCertificationLevel, String> =
        Iso18045AssuranceScheme.DEFAULT_CERTIFICATION_LEVEL_LABELS,
    val keyStorageTypeLabels: Map<String, String> = Iso18045AssuranceScheme.DEFAULT_KEY_STORAGE_TYPE_LABELS,
    val nominalPluginLabels: Map<String, String> = Iso18045AssuranceScheme.DEFAULT_NOMINAL_PLUGIN_LABELS,
    val tierOrder: List<String> = Iso18045AssuranceScheme.DEFAULT_TIER_ORDER,
) {
    /** Materializes the edited tables into a scheme instance for WalletConfig. */
    fun toScheme(): Iso18045AssuranceScheme = Iso18045AssuranceScheme(
        certificationLevelLabels = certificationLevelLabels,
        keyStorageTypeLabels = keyStorageTypeLabels,
        nominalPluginLabels = nominalPluginLabels,
        tierOrder = tierOrder,
    )

    companion object {
        /** The OID4VCI-registered wire vocabulary - the only legal label values. */
        val WIRE_LABELS: List<String> = listOf(
            Iso18045AssuranceScheme.BASIC,
            Iso18045AssuranceScheme.ENHANCED_BASIC,
            Iso18045AssuranceScheme.MODERATE,
            Iso18045AssuranceScheme.HIGH,
        )
    }
}

/**
 * The ISO 18045 assurance-scheme editor - a DEMO TOOL, deliberately.
 *
 * The scheme's four mapping tables (which label a certification level /
 * key-storage type / plugin id maps to, and in which order the tiers rank)
 * are POLICY choices of the ecosystem a deployment runs in, never a user
 * preference: a production deployment constructs its instance at
 * integration time (WalletConfig.wscdAssuranceScheme) and exposes nothing
 * here. This screen exists so a demonstrator can show the mechanism -
 * override a label, re-map a plugin, reorder the tiers - live on a device,
 * then see the selection policy follow.
 *
 * Native M3 patterns throughout: ExposedDropdownMenuBox for the fixed
 * vocabularies (certification levels, wire labels), radio rows for
 * ordered picks, list-editing rows for the open-ended maps (plugin ids).
 * No free text where a menu can name the legal values; free text only
 * where the vocabulary is open (a plugin id string).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun Iso18045EditorScreen(
    state: Iso18045EditorState,
    onUpdate: (Iso18045EditorState) -> Unit,
    onBack: () -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("ISO 18045 assurance scheme") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    TextButton(onClick = { onUpdate(Iso18045EditorState()) }) { Text("Reset") }
                },
            )
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxWidth().padding(padding).padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            item {
                Text(
                    "Demo tool: re-map the scheme a deployment would fix at integration time " +
                        "(WalletConfig.wscdAssuranceScheme). The WSCD selection policy re-evaluates " +
                        "on the next issuance.",
                    style = MaterialTheme.typography.bodySmall,
                    color = SirosDesign.secondaryText,
                )
            }

            // ── Tier order: the four wire labels, ranked ──────────────────
            item {
                SectionCard(title = "Tier order (ascending)") {
                    Text(
                        "Which label satisfies which - drag is not needed: the wire vocabulary " +
                            "is four fixed labels, so the order is a permutation pick. Tap a " +
                            "label to pick the next position.",
                        style = MaterialTheme.typography.bodySmall,
                        color = SirosDesign.secondaryText,
                    )
                    TierOrderBuilder(
                        placed = state.tierOrder,
                        remaining = Iso18045EditorState.WIRE_LABELS.filter { it !in state.tierOrder },
                        onAppend = { label ->
                            onUpdate(state.copy(tierOrder = state.tierOrder + label))
                        },
                        onRemoveAt = { idx ->
                            onUpdate(state.copy(tierOrder = state.tierOrder.filterIndexed { i, _ -> i != idx }))
                        },
                    )
                }
            }

            // ── Certification level labels ─────────────────────────────────
            item {
                SectionCard(title = "Certification level labels") {
                    WscdCertificationLevel.entries.forEach { level ->
                        LabelDropdownRow(
                            label = level.name.lowercase().replace('_', ' '),
                            value = state.certificationLevelLabels[level] ?: "",
                            options = Iso18045EditorState.WIRE_LABELS,
                            onValueChange = {
                                onUpdate(
                                    state.copy(
                                        certificationLevelLabels =
                                            state.certificationLevelLabels + (level to it),
                                    ),
                                )
                            },
                        )
                    }
                }
            }

            // ── Key-storage type labels ───────────────────────────────────
            item {
                SectionCard(title = "Key-storage type labels") {
                    state.keyStorageTypeLabels.entries.toList().forEach { (raw, label) ->
                        MapEntryRow(
                            key = raw,
                            value = label,
                            valueOptions = Iso18045EditorState.WIRE_LABELS,
                            onValueChange = { newLabel ->
                                onUpdate(
                                    state.copy(
                                        keyStorageTypeLabels =
                                            state.keyStorageTypeLabels + (raw to newLabel),
                                    ),
                                )
                            },
                            onRemove = {
                                onUpdate(
                                    state.copy(
                                        keyStorageTypeLabels =
                                            state.keyStorageTypeLabels - raw,
                                    ),
                                )
                            },
                        )
                    }
                    var newRaw by remember(state.keyStorageTypeLabels.size) { mutableStateOf("") }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        OutlinedTextField(
                            value = newRaw,
                            onValueChange = { newRaw = it },
                            label = { Text("Add key-storage type (raw)") },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                        )
                        IconButton(
                            enabled = newRaw.isNotBlank(),
                            onClick = {
                                onUpdate(
                                    state.copy(
                                        keyStorageTypeLabels = state.keyStorageTypeLabels +
                                            (newRaw.trim() to Iso18045AssuranceScheme.BASIC),
                                    ),
                                )
                                newRaw = ""
                            },
                        ) { Icon(Icons.Filled.Add, contentDescription = "Add") }
                    }
                }
            }

            // ── Nominal plugin labels ─────────────────────────────────────
            item {
                SectionCard(title = "Nominal plugin labels") {
                    Text(
                        "The a-priori label per plugin id - what the selection policy " +
                            "assumes BEFORE any key exists.",
                        style = MaterialTheme.typography.bodySmall,
                        color = SirosDesign.secondaryText,
                    )
                    state.nominalPluginLabels.entries.toList().forEach { (plugin, label) ->
                        MapEntryRow(
                            key = plugin,
                            value = label,
                            valueOptions = Iso18045EditorState.WIRE_LABELS,
                            onValueChange = { newLabel ->
                                onUpdate(
                                    state.copy(
                                        nominalPluginLabels =
                                            state.nominalPluginLabels + (plugin to newLabel),
                                    ),
                                )
                            },
                            onRemove = {
                                onUpdate(
                                    state.copy(
                                        nominalPluginLabels = state.nominalPluginLabels - plugin,
                                    ),
                                )
                            },
                        )
                    }
                    var newPlugin by remember(state.nominalPluginLabels.size) { mutableStateOf("") }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        OutlinedTextField(
                            value = newPlugin,
                            onValueChange = { newPlugin = it },
                            label = { Text("Add plugin id") },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                        )
                        IconButton(
                            enabled = newPlugin.isNotBlank(),
                            onClick = {
                                onUpdate(
                                    state.copy(
                                        nominalPluginLabels = state.nominalPluginLabels +
                                            (newPlugin.trim() to Iso18045AssuranceScheme.BASIC),
                                    ),
                                )
                                newPlugin = ""
                            },
                        ) { Icon(Icons.Filled.Add, contentDescription = "Add") }
                    }
                }
            }

            item { Spacer(modifier = Modifier.height(32.dp)) }
        }
    }
}

/** One titled card, the screen's every section's chrome. */
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
 * The tier-order picker: the labels NOT yet placed, each tappable to
 * append; the placed list, each removable. Native radio semantics without
 * the radio chrome (order, not single choice).
 */
@Composable
private fun TierOrderBuilder(
    placed: List<String>,
    remaining: List<String>,
    onAppend: (String) -> Unit,
    onRemoveAt: (Int) -> Unit,
) {
    Column {
        Text("Placed:", style = MaterialTheme.typography.bodySmall, color = SirosDesign.secondaryText)
        placed.forEachIndexed { index, label ->
            Row(
                modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    "${index + 1}. $label",
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.weight(1f),
                )
                IconButton(onClick = { onRemoveAt(index) }) {
                    Icon(Icons.Filled.Delete, contentDescription = "Remove $label")
                }
            }
        }
        if (remaining.isNotEmpty()) {
            Text("Pick next:", style = MaterialTheme.typography.bodySmall, color = SirosDesign.secondaryText)
            remaining.forEach { label ->
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(selected = false, onClick = { onAppend(label) })
                    Text(label, style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
    }
}

/** A label row whose value is one of the fixed wire labels - a dropdown. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun LabelDropdownRow(
    label: String,
    value: String,
    options: List<String>,
    onValueChange: (String) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        ExposedDropdownMenuBox(
            expanded = expanded,
            onExpandedChange = { expanded = it },
            modifier = Modifier.weight(1f),
        ) {
            OutlinedTextField(
                value = value,
                onValueChange = {},
                readOnly = true,
                label = { Text("tier") },
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                modifier = Modifier.menuAnchor().fillMaxWidth(),
            )
            ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                options.forEach { option ->
                    DropdownMenuItem(
                        text = { Text(option) },
                        onClick = {
                            onValueChange(option)
                            expanded = false
                        },
                    )
                }
            }
        }
    }
}

/** One open- keyed map entry: free-text key, dropdown value, delete. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MapEntryRow(
    key: String,
    value: String,
    valueOptions: List<String>,
    onValueChange: (String) -> Unit,
    onRemove: () -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            key,
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.weight(1.2f),
        )
        ExposedDropdownMenuBox(
            expanded = expanded,
            onExpandedChange = { expanded = it },
            modifier = Modifier.weight(1.8f),
        ) {
            OutlinedTextField(
                value = value,
                onValueChange = {},
                readOnly = true,
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                modifier = Modifier.menuAnchor().fillMaxWidth(),
            )
            ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                valueOptions.forEach { option ->
                    DropdownMenuItem(
                        text = { Text(option) },
                        onClick = {
                            onValueChange(option)
                            expanded = false
                        },
                    )
                }
            }
        }
        IconButton(onClick = onRemove) {
            Icon(Icons.Filled.Delete, contentDescription = "Remove $key")
        }
    }
}