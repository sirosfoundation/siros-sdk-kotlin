package org.siros.sdk.sample

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.siros.sdk.credentials.CertificationInfo
import org.siros.sdk.credentials.SignerSecurityProperties
import org.siros.sdk.credentials.Ts11DiscoveredCredential
import org.siros.sdk.keystore.DetailedKeyInfo
import org.siros.sdk.keystore.LifecycleState
import org.siros.sdk.keystore.LifecycleStatus
import org.siros.sdk.keystore.WscdPluginCapabilities
import uniffi.siros_wscd_manager.wscdManagerVersion
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** The three WSCD plugin IDs `FfiWscdConfig.defaultPlugin` knows about - one tab each. */
private val WSCD_PLUGIN_IDS = listOf("softkey", "r2ps", "fido2")

/**
 * Single consolidated WSCD settings screen, replacing the old split between
 * a standalone "WSCA Developer" screen and the three separate WSCD cards
 * that used to live in [MainActivity]'s Settings tab (WSCD Choices/TOFU,
 * Preferred WSCD, WSCD Overrides, WSCD Lifecycle + two Enroll buttons - see
 * this repo's Phase 3 settings-consolidation plan). Two parts:
 *
 * - A **common section** (always visible, shown once, above the tabs): the
 *   [WscdMappingCard] (the single global per-(issuer, credentialType) ->
 *   plugin ID resolution table, combined with TS11 registry discovery into
 *   one enable/disable list) and the [TofuCard] (the single global
 *   auto-remembered TOFU choices table). Neither is actually scoped to one
 *   plugin (see each card's own doc comment for why) - showing them 3x
 *   identically, once per plugin tab, was a mistake in this repo's Phase 3
 *   consolidation pass, not a deliberate design.
 * - A **plugin-specific sub-group** below the common section: one tab per
 *   plugin ([WSCD_PLUGIN_IDS]), each with a "Preferred WSCD" toggle for that
 *   plugin and a collapsible "Developer" section (collapsed by default:
 *   transport config, lifecycle actions (Enroll/Rotate/Destroy/Refresh),
 *   Stored Keys, and Build Info - everything the old standalone WSCA
 *   Developer screen had, genuinely plugin-specific).
 *
 * There is deliberately only one Enroll action across the whole app now (it
 * lives in the Developer section, since it's a diagnostic/test action
 * rather than something an end user taps routinely) and only one Destroy
 * action/confirmation dialog (see [showDestroyConfirm] below) - both were
 * previously duplicated between the standalone dev screen and Settings.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WscdScreen(
    lifecycleState: LifecycleState?,
    lifecycleStatus: LifecycleStatus?,
    keys: List<DetailedKeyInfo>,
    keySecurityProps: Map<String, SignerSecurityProperties>,
    selectedPluginId: String,
    r2psServerUrl: String,
    defaultWscdMappingText: String,
    fido2TransportMode: Fido2TransportMode,
    wscdLifecycleBusy: Boolean,
    wscdGlobalOverride: String?,
    wscdUserOverrides: Map<String, String>,
    wscdTofuMapping: Map<String, String>,
    ts11DiscoveredCredentials: List<Ts11DiscoveredCredential>,
    ts11DiscoveryInProgress: Boolean,
    onSelectPlugin: (String) -> Unit,
    onSelectFido2TransportMode: (Fido2TransportMode) -> Unit,
    onR2psServerUrlChange: (String) -> Unit,
    onDefaultWscdMappingTextChange: (String) -> Unit,
    onEnroll: () -> Unit,
    onRotate: () -> Unit,
    onDestroy: () -> Unit,
    onRefresh: () -> Unit,
    onSetWscdGlobalOverride: (String?) -> Unit,
    onSetWscdUserOverride: (issuer: String, credentialType: String, pluginId: String) -> Unit,
    onClearWscdUserOverride: (issuer: String, credentialType: String) -> Unit,
    onForgetWscdTofuMapping: (issuer: String, credentialType: String) -> Unit,
    onForgetAllWscdTofuMapping: () -> Unit,
    onDiscoverTs11Schemas: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    // Confirmation gate - destroying a WSCD key is not reversible. There's
    // only one Destroy action; whether that also revokes anything server-side
    // is up to the active plugin's own destroy_lifecycle hook (fido2 has no
    // remote to revoke; r2ps does), not a choice made here.
    var showDestroyConfirm by remember { mutableStateOf(false) }
    if (showDestroyConfirm) {
        AlertDialog(
            onDismissRequest = { showDestroyConfirm = false },
            title = { Text("Destroy this key?") },
            text = {
                Text(
                    "This permanently destroys the enrolled key and any keys derived from " +
                        "it, locally and on the backend if the active plugin supports remote " +
                        "revocation. This cannot be undone.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    onDestroy()
                    showDestroyConfirm = false
                }) {
                    Text("Destroy", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { showDestroyConfirm = false }) { Text("Cancel") }
            },
        )
    }

    val selectedTabIndex = WSCD_PLUGIN_IDS.indexOf(selectedPluginId).coerceAtLeast(0)

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("WSCD Settings") },
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
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 12.dp),
        ) {
            // ── Common section (always visible, shown once, above the
            // tabs): neither of these is scoped to one plugin - see each
            // card's own doc comment.
            WscdMappingCard(
                defaultWscdMappingText = defaultWscdMappingText,
                wscdUserOverrides = wscdUserOverrides,
                ts11Discovered = ts11DiscoveredCredentials,
                ts11InProgress = ts11DiscoveryInProgress,
                onDiscover = onDiscoverTs11Schemas,
                onSetWscdUserOverride = onSetWscdUserOverride,
                onClearWscdUserOverride = onClearWscdUserOverride,
                onDefaultWscdMappingTextChange = onDefaultWscdMappingTextChange,
            )
            Spacer(modifier = Modifier.height(16.dp))

            TofuCard(wscdTofuMapping, onForgetWscdTofuMapping, onForgetAllWscdTofuMapping)
            Spacer(modifier = Modifier.height(24.dp))

            // ── Plugin-specific sub-group: genuinely per-plugin settings only ──
            HorizontalDivider(modifier = Modifier.padding(bottom = 8.dp))
            Text(
                "WSCD Plugin",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.padding(bottom = 8.dp),
            )
            TabRow(selectedTabIndex = selectedTabIndex) {
                WSCD_PLUGIN_IDS.forEachIndexed { index, pluginId ->
                    Tab(
                        selected = selectedTabIndex == index,
                        onClick = { onSelectPlugin(pluginId) },
                        text = { Text(pluginId) },
                    )
                }
            }
            Spacer(modifier = Modifier.height(12.dp))

            PluginSpecificSection(
                pluginId = selectedPluginId,
                lifecycleState = lifecycleState,
                lifecycleStatus = lifecycleStatus,
                keys = keys,
                keySecurityProps = keySecurityProps,
                r2psServerUrl = r2psServerUrl,
                defaultWscdMappingText = defaultWscdMappingText,
                fido2TransportMode = fido2TransportMode,
                wscdLifecycleBusy = wscdLifecycleBusy,
                wscdGlobalOverride = wscdGlobalOverride,
                onSelectFido2TransportMode = onSelectFido2TransportMode,
                onR2psServerUrlChange = onR2psServerUrlChange,
                onDefaultWscdMappingTextChange = onDefaultWscdMappingTextChange,
                onEnroll = onEnroll,
                onRotate = onRotate,
                onRequestDestroy = { showDestroyConfirm = true },
                onRefresh = onRefresh,
                onSetWscdGlobalOverride = onSetWscdGlobalOverride,
            )
            Spacer(modifier = Modifier.height(32.dp))
        }
    }
}

/**
 * One plugin tab's genuinely plugin-specific content: the "Preferred WSCD"
 * toggle, then the collapsible Developer section - the Mapping/TOFU/TS11
 * Discovery cards that used to live here too were hoisted out to
 * [WscdScreen]'s common section (see that function's doc comment for why).
 */
@Composable
private fun PluginSpecificSection(
    pluginId: String,
    lifecycleState: LifecycleState?,
    lifecycleStatus: LifecycleStatus?,
    keys: List<DetailedKeyInfo>,
    keySecurityProps: Map<String, SignerSecurityProperties>,
    r2psServerUrl: String,
    defaultWscdMappingText: String,
    fido2TransportMode: Fido2TransportMode,
    wscdLifecycleBusy: Boolean,
    wscdGlobalOverride: String?,
    onSelectFido2TransportMode: (Fido2TransportMode) -> Unit,
    onR2psServerUrlChange: (String) -> Unit,
    onDefaultWscdMappingTextChange: (String) -> Unit,
    onEnroll: () -> Unit,
    onRotate: () -> Unit,
    onRequestDestroy: () -> Unit,
    onRefresh: () -> Unit,
    onSetWscdGlobalOverride: (String?) -> Unit,
) {
    // ── User-facing section (always visible) ────────────────────────

    PreferredWscdCard(pluginId, wscdGlobalOverride, onSetWscdGlobalOverride)
    Spacer(modifier = Modifier.height(24.dp))

    // ── Developer section (collapsed by default) ────────────────────

    var developerExpanded by rememberSaveable(pluginId) { mutableStateOf(false) }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { developerExpanded = !developerExpanded }
            .padding(vertical = 8.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            "Developer",
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.SemiBold,
        )
        Icon(
            if (developerExpanded) Icons.Filled.KeyboardArrowUp else Icons.Filled.KeyboardArrowDown,
            contentDescription = if (developerExpanded) "Collapse" else "Expand",
        )
    }
    if (developerExpanded) {
        HorizontalDivider(modifier = Modifier.padding(bottom = 12.dp))
        DeveloperSection(
            pluginId = pluginId,
            lifecycleState = lifecycleState,
            lifecycleStatus = lifecycleStatus,
            keys = keys,
            keySecurityProps = keySecurityProps,
            r2psServerUrl = r2psServerUrl,
            defaultWscdMappingText = defaultWscdMappingText,
            fido2TransportMode = fido2TransportMode,
            wscdLifecycleBusy = wscdLifecycleBusy,
            onSelectFido2TransportMode = onSelectFido2TransportMode,
            onR2psServerUrlChange = onR2psServerUrlChange,
            onDefaultWscdMappingTextChange = onDefaultWscdMappingTextChange,
            onEnroll = onEnroll,
            onRotate = onRotate,
            onRequestDestroy = onRequestDestroy,
            onRefresh = onRefresh,
        )
    }
}

/**
 * "Always use this WSCD, even for credentials that don't require it" -
 * consolidates the old Settings tab's multi-option "Preferred WSCD" radio
 * group into a single per-plugin toggle, since each tab now already IS one
 * plugin (see this file's class doc comment / this repo's Phase 3 plan for
 * why [selectedPluginId]/[wscdGlobalOverride] are being unified). Turning
 * this ON makes [pluginId] the sole global override (any other plugin
 * previously preferred is implicitly replaced, matching
 * `WscdSelectionPolicy.setGlobalUserOverride`'s "one value" semantics);
 * turning it OFF clears the override entirely (only meaningful when this
 * plugin IS the current override).
 */
@Composable
private fun PreferredWscdCard(
    pluginId: String,
    wscdGlobalOverride: String?,
    onSetWscdGlobalOverride: (String?) -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp)) {
        Column(modifier = Modifier.fillMaxWidth().padding(20.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        "Preferred WSCD",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        "Always use $pluginId, even for credentials that don't require it. " +
                            "Applies to every issuer unless a per-issuer override below takes precedence.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Switch(
                    checked = wscdGlobalOverride == pluginId,
                    onCheckedChange = { checked ->
                        onSetWscdGlobalOverride(if (checked) pluginId else null)
                    },
                )
            }
        }
    }
}

/**
 * The single global per-(issuer, credentialType) -> plugin ID mapping,
 * combined with TS11 registry discovery in one widget (an earlier version
 * kept these as two separate cards - a "Discover" card whose "Add"/"Add
 * all" actions fed into a completely separate "Mapping" card - which meant
 * hitting "Add" gave no visible feedback: the entry didn't disappear from
 * Discovery, and you had to scroll to a different card to confirm it
 * landed). One list now, with a per-row Switch instead of an add/delete
 * asymmetry:
 * - A row for every TS11-discovered credential (see [Ts11CredentialDiscovery])
 *   is STICKY - it stays in the list once discovered regardless of the
 *   switch's state, since [ts11Discovered] is independent of whether that
 *   credential is currently mapped. Flipping the switch on/off just calls
 *   [onSetWscdUserOverride]/[onClearWscdUserOverride] for that identifier
 *   (using the cheapest-sufficient plugin from [bestPluginFor]) - "Add" from
 *   the old Discovery card is now just switching a row on.
 * - A row for every [wscdUserOverrides] entry not already shown as a
 *   discovered row (i.e. a manually-added override via [OverrideDialog],
 *   or one mapped for an issuer other than the wildcard discovery uses) -
 *   these aren't sticky, so switching one off removes its row (same as the
 *   old delete button, just via the same Switch control for consistency).
 * - A row for every [defaultWscdMappingText] ("dev default") entry not
 *   already covered above - likewise not sticky; edited in bulk via the
 *   free-text box in each plugin tab's Developer section.
 *
 * Shown once, in [WscdScreen]'s common section above the plugin tabs - this
 * is a single global resolution table, not something scoped to any one
 * plugin, so an earlier version of this screen that showed three identical
 * copies of it (one per tab, each filtered to that tab's plugin) was wrong.
 *
 * NOTE: a TS11 schema entry has no issuer of its own (it describes a
 * credential *type*, not an (issuer, credentialType) pair), so discovered
 * rows are mapped using [WscdSelectionPolicy.WILDCARD_ISSUER] (`*`) - "use
 * this plugin for this credential type, regardless of issuer" -
 * `WscdSelectionPolicy.resolve` explicitly interprets that placeholder as a
 * fallback when no issuer-specific entry matches, so switching a discovered
 * row on resolves end-to-end immediately, not just as a hand-edit starting
 * point. A real per-plugin reshape (see this repo's Phase 4 plan) can
 * eventually replace this with real per-issuer TS11 data, but the wildcard
 * is a genuine resolution mechanism in the meantime, not a stopgap.
 */
@Composable
private fun WscdMappingCard(
    defaultWscdMappingText: String,
    wscdUserOverrides: Map<String, String>,
    ts11Discovered: List<Ts11DiscoveredCredential>,
    ts11InProgress: Boolean,
    onDiscover: () -> Unit,
    onSetWscdUserOverride: (issuer: String, credentialType: String, pluginId: String) -> Unit,
    onClearWscdUserOverride: (issuer: String, credentialType: String) -> Unit,
    onDefaultWscdMappingTextChange: (String) -> Unit,
) {
    val devDefaults = remember(defaultWscdMappingText) { parseWscdMappingText(defaultWscdMappingText) }
    var editing by remember { mutableStateOf<EditingOverride?>(null) }

    // identifier -> (discovered credential, cheapest-sufficient plugin) -
    // credentials with no plugin able to satisfy their tier are dropped
    // (nothing to offer a switch for).
    val discoveredByIdentifier = remember(ts11Discovered) {
        ts11Discovered.mapNotNull { dc ->
            dc.schema.attestationLoS?.let { bestPluginFor(it) }?.let { plugin -> dc.identifier to (dc to plugin) }
        }.toMap()
    }
    val discoveredKeys = remember(discoveredByIdentifier) { discoveredByIdentifier.keys.map { "*|$it" }.toSet() }

    editing?.let { e ->
        OverrideDialog(
            isNew = e.originalKey == null,
            initialIssuer = e.issuer,
            initialCredentialType = e.credentialType,
            initialPluginId = e.pluginId,
            onDismiss = { editing = null },
            onSave = { issuer, credentialType, pluginId ->
                val newKey = "$issuer|$credentialType"
                if (e.backedByText) {
                    onDefaultWscdMappingTextChange(updateWscdMappingTextEntry(defaultWscdMappingText, e.originalKey, newKey, pluginId))
                } else {
                    if (e.originalKey != null && e.originalKey != newKey) {
                        val (oldIssuer, oldCredentialType) = splitMappingKey(e.originalKey)
                        onClearWscdUserOverride(oldIssuer, oldCredentialType)
                    }
                    onSetWscdUserOverride(issuer, credentialType, pluginId)
                }
                editing = null
            },
        )
    }

    Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp)) {
        Column(modifier = Modifier.fillMaxWidth().padding(20.dp)) {
            Text(
                "Mapping & Discovery",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                "Which (issuer, credential type) pairs always use a specific WSCD plugin. " +
                    "Discover candidates from registry.siros.org, then switch the ones you want " +
                    "on - each is assigned to the cheapest plugin whose tier satisfies it (e.g. " +
                    "iso_18045_basic → softkey, not fido2). Tap the pencil to edit a row's issuer, " +
                    "credential type, or target plugin.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedButton(onClick = onDiscover, enabled = !ts11InProgress, modifier = Modifier.fillMaxWidth()) {
                if (ts11InProgress) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                    Spacer(modifier = Modifier.width(8.dp))
                }
                Text("Discover from TS11 Registry")
            }
            Spacer(modifier = Modifier.height(8.dp))

            val savedOnly = wscdUserOverrides.keys.filterNot { it in discoveredKeys }
            val devDefaultOnly = devDefaults.keys.filterNot { it in discoveredKeys }
            if (discoveredByIdentifier.isEmpty() && savedOnly.isEmpty() && devDefaultOnly.isEmpty()) {
                Text(
                    "No mapping entries yet",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                discoveredByIdentifier.entries.sortedBy { it.key }.forEach { (identifier, pair) ->
                    val (dc, plugin) = pair
                    val key = "*|$identifier"
                    // If this row was already turned on with custom values
                    // (a different issuer/plugin than the wildcard default),
                    // editing should reflect what's actually saved, not the
                    // raw discovery suggestion.
                    val effectivePlugin = wscdUserOverrides[key] ?: plugin
                    MappingRow(
                        title = dc.displayName,
                        subtitle = dc.description ?: "*  (any issuer - discovered)",
                        technical = "${dc.schema.attestationLoS} → $effectivePlugin · $identifier",
                        technicalColor = MaterialTheme.colorScheme.tertiary,
                        isOn = key in wscdUserOverrides,
                        onToggle = { checked ->
                            if (checked) onSetWscdUserOverride("*", identifier, plugin)
                            else onClearWscdUserOverride("*", identifier)
                        },
                        onEdit = {
                            editing = EditingOverride(
                                backedByText = false,
                                originalKey = if (key in wscdUserOverrides) key else null,
                                issuer = "*",
                                credentialType = identifier,
                                pluginId = effectivePlugin,
                            )
                        },
                    )
                }
                savedOnly.sorted().forEach { key ->
                    val (issuer, credentialType) = splitMappingKey(key)
                    MappingRow(
                        title = credentialType,
                        subtitle = issuer,
                        technical = "Saved · → ${wscdUserOverrides.getValue(key)}",
                        technicalColor = MaterialTheme.colorScheme.primary,
                        isOn = true,
                        onToggle = { checked -> if (!checked) onClearWscdUserOverride(issuer, credentialType) },
                        onEdit = {
                            editing = EditingOverride(
                                backedByText = false,
                                originalKey = key,
                                issuer = issuer,
                                credentialType = credentialType,
                                pluginId = wscdUserOverrides.getValue(key),
                            )
                        },
                    )
                }
                devDefaultOnly.sorted().forEach { key ->
                    val (issuer, credentialType) = splitMappingKey(key)
                    MappingRow(
                        title = credentialType,
                        subtitle = issuer,
                        technical = "Dev default · → ${devDefaults.getValue(key)}",
                        technicalColor = MaterialTheme.colorScheme.secondary,
                        isOn = true,
                        onToggle = { checked ->
                            if (!checked) onDefaultWscdMappingTextChange(removeFromWscdMappingText(defaultWscdMappingText, key))
                        },
                        onEdit = {
                            editing = EditingOverride(
                                backedByText = true,
                                originalKey = key,
                                issuer = issuer,
                                credentialType = credentialType,
                                pluginId = devDefaults.getValue(key),
                            )
                        },
                    )
                }
            }
            Spacer(modifier = Modifier.height(12.dp))
            OutlinedButton(
                onClick = {
                    editing = EditingOverride(
                        backedByText = false,
                        originalKey = null,
                        issuer = "",
                        credentialType = "",
                        pluginId = WSCD_PLUGIN_IDS.first(),
                    )
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Add override")
            }
        }
    }
}

/**
 * State for [OverrideDialog] when it's editing (or adding) a mapping entry -
 * see [WscdMappingCard]'s per-row `onEdit` call sites for how each origin
 * (discovered/saved/dev-default) constructs this.
 *
 * @property backedByText true for a "dev default" row (rewrites
 *   [WscdMappingCard]'s free-text box via [updateWscdMappingTextEntry]);
 *   false for a discovered/saved row (goes through the real
 *   `onSetWscdUserOverride`/`onClearWscdUserOverride` calls).
 * @property originalKey the `"issuer|credentialType"` key this entry is
 *   currently stored under, or `null` when adding a brand-new entry (or
 *   editing a discovered row that hasn't been switched on yet, so there's
 *   nothing existing to remove first).
 */
private data class EditingOverride(
    val backedByText: Boolean,
    val originalKey: String?,
    val issuer: String,
    val credentialType: String,
    val pluginId: String,
)

/**
 * One mapping/discovery entry: a primary label, a secondary detail line, a
 * small-caps technical line, and trailing edit/[Switch] controls - see
 * [WscdMappingCard]'s doc comment for what "on"/"off" means for each row
 * origin (sticky discovered rows vs. removable saved/dev-default ones).
 */
@Composable
private fun MappingRow(
    title: String,
    subtitle: String,
    technical: String,
    technicalColor: androidx.compose.ui.graphics.Color,
    isOn: Boolean,
    onToggle: (Boolean) -> Unit,
    onEdit: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyMedium)
            Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(
                technical,
                style = MaterialTheme.typography.labelSmall,
                color = technicalColor,
                fontWeight = FontWeight.SemiBold,
            )
        }
        IconButton(onClick = onEdit, modifier = Modifier.size(32.dp)) {
            Icon(Icons.Default.Edit, contentDescription = "Edit this mapping", modifier = Modifier.size(16.dp))
        }
        Switch(checked = isOn, onCheckedChange = onToggle)
    }
}

/**
 * Modal "Add or edit a mapping entry" flow - a small `AlertDialog` rather
 * than an always-inline form, so it reads clearly as a distinct action
 * instead of blending into the mapping list above it. Shared by
 * [WscdMappingCard]'s "Add override" button (fields start empty) and every
 * row's edit action (fields pre-filled from [EditingOverride]).
 */
@Composable
private fun OverrideDialog(
    isNew: Boolean,
    initialIssuer: String,
    initialCredentialType: String,
    initialPluginId: String,
    onDismiss: () -> Unit,
    onSave: (issuer: String, credentialType: String, pluginId: String) -> Unit,
) {
    var issuer by remember { mutableStateOf(initialIssuer) }
    var credentialType by remember { mutableStateOf(initialCredentialType) }
    var selectedPlugin by remember { mutableStateOf(initialPluginId) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (isNew) "Add override" else "Edit override") },
        text = {
            Column {
                OutlinedTextField(
                    value = issuer,
                    onValueChange = { issuer = it },
                    label = { Text("Issuer URL") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    shape = RoundedCornerShape(8.dp),
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = credentialType,
                    onValueChange = { credentialType = it },
                    label = { Text("Credential type (vct/doctype)") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    shape = RoundedCornerShape(8.dp),
                )
                Spacer(modifier = Modifier.height(12.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    WSCD_PLUGIN_IDS.forEach { id ->
                        androidx.compose.material3.FilterChip(
                            selected = selectedPlugin == id,
                            onClick = { selectedPlugin = id },
                            label = { Text(id) },
                        )
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = { onSave(issuer.trim(), credentialType.trim(), selectedPlugin) },
                enabled = issuer.isNotBlank() && credentialType.isNotBlank(),
            ) { Text(if (isNew) "Add" else "Save") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

/**
 * The single global auto-remembered trust-on-first-use choices (see
 * `WscdSelectionPolicy`'s doc comment) - same `"issuer|credentialType"` ->
 * plugin ID shape as [MappingCard]'s data, and, like that card, not scoped
 * to any one plugin, so it's shown once here in [WscdScreen]'s common
 * section rather than filtered per tab.
 */
@Composable
private fun TofuCard(
    wscdTofuMapping: Map<String, String>,
    onForgetWscdTofuMapping: (issuer: String, credentialType: String) -> Unit,
    onForgetAllWscdTofuMapping: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp)) {
        Column(modifier = Modifier.fillMaxWidth().padding(20.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    "WSCD Choices",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (wscdTofuMapping.isNotEmpty()) {
                    TextButton(onClick = onForgetAllWscdTofuMapping) {
                        Text("Forget All")
                    }
                }
            }
            Text(
                "Ambiguous-choice outcomes remembered per (issuer, credential type), so you're only " +
                    "asked once. Forget a choice to be asked again next time.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(modifier = Modifier.height(8.dp))
            if (wscdTofuMapping.isEmpty()) {
                Text(
                    "No WSCD choices remembered yet",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                wscdTofuMapping.keys.sorted().forEach { key ->
                    val (issuer, credentialType) = splitMappingKey(key)
                    val pluginId = wscdTofuMapping.getValue(key)
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(credentialType, style = MaterialTheme.typography.bodyMedium)
                            Text(issuer, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Text(
                                "→ $pluginId",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.tertiary,
                                fontWeight = FontWeight.SemiBold,
                            )
                        }
                        IconButton(onClick = { onForgetWscdTofuMapping(issuer, credentialType) }, modifier = Modifier.size(32.dp)) {
                            Icon(Icons.Default.Close, contentDescription = "Forget this choice", modifier = Modifier.size(16.dp))
                        }
                    }
                }
            }
        }
    }
}

/**
 * The cheapest known WSCD plugin ID whose nominal tier ([WscdPluginCapabilities])
 * satisfies [requiredTier], or `null` if none does. "Cheapest" = lowest
 * assurance tier that's still sufficient (e.g. a basic-tier requirement
 * resolves to softkey, not fido2) - see [WscdMappingCard]'s doc comment for
 * why discovered rows are assigned this way instead of targeting whichever
 * tab happened to be selected.
 */
/**
 * Tie-break order when more than one plugin shares the same nominal tier
 * (e.g. `r2ps` and `fido2` both nominally "high" - see
 * [WscdPluginCapabilities.NOMINAL_TIER]'s doc comment). Prefers a plugin
 * that's genuinely real/local over one whose assurance is a config-dependent
 * placeholder: `r2ps`'s "high" is explicitly documented as "best-effort...
 * not a guarantee", whereas `fido2` is a real hardware-backed authenticator
 * - a real bug found via live testing, where every high-tier discovered
 * credential silently defaulted to `r2ps` because it happened to come
 * first in [WSCD_PLUGIN_IDS] and [minByOrNull] breaks ties by iteration
 * order. `softkey` never actually ties with either (it's the only "basic"
 * plugin), so its position here is arbitrary but harmless.
 */
private val PLUGIN_TIE_BREAK_ORDER = listOf("softkey", "fido2", "r2ps")

private fun bestPluginFor(requiredTier: String): String? =
    WSCD_PLUGIN_IDS
        .mapNotNull { pid -> WscdPluginCapabilities.tierOf(pid)?.let { tier -> pid to tier } }
        .filter { (_, tier) -> WscdPluginCapabilities.meets(tier, requiredTier) }
        .minWithOrNull(
            compareBy(
                { (_, tier) -> WscdPluginCapabilities.rankOf(tier) },
                { (pid, _) -> PLUGIN_TIE_BREAK_ORDER.indexOf(pid).let { if (it < 0) Int.MAX_VALUE else it } },
            ),
        )
        ?.first

/** Parses the dev-default free-text box: one `issuer|credentialType=pluginId` entry per line. */
private fun parseWscdMappingText(text: String): Map<String, String> =
    text.lineSequence()
        .map { it.trim() }
        .filter { it.isNotEmpty() && it.contains('=') }
        .associate { line ->
            val (key, pluginId) = line.split('=', limit = 2)
            key.trim() to pluginId.trim()
        }

/** Splits a `"issuer|credentialType"` mapping key back into its two parts (see `WscdSelectionPolicy`). */
private fun splitMappingKey(key: String): Pair<String, String> =
    key.split("|", limit = 2).let { it.getOrElse(0) { "" } to it.getOrElse(1) { "" } }

/**
 * Removes [key]'s line from the dev-default mapping [text] - the delete
 * action for [WscdMappingCard]'s "Dev default" rows, which (unlike "Saved"
 * rows, backed by a real `clearUserOverride` call) live in this free-text
 * box rather than a proper store, so deleting one means rewriting the text
 * without that line.
 */
private fun removeFromWscdMappingText(text: String, key: String): String =
    text.lineSequence()
        .map { it.trim() }
        .filter { it.isNotEmpty() && it.contains('=') }
        .filterNot { line -> line.substringBefore('=').trim() == key }
        .joinToString("\n")

/**
 * Replaces [oldKey]'s line (if any) with `newKey=newPluginId` in the
 * dev-default mapping [text], preserving line order - the edit action for
 * [WscdMappingCard]'s "Dev default" rows. `oldKey == null` (a brand-new
 * entry) is just an append; `oldKey == newKey` (only the plugin changed) is
 * an in-place update; `oldKey != newKey` (issuer/credential type changed
 * too) removes the old line before adding the new one, so editing never
 * leaves a stale duplicate behind.
 */
private fun updateWscdMappingTextEntry(text: String, oldKey: String?, newKey: String, newPluginId: String): String {
    val ordered = LinkedHashMap<String, String>()
    text.lineSequence()
        .map { it.trim() }
        .filter { it.isNotEmpty() && it.contains('=') }
        .forEach { line ->
            val (key, pluginId) = line.split('=', limit = 2)
            ordered[key.trim()] = pluginId.trim()
        }
    if (oldKey != null) ordered.remove(oldKey)
    ordered[newKey] = newPluginId
    return ordered.entries.joinToString("\n") { (key, pluginId) -> "$key=$pluginId" }
}

/**
 * Everything that used to live in the standalone "WSCA Developer" screen:
 * transport config, lifecycle status/actions, Stored Keys, Build Info.
 * Collapsed by default behind [PluginSpecificSection]'s "Developer" toggle -
 * this is diagnostic/test content, not a thing an end user needs routinely.
 */
@Composable
private fun DeveloperSection(
    pluginId: String,
    lifecycleState: LifecycleState?,
    lifecycleStatus: LifecycleStatus?,
    keys: List<DetailedKeyInfo>,
    keySecurityProps: Map<String, SignerSecurityProperties>,
    r2psServerUrl: String,
    defaultWscdMappingText: String,
    fido2TransportMode: Fido2TransportMode,
    wscdLifecycleBusy: Boolean,
    onSelectFido2TransportMode: (Fido2TransportMode) -> Unit,
    onR2psServerUrlChange: (String) -> Unit,
    onDefaultWscdMappingTextChange: (String) -> Unit,
    onEnroll: () -> Unit,
    onRotate: () -> Unit,
    onRequestDestroy: () -> Unit,
    onRefresh: () -> Unit,
) {
    // ── Build Info ──────────────────────────────────────────
    SectionHeader("Build Info")
    InfoCard {
        InfoRow("App Version", BuildConfig.VERSION_NAME)
        InfoRow("Build Type", BuildConfig.BUILD_TYPE)
        InfoRow("WSCD Manager", "siros-wscd-manager ${wscdManagerVersion()} (UniFFI)")
    }

    Spacer(modifier = Modifier.height(16.dp))

    // ── Transport / plugin-specific config ──────────────────
    if (pluginId == "r2ps") {
        SectionHeader("R2PS Server")
        OutlinedTextField(
            value = r2psServerUrl,
            onValueChange = onR2psServerUrlChange,
            label = { Text("R2PS Server URL") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            shape = RoundedCornerShape(12.dp),
        )
        Spacer(modifier = Modifier.height(16.dp))
    }
    if (pluginId == "fido2") {
        SectionHeader("Transport")
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Fido2TransportMode.entries.forEach { mode ->
                androidx.compose.material3.FilterChip(
                    selected = fido2TransportMode == mode,
                    onClick = { onSelectFido2TransportMode(mode) },
                    label = { Text(mode.name) },
                )
            }
        }
        Spacer(modifier = Modifier.height(16.dp))
    }

    // ── Default WSCD Mapping (dev, session-only, shared across all plugin tabs) ──
    SectionHeader("Default WSCD Mapping (dev)")
    Text(
        text = "Pre-populates WalletConfig.defaultWscdMapping: one \"issuer|credentialType=pluginId\" " +
            "entry per line, across ALL plugins (not just $pluginId - see the common Mapping card " +
            "above the tabs for the full, unfiltered table). Host-app/dev config, not persisted " +
            "across restarts.",
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
    // wscdLifecycleBusy disables ALL FOUR actions while any one is
    // in flight (not just the one that started it) - a real CTAP2
    // ceremony can take many seconds waiting for a touch/tap, and
    // rapid re-tapping while that's pending was confirmed on real
    // hardware to launch overlapping coroutines that interleave
    // unpredictably (concurrent register/activate/destroy calls).
    Button(
        onClick = onEnroll,
        enabled = !wscdLifecycleBusy && (lifecycleState == null || lifecycleState == LifecycleState.Destroyed),
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
    ) {
        if (wscdLifecycleBusy) {
            CircularProgressIndicator(
                modifier = Modifier.size(18.dp),
                strokeWidth = 2.dp,
                color = MaterialTheme.colorScheme.onPrimary,
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text("Waiting for security key…")
        } else {
            Text("Enroll ($pluginId)")
        }
    }
    Spacer(modifier = Modifier.height(8.dp))
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Button(
            onClick = onRotate,
            enabled = !wscdLifecycleBusy && lifecycleState == LifecycleState.Active,
            modifier = Modifier.weight(1f),
            shape = RoundedCornerShape(12.dp),
        ) {
            Text("Rotate Keys")
        }
        OutlinedButton(
            onClick = onRequestDestroy,
            enabled = !wscdLifecycleBusy && lifecycleState != null && lifecycleState != LifecycleState.Destroyed,
            modifier = Modifier.weight(1f),
            shape = RoundedCornerShape(12.dp),
            colors = ButtonDefaults.outlinedButtonColors(
                contentColor = MaterialTheme.colorScheme.error,
            ),
        ) {
            Text("Destroy")
        }
    }
    Row(
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedButton(
            onClick = onRefresh,
            enabled = !wscdLifecycleBusy,
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
