// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp

/**
 * Shown when [WalletViewModel]'s `requestWscdChoice` callback fires - the
 * SDK ([org.siros.sdk.wallet.WscdSelectionPolicy]) asking which of more than
 * one eligible, already-registered WSCD plugin should back an upcoming
 * credential-issuance key batch, because a persisted trust-on-first-use
 * choice and the dev-supplied default mapping both came up empty. Mirrors
 * `ProximityConsentDialog`'s shape (see `ProximityEngagementScreen.kt`)
 * exactly: a plain-language explanation, a radio-button list of the
 * offered options, and Choose/Cancel actions - `onChoose(null)` on
 * dismiss/Cancel, matching [org.siros.sdk.wallet.WscdChoiceResult.Cancelled].
 */
@Composable
fun WscdChoiceDialog(pending: PendingWscdChoice, onChoose: (String?) -> Unit) {
    var selected by remember(pending) { mutableStateOf(pending.eligiblePluginIds.first()) }

    AlertDialog(
        onDismissRequest = { onChoose(null) },
        title = { Text("Choose a security key") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text(
                    "This credential requires a hardware-backed key. Choose which security key " +
                        "to use for \"${pending.credentialType}\" from ${pending.issuer}:",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Spacer(modifier = Modifier.height(12.dp))
                Column(Modifier.selectableGroup()) {
                    for (pluginId in pending.eligiblePluginIds) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .selectable(
                                    selected = pluginId == selected,
                                    onClick = { selected = pluginId },
                                    role = Role.RadioButton,
                                )
                                .padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            RadioButton(selected = pluginId == selected, onClick = { selected = pluginId })
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(pluginId, style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onChoose(selected) }) { Text("Use this key") }
        },
        dismissButton = {
            TextButton(onClick = { onChoose(null) }) { Text("Cancel") }
        },
    )
}
