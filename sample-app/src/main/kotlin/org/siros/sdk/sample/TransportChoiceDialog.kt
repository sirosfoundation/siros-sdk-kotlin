// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
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
 * Shown when [CompositeCtap2Transport] finds BOTH USB and NFC available
 * around the same time (e.g. a USB security key already plugged in and the
 * user also taps an NFC one) - see that class's `AMBIGUITY_GRACE_MS` doc
 * comment for exactly when this fires versus just waiting longer for
 * whichever transport the user is actually using.
 *
 * `respond(null)` on cancel - [CompositeCtap2Transport.connect] then
 * disconnects both candidate transports and surfaces
 * `Ctap2TransportException.ConnectionFailed`, matching
 * [WscdChoiceDialog]'s cancel handling.
 */
@Composable
fun TransportChoiceDialog(respond: (Fido2TransportMode?) -> Unit) {
    var selected by remember { mutableStateOf(Fido2TransportMode.USB) }

    AlertDialog(
        onDismissRequest = { respond(null) },
        title = { Text("Multiple security keys detected") },
        text = {
            Column {
                Text(
                    "Both a USB and an NFC security key are available. Choose which one to use:",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Spacer(modifier = Modifier.height(12.dp))
                Column(Modifier.selectableGroup()) {
                    for (mode in Fido2TransportMode.entries) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .selectable(
                                    selected = mode == selected,
                                    onClick = { selected = mode },
                                    role = Role.RadioButton,
                                ),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            RadioButton(selected = mode == selected, onClick = { selected = mode })
                            Text(mode.name, style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { respond(selected) }) { Text("Use this key") }
        },
        dismissButton = {
            TextButton(onClick = { respond(null) }) { Text("Cancel") }
        },
    )
}
