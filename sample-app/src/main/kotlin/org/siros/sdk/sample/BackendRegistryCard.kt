package org.siros.sdk.sample

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

/**
 * The backend registry card: the list of every backend the user knows, the
 * one that is current, and the add/edit/delete/switch actions over them.
 *
 * Android-only on purpose - see [org.siros.sdk.sample.BackendProfile]'s doc
 * comment (iOS registers redirect schemes statically; a runtime-added
 * backend there could never complete its own login).
 *
 * Switching is a LOGOUT: the wallet's account, credentials and cached trust
 * belong to the backend they came from, so the switch confirms, materializes
 * the profile into the connection settings, and disconnects - the user then
 * logs into the switched-to backend (WalletViewModel.switchBackend).
 */
@Composable
fun BackendRegistryCard(
    backends: List<org.siros.sdk.sample.BackendProfile>,
    currentBackendId: String?,
    onSaveBackend: (org.siros.sdk.sample.BackendProfile) -> Unit,
    onDeleteBackend: (String) -> Unit,
    onSwitchBackend: (String) -> Unit,
) {
    // The dialog's working state: null = closed, else the profile being
    // added or edited (a copy the fields mutate; saving hands it back).
    var editing by remember { mutableStateOf<org.siros.sdk.sample.BackendProfile?>(null) }
    // The pending switch, confirmed through a dialog (it logs out).
    var pendingSwitch by remember { mutableStateOf<org.siros.sdk.sample.BackendProfile?>(null) }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Column(modifier = Modifier.fillMaxWidth().padding(20.dp)) {
            Text(
                "Backends",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                color = SirosDesign.secondaryText,
            )
            Spacer(modifier = Modifier.height(12.dp))

            backends.forEach { profile ->
                val isCurrent = profile.id == currentBackendId
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Row(
                        modifier = Modifier.weight(1f).padding(vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = isCurrent, onClick = {
                            if (!isCurrent) pendingSwitch = profile
                        })
                        Column {
                            Text(
                                profile.name,
                                style = MaterialTheme.typography.bodyLarge,
                                fontWeight = FontWeight.Medium,
                            )
                            Text(
                                "${profile.backendUrl} · ${profile.tenantId}",
                                style = MaterialTheme.typography.bodySmall,
                                color = SirosDesign.secondaryText,
                            )
                        }
                    }
                    TextButton(onClick = { editing = profile }) { Text("Edit") }
                    // The current backend cannot be deleted out from under
                    // the active wallet (WalletViewModel.deleteBackendProfile
                    // refuses silently too) - switch away first.
                    TextButton(
                        enabled = !isCurrent,
                        onClick = { onDeleteBackend(profile.id) },
                    ) { Text("Delete") }
                }
            }

            Spacer(modifier = Modifier.height(8.dp))
            OutlinedButton(
                onClick = {
                    editing = org.siros.sdk.sample.BackendProfile(
                        id = java.util.UUID.randomUUID().toString(),
                        name = "",
                        backendUrl = "https://",
                        tenantId = "default",
                    )
                },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Add backend") }
        }
    }

    editing?.let { profile ->
        BackendProfileDialog(
            profile = profile,
            isNew = backends.none { it.id == profile.id },
            onSave = {
                onSaveBackend(it)
                editing = null
            },
            onDismiss = { editing = null },
        )
    }

    pendingSwitch?.let { profile ->
        AlertDialog(
            onDismissRequest = { pendingSwitch = null },
            title = { Text("Switch backend?") },
            text = {
                Text(
                    "Switching to \"${profile.name}\" logs you out: your account, " +
                        "credentials and trust cache belong to the current backend. " +
                        "You will sign in to ${profile.backendUrl} next.",
                )
            },
            confirmButton = {
                Button(onClick = {
                    pendingSwitch = null
                    onSwitchBackend(profile.id)
                }) { Text("Switch & log out") }
            },
            dismissButton = {
                TextButton(onClick = { pendingSwitch = null }) { Text("Cancel") }
            },
        )
    }
}

/**
 * The add/edit form: the complete profile (name, backend URL, tenant,
 * engine override, ZK circuit mirrors). Saving hands the whole profile up -
 * the caller decides persistence (WalletViewModel.saveBackendProfile).
 */
@Composable
private fun BackendProfileDialog(
    profile: org.siros.sdk.sample.BackendProfile,
    isNew: Boolean,
    onSave: (org.siros.sdk.sample.BackendProfile) -> Unit,
    onDismiss: () -> Unit,
) {
    var name by remember { mutableStateOf(profile.name) }
    var backendUrl by remember { mutableStateOf(profile.backendUrl) }
    var tenantId by remember { mutableStateOf(profile.tenantId) }
    var engineUrl by remember { mutableStateOf(profile.engineUrl) }
    var zkCircuitUrls by remember { mutableStateOf(profile.zkCircuitUrls.joinToString("\n")) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (isNew) "Add backend" else "Edit backend") },
        text = {
            Column {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = backendUrl,
                    onValueChange = { backendUrl = it },
                    label = { Text("Backend URL") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = tenantId,
                    onValueChange = { tenantId = it },
                    label = { Text("Tenant ID") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = engineUrl,
                    onValueChange = { engineUrl = it },
                    label = { Text("Engine URL (blank = derived)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = zkCircuitUrls,
                    onValueChange = { zkCircuitUrls = it },
                    label = { Text("ZK circuit URLs (one per line, blank = default)") },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            Button(
                enabled = name.isNotBlank() && backendUrl.isNotBlank(),
                onClick = {
                    onSave(
                        profile.copy(
                            name = name.trim(),
                            backendUrl = backendUrl.trim(),
                            tenantId = tenantId.trim().ifBlank { "default" },
                            engineUrl = engineUrl.trim(),
                            zkCircuitUrls = zkCircuitUrls
                                .lines()
                                .map(String::trim)
                                .filter(String::isNotEmpty),
                        )
                    )
                },
            ) { Text("Save") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}