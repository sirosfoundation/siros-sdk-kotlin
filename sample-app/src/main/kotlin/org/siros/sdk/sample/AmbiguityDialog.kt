// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

package org.siros.sdk.sample

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.siros.sdk.wallet.WalletEventListener

/**
 * A WMP credential-match ambiguity (issue #399's selection ask): more than
 * one credential matched the verifier's query, and the user rules on it -
 * "let the wallet choose" (its first match, the default behaviour) or "I'll
 * choose myself" (a pick from [matches], which becomes the match answer's
 * entirety; the engine then consents and signs exactly the picked ones).
 *
 * The matches render by their display names with their claims; the raw
 * identifier lives in the consent dialog's details, not here.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AmbiguityDialog(
    pending: WalletViewModel.PendingAmbiguity,
    onUserChooses: (List<WalletEventListener.ConsentSelection>) -> Unit,
    onCancel: () -> Unit,
) {
    // Pre-selected: the wallet's first match (its default answer), so Choose
    // alone carries the default forward - but Cancel still REFUSES the
    // presentation outright (never a silent fallback to the pre-selection).
    var picked by remember(pending) { mutableStateOf(pending.matches.firstOrNull()) }
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text("More than one credential matches") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text(
                    "This request matches several of your credentials. Choose which to share.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                pending.matches.forEach { match ->
                    val selected = picked === match
                    androidx.compose.foundation.layout.Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { picked = match }
                            .padding(vertical = 4.dp),
                        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = selected, onClick = { picked = match })
                        // The credential's name alone: the matched CLAIM
                        // (a bare path like 'nl') is machine text - it reads
                        // as noise here and belongs in the consent dialog
                        // that follows, which words it properly.
                        Text(
                            match.credentialName ?: "Credential ${match.credentialId}",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                }
            }
        },
        confirmButton = {
            // Choose = the picked match (the wallet's first, unless changed).
            // Cancel = the presentation refused (no fallback).
            TextButton(
                onClick = { onUserChooses(listOfNotNull(picked)) },
                enabled = picked != null,
            ) { Text("Choose") }
        },
        dismissButton = {
            TextButton(onClick = onCancel) { Text("Cancel") }
        },
    )
}