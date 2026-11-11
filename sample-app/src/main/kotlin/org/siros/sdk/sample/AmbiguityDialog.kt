// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

package org.siros.sdk.sample

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
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
    // Opens the full in-wallet consent flow at the SELECTION step (the
    // choice of credential is what the user came here to make); its Share
    // answers this ask with the picked credential.
    onDetails: () -> Unit,
) {
    // Pre-selected: the wallet's first match (its default answer), so Choose
    // alone carries the default forward - but Cancel still REFUSES the
    // presentation outright (never a silent fallback to the pre-selection).
    var picked by remember(pending) { mutableStateOf(pending.matches.firstOrNull()) }
    AlertDialog(
        onDismissRequest = onCancel,
        title = {
            Text(
                "More than one credential matches",
                style = MaterialTheme.typography.titleMedium,
            )
        },
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
                        // The credential's title alone in the summary tier
                        // (the matched claim is machine text); in the details
                        // tier its claims list under the title, plus the
                        // credential id (the consent dialog that follows words
                        // the claims fully - here they are the detail).
                        // The credential's title alone: the matched claim
                        // (a bare path like 'nl') is machine text - it belongs
                        // in "Show me details", which opens the full in-wallet
                        // consent flow.
                        Text(
                            match.credentialName ?: "Credential ${match.credentialId}",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                }
            }
        },
        confirmButton = {
            // Cancel left, the actions right (the consent dialogs' pattern):
            // Details (the full match record) beside Choose.
            Row {
                TextButton(onClick = onDetails) { Text("Show me details") }
                TextButton(
                    onClick = { onUserChooses(listOfNotNull(picked)) },
                    enabled = picked != null,
                ) { Text("Choose") }
            }
        },
        dismissButton = { TextButton(onClick = onCancel) { Text("Cancel") } },
    )
}