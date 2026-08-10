// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable

/**
 * Shown right after login when [WalletViewModel.maybeOfferWscdAutoEnroll]
 * finds a [org.siros.sdk.auth.WscdAutoEnrollHint] suggesting the
 * just-used login credential might also support signing (see that
 * interface's doc comment for why this is only ever a hint - accepting
 * still runs the real enroll attempt, which can fail if the physical key
 * doesn't actually support it).
 */
@Composable
fun AutoEnrollOfferDialog(pluginId: String, onRespond: (accept: Boolean) -> Unit) {
    AlertDialog(
        onDismissRequest = { onRespond(false) },
        title = { Text("Use this security key for signing?") },
        text = {
            Text(
                "The security key you just used to log in may also support " +
                    "signing credentials directly, instead of relying on a " +
                    "software key. Set it up now?",
            )
        },
        confirmButton = {
            Button(onClick = { onRespond(true) }) { Text("Enable") }
        },
        dismissButton = {
            TextButton(onClick = { onRespond(false) }) { Text("Not now") }
        },
    )
}
