// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.Alignment
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.siros.sdk.credentials.PresentationConsentRequest
import org.siros.sdk.wallet.ConsentScreen
import org.siros.sdk.wallet.PresentationConsentText

/**
 * Asks for consent to a `circuit_zk` presentation. The SDK built the request and owns the wording
 * ([PresentationConsentText]); this only renders [ConsentScreen] and reports the decision.
 *
 * TWO TIERS (found on-device: a single dense dialog read as confusing): this
 * the MINIMAL one - the verifier's label, the credentials by title, the
 * yes/no. Everything else - the raw client_id, the claims per credential,
 * the footnotes - waits behind "Show me details", which opens
 * [FullPresentationConsentDialog] (the original full [ConsentScreen]
 * rendering, unchanged).
 */
@Composable
fun PresentationConsentDialog(
    request: PresentationConsentRequest,
    onAgree: () -> Unit,
    onDecline: () -> Unit,
    onDetails: () -> Unit,
) {
    val context = LocalContext.current
    val screen = remember(request) { PresentationConsentText.forContext(context).render(request) }
    PresentationConsentSummary(screen, onAgree = onAgree, onDecline = onDecline, onDetails = onDetails)
}

/** The minimal tier: who, what, yes/no - the decision essentials only. */
@Composable
private fun PresentationConsentSummary(
    screen: ConsentScreen,
    onAgree: () -> Unit,
    onDecline: () -> Unit,
    onDetails: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDecline,
        title = { Text(screen.header, style = MaterialTheme.typography.titleMedium) },
        text = {
            Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                // The WHAT in the SDK's own wording (the decision's core):
                // each credential by title, then ALL its worded claim
                // lines ("The value of 'nl' from your credential is
                // shared", "No other personal data is shared") - never
                // the raw claim paths. The details tier carries what
                // remains: the raw client_id, the issuer names, the
                // footnotes.
                screen.entries.forEach { entry ->
                    entry.credentialName?.let {
                        Text(it, fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 6.dp))
                    }
                    entry.lines.forEach {
                        Text(
                            it,
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.padding(top = 2.dp),
                        )
                    }
                }
            }
        },
        // Confirm renders LEFT in Material's AlertDialog, dismiss RIGHT -
        // so the Share action and its Details companion go in the
        // confirm slot (right), Cancel alone in dismiss (left).
        confirmButton = {
            Row {
                TextButton(onClick = onDetails) { Text("Show me details") }
                TextButton(onClick = onAgree) { Text(screen.shareLabel) }
            }
        },
        dismissButton = { TextButton(onClick = onDecline) { Text(screen.cancelLabel) } },
    )
}
