// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import java.text.DateFormat
import java.util.Date

/**
 * The "Recent errors" journal: the last N failures, newest first, each with
 * its title and one-line summary — and its technical details behind an
 * explicit "Show technical details" reveal (never shown by default). An entry
 * opens its full record on tap. The reserved contact/context lines render only
 * when a source provided them.
 */
@Composable
fun ErrorJournalScreen(
    entries: List<ErrorJournalEntry>,
    onClear: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = ScreenMargin),
    ) {
        Spacer(modifier = Modifier.height(20.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
        ) {
            Text(
                text = stringResource(R.string.error_journal_title),
                style = MaterialTheme.typography.headlineSmall,
            )
            if (entries.isNotEmpty()) {
                TextButton(onClick = onClear) {
                    Text(stringResource(R.string.error_journal_clear))
                }
            }
        }
        if (entries.isEmpty()) {
            Spacer(modifier = Modifier.height(32.dp))
            Text(
                text = stringResource(R.string.error_journal_empty),
                style = MaterialTheme.typography.bodyLarge,
                color = SirosDesign.secondaryText,
            )
        }
        entries.forEachIndexed { index, entry ->
            if (index > 0) Spacer(modifier = Modifier.height(8.dp))
            ErrorJournalCard(entry)
        }
        Spacer(modifier = Modifier.height(32.dp))
    }
}

/** One journal entry: the card shows the title, time and summary; the tap opens the details. */
@Composable
private fun ErrorJournalCard(entry: ErrorJournalEntry) {
    var expanded by remember(entry.id) { mutableStateOf(false) }
    val time = remember(entry.timestamp) {
        DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM).format(Date(entry.timestamp))
    }
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("error_journal_entry")
            .clickable(role = Role.Button) { expanded = !expanded },
        shape = RoundedCornerShape(CardCorner),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer,
        ),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = entry.title,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.error,
            )
            Text(
                text = time,
                style = MaterialTheme.typography.bodySmall,
                color = SirosDesign.secondaryText,
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(entry.summary, style = MaterialTheme.typography.bodyMedium)
            if (expanded) {
                // The technical trail the user must choose to see, the reserved
                // contact/context lines when a source provided them.
                Spacer(modifier = Modifier.height(10.dp))
                HorizontalDivider(color = MaterialTheme.colorScheme.outline)
                Spacer(modifier = Modifier.height(10.dp))
                entry.contact?.let {
                    Text(
                        stringResource(R.string.error_journal_contact, it),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                entry.context?.let {
                    Text(
                        stringResource(R.string.error_journal_context, it),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                Text(
                    text = stringResource(R.string.error_journal_details_label),
                    style = MaterialTheme.typography.labelMedium,
                    color = SirosDesign.secondaryText,
                )
                val details = entry.details
                    ?: stringResource(R.string.error_journal_details_none)
                Text(
                    text = details,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            Color(0x11000000),
                            RoundedCornerShape(6.dp),
                        )
                        .padding(10.dp),
                )
            } else {
                Text(
                    text = stringResource(R.string.error_journal_show_details),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
        }
    }
}