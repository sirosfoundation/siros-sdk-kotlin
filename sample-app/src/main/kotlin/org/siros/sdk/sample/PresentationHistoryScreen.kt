// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.OutlinedTextField
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.draw.clip
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.siros.sdk.credentials.PresentationRecord
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * History: the wallet's log of presentations, newest first under day
 * headings, with a search over who it was shown to and what was shown.
 * Chrome-free - the caller frames it (see [WalletChrome]).
 */
@Composable
fun PresentationHistoryScreen(
    history: List<PresentationRecord>,
    modifier: Modifier = Modifier,
    filterCredentialId: Long? = null,
) {
    var query by rememberSaveable { mutableStateOf("") }
    val today = stringResource(R.string.history_today)
    val yesterday = stringResource(R.string.history_yesterday)
    val groups = remember(history, filterCredentialId, query, today, yesterday) {
        history
            .filter { filterCredentialId == null || it.credentialIds.contains(filterCredentialId) }
            .filter { matchesHistoryQuery(it, query) }
            .sortedByDescending { it.timestamp }
            .groupBy { historyDayLabel(it.timestamp, System.currentTimeMillis(), today, yesterday) }
            .toList()
    }
    Column(modifier = modifier.fillMaxSize().padding(horizontal = ScreenMargin).padding(top = 24.dp)) {
        Text(stringResource(R.string.menu_history), style = MaterialTheme.typography.headlineSmall)
        Spacer(modifier = Modifier.height(12.dp))
        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            modifier = Modifier.fillMaxWidth(),
            placeholder = { Text(stringResource(R.string.history_search), color = SirosDesign.secondaryText) },
            trailingIcon = { Icon(Icons.Filled.Search, contentDescription = null, tint = MaterialTheme.colorScheme.outlineVariant) },
            singleLine = true,
            shape = RoundedCornerShape(CardCorner),
        )
        if (groups.isEmpty()) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text(
                    text = stringResource(R.string.history_empty),
                    style = MaterialTheme.typography.bodyLarge,
                    color = SirosDesign.secondaryText,
                )
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(16.dp),
                contentPadding = androidx.compose.foundation.layout.PaddingValues(top = 16.dp, bottom = 24.dp),
            ) {
                groups.forEach { (day, records) ->
                    item(key = "day-$day") {
                        Text(day, style = MaterialTheme.typography.titleMedium)
                    }
                    items(records, key = { it.id }) { record ->
                        PresentationRecordCard(record)
                    }
                }
            }
        }
    }
}

/** Whether [record] mentions [query] in its verifier, its credentials or its disclosed claims. A blank query matches all. */
internal fun matchesHistoryQuery(record: PresentationRecord, query: String): Boolean {
    val q = query.trim()
    if (q.isEmpty()) return true
    return (record.verifierName?.contains(q, ignoreCase = true) == true) ||
        record.credentialNames.any { it.contains(q, ignoreCase = true) } ||
        record.requestedClaims.any { it.contains(q, ignoreCase = true) }
}

/** The day heading a record at [timestamp] falls under, as seen at [now]: [today], [yesterday], or the date. */
internal fun historyDayLabel(
    timestamp: Long,
    now: Long,
    today: String,
    yesterday: String,
    zone: java.util.TimeZone = java.util.TimeZone.getDefault(),
    locale: Locale = Locale.getDefault(),
): String {
    fun dayOf(millis: Long): Long = (millis + zone.getOffset(millis)) / 86_400_000L
    return when (dayOf(now) - dayOf(timestamp)) {
        0L -> today
        1L -> yesterday
        else -> SimpleDateFormat("d MMMM yyyy", locale).apply { timeZone = zone }.format(Date(timestamp))
    }
}

@Composable
private fun PresentationRecordCard(record: PresentationRecord) {
    val dateFormatter = remember { SimpleDateFormat("dd/MM/yyyy, HH:mm:ss", Locale.getDefault()) }
    var expanded by remember { androidx.compose.runtime.mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(CardCorner))
            .background(MaterialTheme.colorScheme.surface)
            .border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(CardCorner))
            .clickable { expanded = !expanded },
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            // Status icon
            Icon(
                imageVector = if (record.success) Icons.Filled.Check else Icons.Filled.Close,
                contentDescription = if (record.success)
                    stringResource(R.string.history_success)
                else
                    stringResource(R.string.history_failed),
                tint = if (record.success)
                    MaterialTheme.colorScheme.primary
                else
                    MaterialTheme.colorScheme.error,
                modifier = Modifier.size(24.dp),
            )

            Spacer(modifier = Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                // Verifier name or credential names
                val verifier = record.verifierName
                val title = if (verifier != null) {
                    verifier
                } else if (record.credentialNames.isNotEmpty()) {
                    record.credentialNames.joinToString(", ")
                } else {
                    stringResource(R.string.history_credentials_shared, record.credentialIds.size)
                }

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = title,
                        style = MaterialTheme.typography.titleSmall,
                    )
                    if (record.zkProof) {
                        Spacer(modifier = Modifier.width(6.dp))
                        Icon(
                            imageVector = Icons.Filled.Lock,
                            contentDescription = stringResource(R.string.history_zk_proof),
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(14.dp),
                        )
                    }
                }
                if (verifier != null && record.credentialNames.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(text = record.credentialNames.joinToString(", "), style = MaterialTheme.typography.bodyLarge)
                }
                Spacer(modifier = Modifier.height(6.dp))
                Text(text = dateFormatter.format(Date(record.timestamp)), style = MaterialTheme.typography.bodyLarge)
                if (record.requestedClaims.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        text = record.requestedClaims.joinToString(", ") { claim ->
                            claim.split(".", "_")
                                .joinToString(" ") { it.replaceFirstChar { c -> c.uppercase() } }
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = SirosDesign.secondaryText,
                    )
                }
            }
        }

        // Expandable detail section
        AnimatedVisibility(visible = expanded) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
                    .padding(bottom = 16.dp),
            ) {
                HorizontalDivider(modifier = Modifier.padding(bottom = 8.dp))

                if (record.credentialNames.isNotEmpty()) {
                    Text("Credentials shared:", style = MaterialTheme.typography.labelSmall,
                        color = SirosDesign.secondaryText)
                    record.credentialNames.forEach { name ->
                        Text("  • $name", style = MaterialTheme.typography.bodySmall)
                    }
                    Spacer(modifier = Modifier.height(4.dp))
                }

                if (record.requestedClaims.isNotEmpty()) {
                    Text("Data disclosed:", style = MaterialTheme.typography.labelSmall,
                        color = SirosDesign.secondaryText)
                    record.requestedClaims.forEach { claim ->
                        val formatted = claim.split(".", "_")
                            .joinToString(" ") { it.replaceFirstChar { c -> c.uppercase() } }
                        Text("  • $formatted", style = MaterialTheme.typography.bodySmall)
                    }
                    Spacer(modifier = Modifier.height(4.dp))
                }

                Text("Flow ID: ${record.flowId}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.outline)
                Text("Status: ${if (record.success) "Successful" else "Failed"}",
                    style = MaterialTheme.typography.labelSmall,
                    color = if (record.success) MaterialTheme.colorScheme.primary
                    else MaterialTheme.colorScheme.error)
            }
        }
    }
}
