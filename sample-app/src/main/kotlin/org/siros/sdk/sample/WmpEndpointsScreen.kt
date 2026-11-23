// Copyright 2026 SIROS Foundation. BSD-2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Lan
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
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
import org.siros.sdk.wallet.WmpEndpointInfo

/**
 * Issue #77's group-centric view: the MLS GROUPS the wallet holds — one
 * card per group (the configured engine plus every backend a scanned
 * invitation named).
 *
 * The card's identity is the GROUP — its name/id, its connection state, and
 * the CAPABILITIES its live session negotiated (what the group may ask of
 * this wallet: flows, mcp tools, …). WMP messages are machine traffic —
 * credentials and typed asks — so the card carries a TRACE (the store's
 * both-direction record, → sent / ← received), not a chat transcript; the
 * send field drives the wallet's message tool ([SirosWallet.replyToGroup],
 * `wmp_message_send`'s twin — either side of the group endpoints drives the
 * same primitive). The connection plumbing sits behind the ⓘ popup.
 */
/** One line of the ⓘ popup's plumbing (label + value). */
@Composable
private fun DetailLine(label: String, value: String) {
    Row(Modifier.fillMaxWidth()) {
        Text(
            label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.outline,
            modifier = Modifier.width(110.dp),
        )
        Text(
            value,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Medium,
        )
    }
}

/**
 * Issue #77's group-centric view: the MLS groups the wallet holds, one card
 * per group — the group's name/id and state headline, its negotiated
 * capabilities as chips, the connection details behind the ⓘ.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WmpEndpointsScreen(
    endpoints: List<WmpEndpointInfo>,
    messages: List<org.siros.sdk.wallet.WmpGroupMessage>,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onSend: (backend: String, text: String) -> Unit,
) {
    // The ⓘ popup: which card's plumbing is open (null = closed).
    var detailsFor by remember { mutableStateOf<WmpEndpointInfo?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.menu_wmp_endpoints)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
                    }
                },
                actions = {
                    IconButton(onClick = onRefresh) {
                        Icon(Icons.Default.Refresh, contentDescription = stringResource(R.string.wmp_endpoints_refresh))
                    }
                },
            )
        },
    ) { padding ->
        if (endpoints.isEmpty()) {
            Column(
                modifier = Modifier.fillMaxSize().padding(padding).padding(24.dp),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Icon(
                    Icons.Outlined.Lan,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.outline,
                )
                Spacer(Modifier.height(12.dp))
                Text(
                    stringResource(R.string.wmp_endpoints_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.outline,
                )
            }
            return@Scaffold
        }
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            items(endpoints, key = { it.providerUrl ?: it.origin + ":" + it.sendUrl }) { ep ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = if (ep.origin == WmpEndpointInfo.ORIGIN_INVITATION) {
                            MaterialTheme.colorScheme.secondaryContainer
                        } else {
                            MaterialTheme.colorScheme.surfaceVariant
                        },
                    ),
                ) {
                    Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        // The GROUP is the card's identity: its name (or id)
                        // headlines, the state rides beside it, the ⓘ opens
                        // the plumbing.
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column(Modifier.weight(1f)) {
                                Text(
                                    text = ep.groupName ?: ep.groupId ?: ep.sessionId
                                        ?: stringResource(
                                            if (ep.origin == WmpEndpointInfo.ORIGIN_INVITATION) {
                                                R.string.wmp_endpoint_origin_invitation
                                            } else {
                                                R.string.wmp_endpoint_origin_engine
                                            },
                                        ),
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.Bold,
                                )
                                ep.groupId?.let {
                                    if (ep.groupName != null) {
                                        Text(
                                            it,
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.outline,
                                        )
                                    }
                                }
                            }
                            Spacer(Modifier.width(8.dp))
                            Text(
                                text = ep.state,
                                style = MaterialTheme.typography.labelMedium,
                                color = if (ep.state == "active") {
                                    MaterialTheme.colorScheme.primary
                                } else {
                                    MaterialTheme.colorScheme.outline
                                },
                            )
                            Spacer(Modifier.width(4.dp))
                            IconButton(
                                onClick = { detailsFor = ep },
                                modifier = Modifier.height(28.dp).width(28.dp),
                            ) {
                                Icon(
                                    Icons.Outlined.Info,
                                    contentDescription = stringResource(R.string.wmp_endpoint_details),
                                    tint = MaterialTheme.colorScheme.outline,
                                )
                            }
                        }
                        // The capabilities the live session negotiated — what
                        // this group may ask of the wallet (flows, mcp, …).
                        if (ep.caps.isNotEmpty()) {
                            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text(
                                    stringResource(R.string.wmp_endpoint_caps),
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.Medium,
                                )
                                Row(
                                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                                    modifier = Modifier.fillMaxWidth(),
                                ) {
                                    ep.caps.take(4).forEach { cap ->
                                        AssistChip(
                                            onClick = {},
                                            label = {
                                                Text(cap, style = MaterialTheme.typography.labelSmall)
                                            },
                                        )
                                    }
                                }
                            }
                        }
                        // The group's TRACE (issue #77, both directions): the
                        // store's record for this group's session — → the
                        // wallet's sends ([WmpGroupMessage.outbound]), ← the
                        // arrivals — the machine traffic rendered as an
                        // inspection log, newest first. Not a chat transcript.
                        if (ep.sessionId != null) {
                            val trace = messages.filter {
                                (it.sessionId == ep.sessionId) &&
                                    (
                                    (ep.origin == WmpEndpointInfo.ORIGIN_ENGINE && it.backend == WmpEndpointInfo.ORIGIN_ENGINE) ||
                                        (ep.origin == WmpEndpointInfo.ORIGIN_INVITATION && it.backend == ep.providerUrl)
                                    )
                            }
                            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text(
                                    stringResource(R.string.wmp_endpoint_trace),
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.Medium,
                                )
                                if (trace.isEmpty()) {
                                    Text(
                                        stringResource(R.string.wmp_endpoint_trace_empty),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.outline,
                                    )
                                } else {
                                    trace.take(6).forEach { m ->
                                        Row(verticalAlignment = Alignment.Top) {
                                            Text(
                                                if (m.outbound) "→ " else "← ",
                                                style = MaterialTheme.typography.bodySmall,
                                                fontWeight = FontWeight.Bold,
                                                color = if (m.outbound) {
                                                    MaterialTheme.colorScheme.primary
                                                } else {
                                                    MaterialTheme.colorScheme.onSurfaceVariant
                                                },
                                            )
                                            Text(
                                                m.text,
                                                style = MaterialTheme.typography.bodySmall,
                                            )
                                        }
                                    }
                                }
                                // The wallet's message tool — [replyToGroup],
                                // the `wmp_message_send` twin: either side of
                                // the group endpoints drives the same
                                // primitive.
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    var text by remember { mutableStateOf("") }
                                    androidx.compose.material3.OutlinedTextField(
                                        value = text,
                                        onValueChange = { text = it },
                                        placeholder = {
                                            Text(
                                                stringResource(R.string.wmp_endpoint_reply),
                                                style = MaterialTheme.typography.bodySmall,
                                            )
                                        },
                                        singleLine = true,
                                        modifier = Modifier.weight(1f),
                                        textStyle = MaterialTheme.typography.bodySmall,
                                    )
                                    Spacer(Modifier.width(8.dp))
                                    androidx.compose.material3.TextButton(
                                        onClick = {
                                            if (text.isNotBlank()) {
                                                onSend(
                                                    if (ep.origin == WmpEndpointInfo.ORIGIN_INVITATION) {
                                                        ep.providerUrl ?: WmpEndpointInfo.ORIGIN_ENGINE
                                                    } else {
                                                        WmpEndpointInfo.ORIGIN_ENGINE
                                                    },
                                                    text.trim(),
                                                )
                                                text = ""
                                            }
                                        },
                                    ) {
                                        Text(stringResource(R.string.wmp_endpoint_reply_send))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // The ⓘ popup: this card's connection plumbing.
        detailsFor?.let { ep ->
            AlertDialog(
                onDismissRequest = { detailsFor = null },
                confirmButton = {
                    TextButton(onClick = { detailsFor = null }) {
                        Text(stringResource(R.string.wmp_endpoint_details_close))
                    }
                },
                title = {
                    Text(
                        stringResource(
                            if (ep.origin == WmpEndpointInfo.ORIGIN_INVITATION) {
                                R.string.wmp_endpoint_origin_invitation
                            } else {
                                R.string.wmp_endpoint_origin_engine
                            },
                        ),
                    )
                },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        ep.providerUrl?.let { DetailLine(stringResource(R.string.wmp_endpoint_provider), it) }
                        DetailLine(stringResource(R.string.wmp_endpoint_send), ep.sendUrl)
                        ep.sseUrl?.let { DetailLine(stringResource(R.string.wmp_endpoint_events), it) }
                        ep.sessionId?.let { DetailLine(stringResource(R.string.wmp_endpoint_session), it) }
                        ep.groupId?.let {
                            if (ep.sessionId != it) {
                                DetailLine(stringResource(R.string.wmp_endpoint_group), it)
                            }
                        }
                    }
                },
            )
        }
    }
}