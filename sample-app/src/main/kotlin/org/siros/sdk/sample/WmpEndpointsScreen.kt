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
import androidx.compose.material.icons.outlined.Lan
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
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
 * Issue #77's endpoint surface: the WMP backends this wallet is connected
 * to — its own configured engine plus one backend per scanned invitation
 * that named one (the join lands THERE: the nonce exists only on the
 * backend that minted it). The SDK tracks ([SirosWallet.connectedWmpEndpoints]),
 * this screen renders.
 */
@Composable
private fun ReplyField(
    label: String,
    onSend: (String) -> Unit,
) {
    var text by remember { mutableStateOf("") }
    androidx.compose.foundation.layout.Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        androidx.compose.material3.OutlinedTextField(
            value = text,
            onValueChange = { text = it },
            placeholder = { Text(label, style = MaterialTheme.typography.bodySmall) },
            singleLine = true,
            modifier = Modifier.weight(1f),
            textStyle = MaterialTheme.typography.bodySmall,
        )
        Spacer(Modifier.width(8.dp))
        androidx.compose.material3.TextButton(
            onClick = {
                if (text.isNotBlank()) {
                    onSend(text.trim())
                    text = ""
                }
            },
        ) {
            Text(stringResource(R.string.wmp_endpoint_reply_send))
        }
    }
}

/**
 * Issue #77's endpoint surface: the WMP backends this wallet is connected
 * to — its own configured engine plus one backend per scanned invitation
 * that named one (the join lands THERE: the nonce exists only on the
 * backend that minted it). The SDK tracks ([SirosWallet.connectedWmpEndpoints]),
 * this screen renders.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WmpEndpointsScreen(
    endpoints: List<WmpEndpointInfo>,
    messages: List<org.siros.sdk.wallet.WmpGroupMessage>,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onReply: (backend: String, text: String) -> Unit,
) {
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
                    Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                text = stringResource(
                                    if (ep.origin == WmpEndpointInfo.ORIGIN_INVITATION) {
                                        R.string.wmp_endpoint_origin_invitation
                                    } else {
                                        R.string.wmp_endpoint_origin_engine
                                    },
                                ),
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.Bold,
                            )
                            Text(
                                text = ep.state,
                                style = MaterialTheme.typography.labelMedium,
                                color = if (ep.state == "active") {
                                    MaterialTheme.colorScheme.primary
                                } else {
                                    MaterialTheme.colorScheme.outline
                                },
                            )
                        }
                        ep.providerUrl?.let {
                            Text(it, style = MaterialTheme.typography.bodySmall)
                        }
                        Text(
                            stringResource(R.string.wmp_endpoint_send) + " " + ep.sendUrl,
                            style = MaterialTheme.typography.bodySmall,
                        )
                        ep.sseUrl?.let {
                            Text(
                                stringResource(R.string.wmp_endpoint_events) + " " + it,
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                        ep.sessionId?.let {
                            Text(
                                stringResource(R.string.wmp_endpoint_session) + " " + it,
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                        // Issue #77: the session's group inbox (the messages
                        // this session's mailbox holds — the SDK's poll).
                        if (ep.sessionId != null) {
                            val sessionMessages = messages.filter {
                                (it.sessionId == ep.sessionId) &&
                                    (
                                    (ep.origin == WmpEndpointInfo.ORIGIN_ENGINE && it.backend == WmpEndpointInfo.ORIGIN_ENGINE) ||
                                        (ep.origin == WmpEndpointInfo.ORIGIN_INVITATION && it.backend == ep.providerUrl)
                                    )
                            }
                            Spacer(Modifier.height(6.dp))
                            Text(
                                stringResource(R.string.wmp_endpoint_messages),
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.Medium,
                            )
                            if (sessionMessages.isEmpty()) {
                                Text(
                                    stringResource(R.string.wmp_endpoint_messages_empty),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.outline,
                                )
                            } else {
                                sessionMessages.take(4).forEach { m ->
                                    Text(
                                        text = m.text,
                                        style = MaterialTheme.typography.bodySmall,
                                    )
                                }
                            }
                            // The reply (issue #77): the wallet answers the
                            // group on the SAME backend the inbox reads.
                            ReplyField(
                                label = stringResource(R.string.wmp_endpoint_reply),
                                onSend = { text ->
                                    onReply(
                                        if (ep.origin == WmpEndpointInfo.ORIGIN_INVITATION) {
                                            ep.providerUrl ?: WmpEndpointInfo.ORIGIN_ENGINE
                                        } else {
                                            WmpEndpointInfo.ORIGIN_ENGINE
                                        },
                                        text,
                                    )
                                },
                            )
                        }
                    }
                }
            }
        }
    }
}