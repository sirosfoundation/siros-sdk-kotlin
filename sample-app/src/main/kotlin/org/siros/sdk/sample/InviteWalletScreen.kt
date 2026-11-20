// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import kotlinx.coroutines.launch
import androidx.compose.ui.unit.dp
import timber.log.Timber

/**
 * Invite a wallet (issue #77): create the WMP invitation and show it as a
 * QR — the counterparty scans it (the wallet's ONE QR scanner,
 * [QrScannerScreen], whose result routes through
 * [WalletViewModel.handleQrResult]'s [org.siros.sdk.wallet.DeepLinkType.Invitation]
 * arm into [org.siros.sdk.wallet.SirosWallet.consumeInvitation]).
 *
 * The QR's payload: the `wmp://invite?data=` URI the engine's
 * `POST /wmp/invitation` answered. The share button offers the same URI
 * through Android's share sheet (any out-of-band channel).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun InviteWalletScreen(
    wallet: org.siros.sdk.wallet.SirosWallet,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var invitation by remember {
        mutableStateOf<org.siros.sdk.wallet.SirosWallet.WalletInvitation?>(null)
    }
    var error by remember { mutableStateOf<String?>(null) }
    var creating by remember { mutableStateOf(false) }

    // One create action: the first entry (LaunchedEffect) and the Retry
    // button both drive it. Retry was dead before - LaunchedEffect(Unit)
    // never re-runs, so the button's launch alone did nothing visible
    // while the transport was mid-reconnect.
    val create: () -> Unit = {
        if (!creating) {
            creating = true
            error = null
            invitation = null
            scope.launch {
                try {
                    android.util.Log.e("InviteWallet", "create start")
                    invitation = wallet.createInvitation()
                    android.util.Log.i("InviteWallet", "create ok: uri=${invitation?.uri?.take(40)}")
                } catch (e: Exception) {
                    android.util.Log.e("InviteWallet", "create failed: ${e::class.qualifiedName}: ${e.message}", e)
                    error = e.message ?: "The invitation create failed"
                } finally {
                    creating = false
                }
            }
        }
    }

    LaunchedEffect(Unit) { create() }

    // The failure's text (issue #77's diagnostics): the screen's
    // UI text alone left three blind rounds today.
    LaunchedEffect(error) {
        error?.let { Timber.e("InviteWallet: the create failed: $it") }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.invite_wallet_title)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                ),
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(padding)
                .padding(horizontal = ScreenMargin),
            verticalArrangement = Arrangement.spacedBy(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            when {
                error != null -> {
                    Spacer(Modifier.height(24.dp))
                    Text(
                        text = error.orEmpty(),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.error,
                    )
                    OutlinedButton(onClick = create, enabled = !creating) {
                        Text(stringResource(R.string.retry))
                    }
                }
                creating || invitation == null -> {
                    Spacer(Modifier.height(48.dp))
                    CircularProgressIndicator()
                    Text(
                        text = stringResource(R.string.invite_wallet_creating),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
                else -> {
                    val inv = invitation ?: return@Column
                    Spacer(Modifier.height(24.dp))
                    Text(
                        text = stringResource(R.string.invite_wallet_instructions),
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    // The QR: the same generator the proximity engagement
                    // uses (ProximityEngagementScreen).
                    val qrBitmap = remember(inv) { QrCodeGenerator.generate(inv.uri) }
                    qrBitmap?.let {
                        Image(
                            bitmap = it.asImageBitmap(),
                            contentDescription = stringResource(R.string.invite_wallet_qr_description),
                            modifier = Modifier
                                .widthIn(max = 320.dp)
                                .fillMaxWidth(),
                        )
                    } ?: Text(
                        text = stringResource(R.string.invite_wallet_qr_failed),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.error,
                    )
                    Text(
                        text = inv.uri,
                        style = MaterialTheme.typography.labelSmall,
                        maxLines = 3,
                        overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Button(
                        onClick = {
                            val send = android.content.Intent(android.content.Intent.ACTION_SEND).apply {
                                type = "text/plain"
                                putExtra(
                                    android.content.Intent.EXTRA_TEXT,
                                    inv.uri,
                                )
                            }
                            context.startActivity(
                                android.content.Intent.createChooser(send, null),
                            )
                        },
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Icon(Icons.Filled.Share, contentDescription = null)
                        Spacer(Modifier.widthIn(8.dp))
                        Text(stringResource(R.string.invite_wallet_share))
                    }
                    val expiresAt = inv.expiresAt
                    if (!expiresAt.isNullOrEmpty()) {
                        Text(
                            text = stringResource(R.string.invite_wallet_expires, expiresAt),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.outline,
                        )
                    }
                }
            }
        }
    }
}