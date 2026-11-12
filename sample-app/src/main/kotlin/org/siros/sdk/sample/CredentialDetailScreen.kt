// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.Surface
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.composed
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.withFrameNanos
import androidx.compose.runtime.mutableFloatStateOf
import coil.compose.AsyncImage
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.credentials.CredentialDisclosureGuard
import org.siros.sdk.credentials.CredentialUtils
import org.siros.sdk.credentials.DisplayClaim
import org.siros.sdk.credentials.interop.CredentialStatus
import org.siros.sdk.credentials.interop.HolderBinding
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Full credential detail screen with Info/Claims/Raw tabs.
 *
 * Modeled after the wallet-frontend CredentialDetail page:
 * - Info tab: issuer, format, type, dates, logo
 * - Claims tab: decoded claims (SD-JWT/mdoc) as key/value list
 * - Raw tab: raw credential string for debugging
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CredentialDetailScreen(
    credential: StoredCredential,
    onBack: () -> Unit,
    onDelete: () -> Unit,
    onRenew: () -> Unit,
    /**
     * Why this credential cannot currently be used, from the SDK's run of
     * DIIP's Validity and Revocation Algorithm (see
     * `WalletViewModel.credentialStatuses`). Null means it can be used.
     */
    credentialStatus: CredentialStatus? = null,
) {
    var showDeleteDialog by remember { mutableStateOf(false) }

    if (showDeleteDialog) {
        AlertDialog(
            onDismissRequest = { showDeleteDialog = false },
            title = { Text(stringResource(R.string.credential_detail_delete_confirm_title)) },
            text = {
                Text(stringResource(
                    R.string.credential_detail_delete_confirm_message,
                    credential.metadata?.name ?: credential.format,
                ))
            },
            confirmButton = {
                TextButton(onClick = {
                    showDeleteDialog = false
                    onDelete()
                }) {
                    Text(
                        stringResource(R.string.credential_detail_delete_confirm),
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteDialog = false }) {
                    Text(stringResource(R.string.cancel))
                }
            },
        )
    }

    Scaffold(
        // Swipe down to close (see [pullDownToDismiss]): the leftover of a
        // downward drag - what the content's own scrollables could not take
        // because they are already at their top - pulls the whole view down
        // with the finger; releasing past the threshold closes the screen.
        modifier = Modifier.pullDownToDismiss(onDismiss = onBack),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.credential_detail_title)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                ),
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.nav_back))
                    }
                },
                actions = {
                    IconButton(onClick = onRenew) {
                        Icon(
                            Icons.Filled.Refresh,
                            stringResource(R.string.credential_renew),
                        )
                    }
                    IconButton(onClick = { showDeleteDialog = true }) {
                        Icon(
                            Icons.Filled.Delete,
                            stringResource(R.string.credential_detail_delete),
                            tint = MaterialTheme.colorScheme.error,
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.padding(padding)) {
            // Compact card header
            CredentialCard(
                credential = credential,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                credentialStatus = credentialStatus,
            )

            // Why the credential cannot be used, spelled out - the card's
            // one-word ribbon says which outcome, this says what it means.
            if (credentialStatus != null && !credentialStatus.isUsable) {
                Surface(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 4.dp),
                    shape = RoundedCornerShape(8.dp),
                    color = credentialStatus.ribbonColor().copy(alpha = 0.12f),
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(
                            Icons.Filled.Warning,
                            contentDescription = null,
                            tint = credentialStatus.ribbonColor(),
                            modifier = Modifier.size(18.dp),
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = stringResource(credentialStatus.detailRes()),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                    }
                }
            }

            // Tabs
            var selectedTab by rememberSaveable { mutableIntStateOf(0) }
            val tabTitles = listOf(
                stringResource(R.string.credential_detail_tab_info),
                stringResource(R.string.credential_detail_tab_claims),
                stringResource(R.string.credential_detail_tab_raw),
            )

            TabRow(selectedTabIndex = selectedTab) {
                tabTitles.forEachIndexed { index, title ->
                    Tab(
                        selected = selectedTab == index,
                        onClick = { selectedTab = index },
                        text = { Text(title) },
                    )
                }
            }

            when (selectedTab) {
                0 -> InfoTab(credential)
                1 -> ClaimsTab(credential)
                2 -> RawTab(credential)
            }
        }
    }
}

@Composable
private fun InfoTab(credential: StoredCredential) {
    val meta = credential.metadata
    val dateFormatter = remember { SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // Logo
        meta?.logo?.uri?.let { logoUri ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                IssuerLogo(
                    uri = logoUri,
                    initial = meta.name ?: credential.format,
                    contentDescription = meta.logo?.altText,
                    modifier = Modifier
                        .size(48.dp)
                        .clip(RoundedCornerShape(8.dp)),
                    contentScale = ContentScale.Fit,
                    initialColor = MaterialTheme.colorScheme.onSurface,
                )
                Spacer(modifier = Modifier.width(12.dp))
                Text(
                    text = meta.name ?: credential.format,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                )
            }
            Spacer(modifier = Modifier.height(4.dp))
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                DetailRow(stringResource(R.string.credential_detail_issuer), meta?.issuer?.name ?: "-")
                DetailRow(stringResource(R.string.credential_detail_format), credential.format)
                // Which interoperability profile this credential was issued
                // under, read off its own holder binding. Informational: the
                // wallet needs no setting to present it correctly, and this is
                // simply what a dual-ecosystem wallet is hard to debug without.
                CredentialUtils.holderBinding(credential)?.let { binding ->
                    DetailRow(
                        stringResource(R.string.credential_detail_holder_binding),
                        when (binding) {
                            HolderBinding.DID_JWK -> "DIIP (cnf.kid)"
                            HolderBinding.EMBEDDED_JWK -> "HAIP (cnf.jwk)"
                        },
                    )
                }
                val typeId = meta?.vct ?: meta?.doctype
                if (typeId != null) {
                    DetailRow(stringResource(R.string.credential_detail_type), typeId)
                }
                credential.issuedAt?.let {
                    DetailRow(stringResource(R.string.credential_detail_issued), dateFormatter.format(Date(it * 1000)))
                }
                credential.expiresAt?.let {
                    DetailRow(stringResource(R.string.credential_detail_expires), dateFormatter.format(Date(it * 1000)))
                }
            }
        }

        meta?.description?.let {
            Text(
                text = it,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun ClaimsTab(credential: StoredCredential) {
    val claims = remember(credential) { CredentialUtils.extractClaims(credential) }

    if (claims.isEmpty()) {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = stringResource(R.string.credential_detail_no_claims),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    } else {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            claims.forEach { claim ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(8.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceVariant,
                    ),
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(
                            text = claim.label,
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        CopyableTextBlock(
                            text = claim.value,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        val desc = claim.description
                        if (desc != null) {
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = desc,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun RawTab(credential: StoredCredential) {
    // credential.raw is "<jwt>~<disclosure>~<disclosure>~..." per the SD-JWT
    // spec, not one JSON blob - decode it into its actual parts so each is
    // individually readable and copyable, instead of one opaque string.
    // The SDK decides what may be shown: a credential with protected claims is redacted there.
    val view = remember(credential.raw) { CredentialDisclosureGuard.rawViewOf(credential) }
    val parts = view.parts

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // Security warning — raw credentials are sensitive
        Card(
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.errorContainer,
            ),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                text = "\u26a0\ufe0f This is sensitive data. Do not screenshot or share.",
                style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Bold),
                color = MaterialTheme.colorScheme.onErrorContainer,
                modifier = Modifier.padding(12.dp),
            )
        }

        parts.header?.let { header ->
            RawSection(stringResource(R.string.credential_detail_raw_header), header.toString())
        }
        parts.payload?.let { payload ->
            RawSection(stringResource(R.string.credential_detail_raw_payload), payload.toString())
        }
        parts.disclosures.forEachIndexed { index, disclosure ->
            RawSection(
                stringResource(R.string.credential_detail_raw_disclosure, index + 1),
                disclosure.toString(),
            )
        }
        if (view.redacted) {
            Text(
                text = stringResource(R.string.credential_detail_raw_redacted),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        view.rawText?.let { text ->
            // Unparseable - still show the raw string rather than nothing.
            CopyableTextBlock(text = text, modifier = Modifier.fillMaxWidth())
        }
    }
}

@Composable
private fun RawSection(label: String, text: String) {
    Column {
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(modifier = Modifier.height(4.dp))
        CopyableTextBlock(text = text, modifier = Modifier.fillMaxWidth())
    }
}

@Composable
private fun DetailRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(0.4f),
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(0.6f),
        )
    }
}


/**
 * Swipe down to close: the leftover of a downward drag - what the content's
 * own scrollables could not take because they are already at their top -
 * drags the whole view down with the finger. Releasing past [threshold]
 * fires [onDismiss]; releasing short of it settles back with a short
 * ease-out. A drag the content CAN still take scrolls it normally, so the
 * gesture never fights the Claims/Raw tabs - it only ever engages from the
 * top.
 *
 * The drag writes the offset DIRECTLY from the nested-scroll callbacks
 * rather than through a launched `snapTo` per pointer delta: launching put
 * every delta a frame behind the finger and the pull read as sluggish
 * (found on-device). Only the settle-back is a coroutine - one shot, on
 * the frame clock, cancelled the moment a finger takes over again.
 */
private fun Modifier.pullDownToDismiss(
    threshold: androidx.compose.ui.unit.Dp = 100.dp,
    onDismiss: () -> Unit,
): Modifier = composed {
    val density = androidx.compose.ui.platform.LocalDensity.current
    val thresholdPx = with(density) { threshold.toPx() }
    var pullY by remember { mutableFloatStateOf(0f) }
    var settleJob by remember { mutableStateOf<kotlinx.coroutines.Job?>(null) }
    val scope = rememberCoroutineScope()
    val fired = remember { mutableStateOf(false) }
    val connection = remember {
        object : androidx.compose.ui.input.nestedscroll.NestedScrollConnection {
            override fun onPreScroll(available: androidx.compose.ui.geometry.Offset, source: androidx.compose.ui.input.nestedscroll.NestedScrollSource): androidx.compose.ui.geometry.Offset {
                // A new finger movement cancels the settle-back and owns the
                // offset again.
                settleJob?.let { if (it.isActive) it.cancel(); settleJob = null }
                // Dragging back up while pulled down: the pull-back comes off
                // the offset before the content scrolls.
                if (available.y < 0f && pullY > 0f) {
                    val take = (-available.y).coerceAtMost(pullY)
                    pullY -= take
                    return androidx.compose.ui.geometry.Offset(0f, -take)
                }
                return androidx.compose.ui.geometry.Offset.Zero
            }

            override fun onPostScroll(
                consumed: androidx.compose.ui.geometry.Offset,
                available: androidx.compose.ui.geometry.Offset,
                source: androidx.compose.ui.input.nestedscroll.NestedScrollSource,
            ): androidx.compose.ui.geometry.Offset {
                if (available.y > 0f) {
                    pullY = (pullY + available.y).coerceAtMost(thresholdPx * 2f)
                    return available
                }
                return androidx.compose.ui.geometry.Offset.Zero
            }

            override suspend fun onPreFling(available: androidx.compose.ui.unit.Velocity): androidx.compose.ui.unit.Velocity {
                if (pullY > thresholdPx && !fired.value) {
                    fired.value = true
                    onDismiss()
                    return available
                }
                val start = pullY
                if (start > 0f) {
                    settleJob = scope.launch {
                        val startNanos = androidx.compose.runtime.withFrameNanos { it }
                        val durationNanos = 180_000_000L
                        while (true) {
                            val now = androidx.compose.runtime.withFrameNanos { it }
                            val t = ((now - startNanos).toFloat() / durationNanos).coerceIn(0f, 1f)
                            // ease-out cubic: quick off the mark, gentle at home.
                            pullY = start * (1f - (1f - (1f - t) * (1f - t) * (1f - t)))
                            if (t >= 1f) break
                        }
                        pullY = 0f
                    }
                }
                return androidx.compose.ui.unit.Velocity.Zero
            }
        }
    }
    this
        .nestedScroll(connection)
        .graphicsLayer { translationY = pullY }
}
