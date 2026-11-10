// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.border
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.material.icons.filled.QrCode2
import androidx.compose.material.icons.outlined.PhotoCamera
import androidx.compose.material.icons.outlined.Badge
import androidx.compose.material.icons.outlined.SentimentSatisfied
import androidx.compose.material.icons.outlined.CropFree
import androidx.compose.material.icons.outlined.Contactless
import androidx.compose.material.icons.outlined.LightMode
import androidx.compose.material.icons.outlined.SignalCellularAlt
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.ui.platform.testTag
import androidx.compose.foundation.background
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Contactless
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.outlined.Info
import androidx.compose.ui.layout.ContentScale
import coil.compose.SubcomposeAsyncImageContent


import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.siros.sdk.credentials.CredentialOffer

/**
 * Add Credentials: two ways to bring a credential in from outside - scan an
 * issuer's QR code ([onScanQr], the wallet's one QR scanner) or scan a
 * passport into a Photo ID ([onStartIDV], shown when IDV is configured; it
 * opens [IDVPreparationScreen]) - followed by the catalog of credentials the
 * wallet's issuers offer, listed in place.
 *
 * The Photo ID card depends only on [onStartIDV] being non-null, never on
 * [offers]: a tenant whose one catalog offer is the Photo ID itself still
 * sees the card while the list below is empty. Chrome-free - the caller
 * frames it (see [WalletChrome]).
 */
@Composable
fun AddCredentialScreen(
    offers: List<CredentialOffer>,
    isLoading: Boolean,
    isRefreshing: Boolean = false,
    onOfferSelected: (CredentialOffer) -> Unit,
    pendingOffer: CredentialOffer? = null,
    onConfirmIssuance: () -> Unit = {},
    onCancelIssuance: () -> Unit = {},
    onStartIDV: (() -> Unit)? = null,
    onScanQr: () -> Unit = {},
    onRetry: () -> Unit = {},
    modifier: Modifier = Modifier,
) {
    // Long-press detail modal — lets the user inspect an offer's full
    // description/format before committing to the issuance-consent dialog
    // below, without the row's own tap target already starting that flow.
    var detailOffer by remember { mutableStateOf<CredentialOffer?>(null) }
    if (detailOffer != null) {
        val offer = detailOffer!!
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { detailOffer = null },
            title = { Text(offer.credentialName) },
            text = {
                Column {
                    Text(
                        text = offer.issuerName,
                        style = androidx.compose.material3.MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.SemiBold,
                    )
                    if (offer.credentialDescription != null) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = offer.credentialDescription!!,
                            style = androidx.compose.material3.MaterialTheme.typography.bodyMedium,
                            color = SirosDesign.secondaryText,
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    CapabilityIconRow(capabilityFlagsFor(offer.format))
                }
            },
            confirmButton = {
                androidx.compose.material3.TextButton(onClick = {
                    detailOffer = null
                    onOfferSelected(offer)
                }) {
                    Text(stringResource(R.string.add_credential_row_action_add))
                }
            },
            dismissButton = {
                androidx.compose.material3.TextButton(onClick = { detailOffer = null }) {
                    Text(stringResource(R.string.add_credential_row_action_close))
                }
            },
        )
    }

    // Issuance consent dialog
    if (pendingOffer != null) {
        androidx.compose.material3.AlertDialog(
            onDismissRequest = onCancelIssuance,
            title = { Text("Add Credential?") },
            text = {
                Column {
                    Text("You are about to request a credential from:")
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = pendingOffer.issuerName,
                        style = androidx.compose.material3.MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = pendingOffer.credentialName,
                        style = androidx.compose.material3.MaterialTheme.typography.bodyMedium,
                        color = SirosDesign.secondaryText,
                    )
                    if (pendingOffer.credentialDescription != null) {
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = pendingOffer.credentialDescription!!,
                            style = androidx.compose.material3.MaterialTheme.typography.bodySmall,
                            color = SirosDesign.secondaryText,
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    CapabilityIconRow(capabilityFlagsFor(pendingOffer.format))
                }
            },
            confirmButton = {
                androidx.compose.material3.TextButton(onClick = onConfirmIssuance) {
                    Text("Accept")
                }
            },
            dismissButton = {
                androidx.compose.material3.TextButton(onClick = onCancelIssuance) {
                    Text("Cancel")
                }
            },
        )
    }

    LazyColumn(
        modifier = modifier.fillMaxSize().testTag(ADD_CREDENTIAL_LIST_TAG),
        contentPadding = PaddingValues(horizontal = ScreenMargin, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        item { ScreenTitle(stringResource(R.string.add_credential_title)) }
        item {
            ActionCard(
                title = stringResource(R.string.add_credential_option_scan_qr_title),
                subtitle = stringResource(R.string.add_credential_option_scan_qr_subtitle),
                icon = Icons.Filled.QrCode2,
                onClick = onScanQr,
            )
        }
        if (onStartIDV != null) {
            item {
                ActionCard(
                    title = stringResource(R.string.add_credential_option_photo_id_title),
                    subtitle = stringResource(R.string.add_credential_option_photo_id_subtitle),
                    icon = Icons.Outlined.PhotoCamera,
                    onClick = onStartIDV,
                )
            }
        }
        item {
            Column(modifier = Modifier.padding(top = 14.dp)) {
                Text(stringResource(R.string.add_credential_available), style = MaterialTheme.typography.titleSmall)
                // The list shown is the SDK's cached catalog; this only says that it is being refreshed in the background.
                if (isRefreshing && !isLoading) {
                    Spacer(modifier = Modifier.height(8.dp))
                    androidx.compose.material3.LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                }
            }
        }
        when {
            isLoading -> item {
                Column(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    CircularProgressIndicator()
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(stringResource(R.string.add_credential_loading))
                }
            }
            offers.isEmpty() -> item {
                Column(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Text(
                        text = stringResource(R.string.add_credential_empty),
                        style = MaterialTheme.typography.bodyLarge,
                        color = SirosDesign.secondaryText,
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Button(onClick = onRetry, shape = RoundedCornerShape(CardCorner)) {
                        Text(stringResource(R.string.add_credential_retry))
                    }
                }
            }
            else -> items(offers) { offer ->
                CredentialOfferRow(
                    offer = offer,
                    onClick = { onOfferSelected(offer) },
                    onLongClick = { detailOffer = offer },
                )
            }
        }
    }
}

/**
 * One offer of the catalog, as a card: the issuer's logo (or a generic
 * credential mark) on a pale tile, the credential's name, its description,
 * and the issuer on a grey chip with the format's capability icons.
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun CredentialOfferRow(
    offer: CredentialOffer,
    onClick: () -> Unit,
    onLongClick: () -> Unit = {},
) {
    val shape = RoundedCornerShape(CardCorner)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(shape)
            .background(MaterialTheme.colorScheme.surface)
            .border(1.dp, MaterialTheme.colorScheme.outline, shape)
            .combinedClickable(onClick = onClick, onLongClick = onLongClick)
            .padding(16.dp),
        verticalAlignment = Alignment.Top,
    ) {
        if (offer.logoUri != null) {
            // The issuer's own logo, at the ID-1 card ratio (15.86:10): what
            // issuers publish as a "logo" is frequently the full card-body
            // template, which a square crop reduces to an unrecognizable sliver.
            Box(
                modifier = Modifier
                    .height(44.dp)
                    .aspectRatio(15.86f / 10f)
                    .clip(RoundedCornerShape(4.dp))
                    .background(offer.backgroundColor?.let { parseColor(it) } ?: MaterialTheme.colorScheme.secondaryContainer),
                contentAlignment = Alignment.Center,
            ) {
                IssuerLogo(
                    uri = offer.logoUri,
                    initial = offer.credentialName,
                    contentDescription = null,
                    modifier = Modifier.fillMaxSize(),
                    contentScale = ContentScale.Crop,
                    initialColor = offer.textColor?.let { parseColor(it) } ?: MaterialTheme.colorScheme.onSecondaryContainer,
                    initialStyle = MaterialTheme.typography.titleMedium,
                )
            }
        } else {
            SoftIconTile(Icons.Outlined.Badge)
        }
        Spacer(modifier = Modifier.width(14.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = offer.credentialName,
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.Medium,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            // Issuer-authored description is often the clearest signal for
            // telling apart two same-named offers (e.g. "Physical card" vs
            // "Digital-only ID").
            if (!offer.credentialDescription.isNullOrBlank()) {
                Text(
                    text = offer.credentialDescription!!,
                    style = MaterialTheme.typography.bodyLarge,
                    color = SirosDesign.secondaryText,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Spacer(modifier = Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = offer.issuerName,
                    style = MaterialTheme.typography.bodyLarge,
                    color = SirosDesign.secondaryText,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier
                        .weight(1f, fill = false)
                        .background(SirosDesign.altSurface, RoundedCornerShape(2.dp))
                        .padding(horizontal = 12.dp, vertical = 2.dp),
                )
                Spacer(modifier = Modifier.width(10.dp))
                CapabilityIconRow(capabilityFlagsFor(offer.format))
            }
        }
    }
}

/**
 * Which of a credential format's presentation capabilities apply - shown as
 * a small icon row under the credential's mini-card badge instead of a text
 * label, since a user has no reason to know what "mDoc" or "SD-JWT" mean.
 * mdoc formats support this wallet's BLE/NFC proximity presentation AND
 * remote OpenID4VP/DC API use, AND can be presented as a zero-knowledge
 * proof via DC API (see LongfellowZkProofSystem/CredentialMatcher's
 * mso_mdoc_zk matching - a ZK query matches a plain mso_mdoc credential,
 * there is no separately-stored "zk format"). The SD-JWT/JWT-VC formats
 * here are remote-presentation only, with no ZK support in this system yet.
 */
private data class CapabilityFlags(val online: Boolean, val proximity: Boolean, val zkp: Boolean)

private fun capabilityFlagsFor(format: String): CapabilityFlags {
    val isMdoc = format.equals("mso_mdoc", ignoreCase = true) ||
        format.equals("mso_mdoc_zk", ignoreCase = true)
    return CapabilityFlags(online = true, proximity = isMdoc, zkp = isMdoc)
}

@Composable
private fun CapabilityIconRow(flags: CapabilityFlags) {
    Row(horizontalArrangement = Arrangement.spacedBy(5.dp)) {
        CapabilityIcon(Icons.Filled.Public, flags.online, stringResource(R.string.credential_capability_online))
        CapabilityIcon(Icons.Filled.Contactless, flags.proximity, stringResource(R.string.credential_capability_proximity))
        CapabilityIcon(Icons.Filled.Shield, flags.zkp, stringResource(R.string.credential_capability_zkp))
    }
}

/** Enabled capabilities render at full tint; inapplicable ones are dimmed rather than hidden, so the icon set always lines up the same way across rows. */
@Composable
private fun CapabilityIcon(icon: ImageVector, enabled: Boolean, description: String) {
    Icon(
        icon,
        contentDescription = if (enabled) description else null,
        tint = if (enabled) {
            SirosDesign.secondaryText
        } else {
            SirosDesign.secondaryText.copy(alpha = 0.25f)
        },
        modifier = Modifier.size(14.dp),
    )
}

private fun parseColor(hex: String): Color? {
    val clean = hex.removePrefix("#")
    return try {
        when (clean.length) {
            3 -> Color(
                red = clean[0].digitToInt(16) * 17,
                green = clean[1].digitToInt(16) * 17,
                blue = clean[2].digitToInt(16) * 17,
            )
            6 -> Color(
                red = clean.substring(0, 2).toInt(16),
                green = clean.substring(2, 4).toInt(16),
                blue = clean.substring(4, 6).toInt(16),
            )
            else -> null
        }
    } catch (_: Exception) { null }
}

// ── Scan Photo ID ───────────────────────────────────────────────────

const val IDV_CONSENT_TAG = "idv_consent"
const val IDV_START_TAG = "idv_start"

/**
 * Scan Photo ID: what the scan will ask of the user (three steps), what to
 * have ready, why a face scan is part of it, and the consent to biometric
 * processing that enables Start Scan. Chrome-free - the caller frames it
 * (see [WalletChrome]).
 */
@Composable
fun IDVPreparationScreen(
    onStartScan: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var consentGiven by remember { mutableStateOf(false) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = ScreenMargin, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        ScreenTitle(stringResource(R.string.add_credential_option_photo_id_title), onBack = onBack)

        OutlinedCard(modifier = Modifier.fillMaxWidth()) {
            Column(verticalArrangement = Arrangement.spacedBy(20.dp)) {
                IDVStepRow(1, Icons.Outlined.SentimentSatisfied, stringResource(R.string.idv_step_face))
                IDVStepRow(2, Icons.Outlined.CropFree, stringResource(R.string.idv_step_document))
                IDVStepRow(3, Icons.Outlined.Contactless, stringResource(R.string.idv_step_nfc))
            }
        }

        OutlinedCard(modifier = Modifier.fillMaxWidth(), container = SirosDesign.altSurface) {
            Column {
                Text(stringResource(R.string.idv_before_title), style = MaterialTheme.typography.titleSmall)
                Spacer(modifier = Modifier.height(12.dp))
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    IDVPrerequisite(Icons.Outlined.Badge, stringResource(R.string.idv_before_passport), Modifier.weight(1f))
                    IDVPrerequisite(Icons.Outlined.LightMode, stringResource(R.string.idv_before_lighting), Modifier.weight(1f))
                    IDVPrerequisite(Icons.Outlined.SignalCellularAlt, stringResource(R.string.idv_before_connection), Modifier.weight(1f))
                }
            }
        }

        OutlinedCard(modifier = Modifier.fillMaxWidth()) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.idv_why_title), style = MaterialTheme.typography.titleSmall)
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(stringResource(R.string.idv_why_text), style = MaterialTheme.typography.bodyMedium)
                }
                Spacer(modifier = Modifier.width(16.dp))
                Box(
                    modifier = Modifier.size(64.dp).background(SirosDesign.altSurface, RoundedCornerShape(4.dp)),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        Icons.Outlined.VerifiedUser,
                        contentDescription = null,
                        tint = SirosDesign.brandOnPage,
                        modifier = Modifier.size(40.dp),
                    )
                }
            }
        }

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { consentGiven = !consentGiven },
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Checkbox(
                checked = consentGiven,
                onCheckedChange = { consentGiven = it },
                modifier = Modifier.testTag(IDV_CONSENT_TAG),
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(stringResource(R.string.idv_consent), style = MaterialTheme.typography.bodyMedium)
        }

        Button(
            onClick = onStartScan,
            enabled = consentGiven,
            modifier = Modifier.fillMaxWidth().height(48.dp).testTag(IDV_START_TAG),
            shape = RoundedCornerShape(CardCorner),
        ) {
            Text(stringResource(R.string.idv_start), style = MaterialTheme.typography.titleSmall)
        }

        Spacer(modifier = Modifier.height(8.dp))
    }
}

@Composable
private fun IDVStepRow(stepNumber: Int, icon: ImageVector, description: String) {
    Row(verticalAlignment = Alignment.Top, modifier = Modifier.fillMaxWidth()) {
        SoftIconTile(icon, shape = RoundedCornerShape(4.dp))
        Spacer(modifier = Modifier.width(20.dp))
        Column {
            Text(stringResource(R.string.idv_step_number, stepNumber), style = MaterialTheme.typography.titleSmall)
            Text(description, style = MaterialTheme.typography.bodyLarge)
        }
    }
}

@Composable
private fun IDVPrerequisite(icon: ImageVector, label: String, modifier: Modifier = Modifier) {
    Column(modifier = modifier, horizontalAlignment = Alignment.CenterHorizontally) {
        SoftIconTile(icon, modifier = Modifier.size(54.dp), shape = CircleShape)
        Spacer(modifier = Modifier.height(10.dp))
        Text(
            label,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium,
            textAlign = androidx.compose.ui.text.style.TextAlign.Center,
        )
    }
}

const val ADD_CREDENTIAL_LIST_TAG = "add_credential_list"
