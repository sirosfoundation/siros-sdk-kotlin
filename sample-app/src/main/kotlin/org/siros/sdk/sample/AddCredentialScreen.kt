// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Contactless
import androidx.compose.material.icons.filled.Public
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
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.vector.ImageVector
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
 * Credential picker list — shows available credentials from all issuers.
 *
 * Modeled after the wallet-frontend's AddCredentials page:
 * each row shows the credential name, issuer badge, and format.
 */
@Composable
fun AddCredentialScreen(
    offers: List<CredentialOffer>,
    isLoading: Boolean,
    onOfferSelected: (CredentialOffer) -> Unit,
    pendingOffer: CredentialOffer? = null,
    onConfirmIssuance: () -> Unit = {},
    onCancelIssuance: () -> Unit = {},
    onStartIDV: (() -> Unit)? = null,
    onRetry: () -> Unit = {},
    modifier: Modifier = Modifier,
) {
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
                        color = androidx.compose.material3.MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    if (pendingOffer.credentialDescription != null) {
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = pendingOffer.credentialDescription!!,
                            style = androidx.compose.material3.MaterialTheme.typography.bodySmall,
                            color = androidx.compose.material3.MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    capabilityFor(pendingOffer.format)?.let { capability ->
                        Spacer(modifier = Modifier.height(8.dp))
                        CapabilityChip(capability)
                    }
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

    Column(modifier = modifier.fillMaxSize()) {
        if (isLoading) {
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center,
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    CircularProgressIndicator()
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(stringResource(R.string.add_credential_loading))
                }
            }
        } else if (offers.isEmpty()) {
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center,
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        text = stringResource(R.string.add_credential_empty),
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Button(onClick = onRetry) {
                        Text(stringResource(R.string.add_credential_retry))
                    }
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(0.dp),
            ) {
                // Scan Physical ID card (when IDV is available)
                if (onStartIDV != null) {
                    item {
                        ScanPhysicalIDCard(onClick = onStartIDV)
                        HorizontalDivider(thickness = 2.dp)
                    }
                }
                items(offers) { offer ->
                    CredentialOfferRow(offer = offer, onClick = { onOfferSelected(offer) })
                    HorizontalDivider()
                }
            }
        }
    }
}

@Composable
private fun CredentialOfferRow(
    offer: CredentialOffer,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // Credential badge: the issuer's own logo image when published
        // (credential_metadata.display[].logo - real graphical metadata, not
        // just a color), falling back to a colored initial letter otherwise.
        val bgColor = offer.backgroundColor?.let { parseColor(it) }
            ?: MaterialTheme.colorScheme.secondaryContainer
        val fgColor = offer.textColor?.let { parseColor(it) }
            ?: MaterialTheme.colorScheme.onSecondaryContainer

        Box(
            modifier = Modifier
                .size(40.dp)
                .clip(RoundedCornerShape(8.dp))
                .background(bgColor),
            contentAlignment = Alignment.Center,
        ) {
            val initial = @Composable {
                Text(
                    text = offer.credentialName.take(1).uppercase(),
                    style = MaterialTheme.typography.titleMedium,
                    color = fgColor,
                    fontWeight = FontWeight.Bold,
                )
            }
            if (offer.logoUri != null) {
                // SubcomposeAsyncImage, not AsyncImage: a plain AsyncImage
                // renders nothing at all while loading or on a failed fetch
                // (a real issue found via live device testing - offers whose
                // logo URI didn't resolve showed a blank square instead of
                // ever falling back to the initial-letter placeholder).
                coil.compose.SubcomposeAsyncImage(
                    model = coilLogoModel(offer.logoUri!!),
                    contentDescription = offer.credentialName,
                    modifier = Modifier.size(40.dp).clip(RoundedCornerShape(8.dp)),
                    contentScale = ContentScale.Crop,
                ) {
                    if (painter.state is coil.compose.AsyncImagePainter.State.Success) {
                        SubcomposeAsyncImageContent()
                    } else {
                        initial()
                    }
                }
            } else {
                initial()
            }
        }

        Spacer(modifier = Modifier.width(12.dp))

        // Credential name + description + issuer
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = offer.credentialName,
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.Medium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            // Issuer-authored description is often the clearest signal for
            // telling apart two same-named offers (e.g. "Physical card" vs
            // "Digital-only ID") - shown here, not just in the confirm
            // dialog, since that's exactly where users need it.
            if (!offer.credentialDescription.isNullOrBlank()) {
                Text(
                    text = offer.credentialDescription!!,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Spacer(modifier = Modifier.height(2.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(16.dp)
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.surfaceVariant),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = offer.issuerName.take(1).uppercase(),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Spacer(modifier = Modifier.width(4.dp))
                Text(
                    text = offer.issuerName,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f, fill = false),
                )
                capabilityFor(offer.format)?.let { capability ->
                    Spacer(modifier = Modifier.width(6.dp))
                    CapabilityChip(capability)
                }
            }
        }
    }
}

/** A plain-language, icon-backed signal for what a credential format lets the holder DO. */
private data class FormatCapability(val icon: ImageVector, val label: String)

/**
 * Maps an OID4VCI `format` identifier to a user-meaningful capability signal,
 * not the raw wire term - a user has no reason to know what "mDoc" or
 * "SD-JWT" mean, but "works in person" vs "online only" is exactly the
 * distinction they need to pick between two same-named offers (e.g. a PID
 * issued as both an mdoc and an SD-JWT VC). mdoc formats support both this
 * wallet's BLE/NFC proximity presentation AND remote OpenID4VP/DC API use;
 * the SD-JWT/JWT-VC formats here are remote-presentation only. Returns null
 * for an unrecognized format rather than guessing.
 */
@Composable
private fun capabilityFor(format: String): FormatCapability? = when {
    format.equals("mso_mdoc", ignoreCase = true) ||
        format.equals("mso_mdoc_zk", ignoreCase = true) ->
        FormatCapability(Icons.Filled.Contactless, stringResource(R.string.credential_capability_in_person))
    format.equals("dc+sd-jwt", ignoreCase = true) ||
        format.equals("vc+sd-jwt", ignoreCase = true) ||
        format.equals("jwt_vc_json", ignoreCase = true) ->
        FormatCapability(Icons.Filled.Public, stringResource(R.string.credential_capability_online_only))
    else -> null
}

@Composable
private fun CapabilityChip(capability: FormatCapability) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .clip(RoundedCornerShape(4.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .padding(horizontal = 6.dp, vertical = 1.dp),
    ) {
        Icon(
            capability.icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(12.dp),
        )
        Spacer(modifier = Modifier.width(3.dp))
        Text(
            text = capability.label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
        )
    }
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

// ── Scan Physical ID ────────────────────────────────────────────────

@Composable
private fun ScanPhysicalIDCard(onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            modifier = Modifier
                .size(40.dp)
                .clip(RoundedCornerShape(8.dp))
                .background(MaterialTheme.colorScheme.primaryContainer),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                Icons.Outlined.Info,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onPrimaryContainer,
                modifier = Modifier.size(20.dp),
            )
        }
        Spacer(modifier = Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = "Digital ID (scanned passport)",
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.Medium,
            )
            Text(
                text = "Scan your face and passport",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Icon(
            Icons.AutoMirrored.Filled.KeyboardArrowRight,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/**
 * IDV preparation screen matching the wallet-frontend's ScanPhysicalID.tsx UX.
 *
 * Shows:
 * 1. Three steps with icons (face scan → document scan → NFC read)
 * 2. Prerequisites
 * 3. Privacy explanation
 * 4. Consent checkbox
 * 5. "Start Scan" CTA
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun IDVPreparationScreen(
    onStartScan: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var consentGiven by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Scan Physical ID") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(20.dp),
        ) {
            // Steps
            Text(
                "How it works",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )

            IDVStepRow(
                stepNumber = 1,
                icon = Icons.Outlined.Info,
                title = "Face scan",
                description = "Scan your face to show you are a real, live human",
            )
            IDVStepRow(
                stepNumber = 2,
                icon = Icons.Outlined.Info,
                title = "Document scan",
                description = "Scan the photo page of your passport or ID card",
            )
            IDVStepRow(
                stepNumber = 3,
                icon = Icons.Outlined.Info,
                title = "NFC chip read",
                description = "Place your phone on your document to read the NFC chip",
            )

            HorizontalDivider()

            // Prerequisites
            Text(
                "Before you start",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
            )
            Text("• Have your passport or ID card ready", style = MaterialTheme.typography.bodyMedium)
            Text("• Ensure good lighting conditions", style = MaterialTheme.typography.bodyMedium)
            Text("• Ensure a stable internet connection", style = MaterialTheme.typography.bodyMedium)

            HorizontalDivider()

            // Privacy explanation
            Text(
                "Why a face scan?",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
            )
            Text(
                "A 3D face scan verifies you are a real, live person. Your biometric data is encrypted during capture and processed only for identity verification. It is not stored after the session.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            // Consent checkbox
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { consentGiven = !consentGiven },
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Checkbox(
                    checked = consentGiven,
                    onCheckedChange = { consentGiven = it },
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    "I consent to biometric processing for identity verification.",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }

            // Start Scan button
            Button(
                onClick = onStartScan,
                enabled = consentGiven,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
            ) {
                Text("Start Scan")
            }

            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}

@Composable
private fun IDVStepRow(
    stepNumber: Int,
    icon: ImageVector,
    title: String,
    description: String,
) {
    Row(
        verticalAlignment = Alignment.Top,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Box(
            modifier = Modifier
                .size(36.dp)
                .clip(CircleShape)
                .background(MaterialTheme.colorScheme.primaryContainer),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = "$stepNumber",
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
            )
        }
        Spacer(modifier = Modifier.width(12.dp))
        Column {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(icon, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text(title, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium)
            }
            Text(
                text = description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
