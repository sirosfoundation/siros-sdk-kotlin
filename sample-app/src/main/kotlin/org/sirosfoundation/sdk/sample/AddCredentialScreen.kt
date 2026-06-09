// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.sirosfoundation.sdk.sample

import androidx.compose.foundation.background
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
import org.sirosfoundation.sdk.credentials.CredentialOffer

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
    modifier: Modifier = Modifier,
) {
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
                Text(
                    text = stringResource(R.string.add_credential_empty),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(0.dp),
            ) {
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
        // Credential initial badge with background color
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
            Text(
                text = offer.credentialName.take(1).uppercase(),
                style = MaterialTheme.typography.titleMedium,
                color = fgColor,
                fontWeight = FontWeight.Bold,
            )
        }

        Spacer(modifier = Modifier.width(12.dp))

        // Credential name + issuer
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = offer.credentialName,
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.Medium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Spacer(modifier = Modifier.height(2.dp))
            // Issuer badge
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
                )
            }
        }
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
