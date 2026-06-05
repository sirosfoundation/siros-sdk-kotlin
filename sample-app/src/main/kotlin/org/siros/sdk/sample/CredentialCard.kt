// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.siros.sdk.credentials.StoredCredential

/**
 * Credit-card style credential display.
 *
 * Uses background_color/text_color from credential metadata when available,
 * otherwise falls back to Material theme surface colors.
 * Aspect ratio 1.6:1 matches the web frontend's card proportions.
 */
@Composable
fun CredentialCard(
    credential: StoredCredential,
    onClick: (() -> Unit)? = null,
    modifier: Modifier = Modifier,
) {
    val meta = credential.metadata
    val bgColor = meta?.backgroundColor?.toComposeColor()
        ?: MaterialTheme.colorScheme.primaryContainer
    val fgColor = meta?.textColor?.toComposeColor()
        ?: MaterialTheme.colorScheme.onPrimaryContainer

    Card(
        modifier = modifier
            .fillMaxWidth()
            .aspectRatio(1.6f)
            .then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = bgColor),
        elevation = CardDefaults.cardElevation(defaultElevation = 4.dp),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            verticalArrangement = Arrangement.SpaceBetween,
        ) {
            // Top: issuer badge
            Row(
                verticalAlignment = Alignment.CenterVertically,
            ) {
                val issuerName = meta?.issuer?.name ?: "?"
                Box(
                    modifier = Modifier
                        .size(32.dp)
                        .clip(CircleShape)
                        .background(fgColor.copy(alpha = 0.15f)),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = issuerName.take(1).uppercase(),
                        style = MaterialTheme.typography.labelMedium,
                        color = fgColor,
                        fontWeight = FontWeight.Bold,
                    )
                }
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = issuerName,
                    style = MaterialTheme.typography.labelMedium,
                    color = fgColor.copy(alpha = 0.7f),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            Spacer(modifier = Modifier.weight(1f))

            // Bottom: credential name + format badge
            Column {
                Text(
                    text = meta?.name ?: credential.format,
                    style = MaterialTheme.typography.titleLarge,
                    color = fgColor,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                Spacer(modifier = Modifier.height(4.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = credential.format.uppercase(),
                        style = MaterialTheme.typography.labelSmall,
                        color = fgColor.copy(alpha = 0.5f),
                    )
                    val typeId = meta?.vct ?: meta?.doctype
                    if (typeId != null) {
                        Text(
                            text = typeId.substringAfterLast('/').substringAfterLast('.'),
                            style = MaterialTheme.typography.labelSmall,
                            color = fgColor.copy(alpha = 0.5f),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
            }
        }
    }
}

/**
 * Parse a CSS color string (#RRGGBB or #RGB) to a Compose [Color].
 */
internal fun String.toComposeColor(): Color? {
    val hex = this.removePrefix("#")
    return try {
        when (hex.length) {
            3 -> Color(
                red = hex[0].digitToInt(16) * 17,
                green = hex[1].digitToInt(16) * 17,
                blue = hex[2].digitToInt(16) * 17,
            )
            6 -> Color(
                red = hex.substring(0, 2).toInt(16),
                green = hex.substring(2, 4).toInt(16),
                blue = hex.substring(4, 6).toInt(16),
            )
            8 -> Color(
                alpha = hex.substring(0, 2).toInt(16),
                red = hex.substring(2, 4).toInt(16),
                green = hex.substring(4, 6).toInt(16),
                blue = hex.substring(6, 8).toInt(16),
            )
            else -> null
        }
    } catch (_: Exception) {
        null
    }
}
