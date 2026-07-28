// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import kotlinx.serialization.json.Json

private val prettyJson = Json { prettyPrint = true }

/**
 * Pretty-prints [text] if it parses as JSON (falls back to the raw string
 * otherwise, so it's safe to use uniformly for both structured and plain
 * claim values), in a monospace scrollable block with a copy-to-clipboard
 * icon. The clipboard always receives the original [text], not the
 * pretty-printed rendering.
 */
@Composable
fun CopyableTextBlock(text: String, modifier: Modifier = Modifier) {
    val displayText = remember(text) {
        try {
            prettyJson.encodeToString(
                kotlinx.serialization.json.JsonElement.serializer(),
                Json.parseToJsonElement(text),
            )
        } catch (_: Exception) {
            text
        }
    }
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current

    Box(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Text(
            text = displayText,
            style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            modifier = Modifier
                .padding(top = 12.dp, bottom = 12.dp, start = 12.dp, end = 40.dp)
                .horizontalScroll(rememberScrollState()),
        )
        IconButton(
            onClick = {
                clipboard.setText(AnnotatedString(text))
                Toast.makeText(context, R.string.copied_to_clipboard, Toast.LENGTH_SHORT).show()
            },
            modifier = Modifier.align(Alignment.TopEnd),
        ) {
            Icon(
                Icons.Filled.ContentCopy,
                contentDescription = stringResource(R.string.copy_to_clipboard),
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(18.dp),
            )
        }
    }
}
