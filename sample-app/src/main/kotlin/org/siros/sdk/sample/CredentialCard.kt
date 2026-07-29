// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import coil.ImageLoader
import coil.decode.SvgDecoder
import coil.request.ImageRequest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.siros.sdk.credentials.CredentialUtils
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.credentials.SvgTemplateRenderer
import timber.log.Timber

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
    // Falls back to a color derived from the actual bgColor above (not an
    // unrelated theme token) - a credential that declares backgroundColor
    // without textColor previously fell back to onPrimaryContainer, which is
    // only a valid pairing for the theme's OWN primaryContainer, not for an
    // arbitrary issuer-declared background (e.g. a saturated blue), producing
    // unreadable text.
    val fgColor = meta?.textColor?.toComposeColor()
        ?: contrastingTextColor(bgColor)

    // VCTM SVG template rendering (if the issuer's VCTM published one) - shows
    // a spinner while fetching (never flashes the flat color+logo layout as a
    // false "this is the real card" state first), and falls back to that flat
    // layout only once fetch/render has actually failed or there's no
    // template at all - never leaves the card blank/broken either way.
    val context = LocalContext.current
    val isDarkTheme = isSystemInDarkTheme()
    // Keyed on meta?.svgTemplates too, not just credential.id: metadata is
    // null on the first Ready emission after a reload (hydrateReloadedCredentials()
    // re-fetches VCTM and re-emits asynchronously) - without this, a card that
    // composed before that re-emission would stay stuck on its initial
    // NotApplicable/flat state forever, since credential.id alone doesn't
    // change when svgTemplates later arrives.
    // meta == null (not yet hydrated) is deliberately treated as "loading",
    // not "no template" - metadata being null doesn't mean the credential has
    // no SVG template, only that hydrateReloadedCredentials() hasn't finished
    // yet. Collapsing that into NotApplicable was what caused a flash of the
    // flat/blue card before the real metadata (and its SVG) arrived.
    var svgState by remember(credential.id, meta?.svgTemplates) {
        mutableStateOf<SvgLoadState>(
            when {
                meta == null -> SvgLoadState.Loading
                meta.svgTemplates.isNullOrEmpty() -> SvgLoadState.NotApplicable
                else -> SvgLoadState.Loading
            }
        )
    }
    LaunchedEffect(credential.id, meta?.svgTemplates, isDarkTheme) {
        if (meta == null) {
            // Wait (bounded) for hydration to populate metadata; the
            // remember/LaunchedEffect keys above cancel and re-fire this
            // block once meta?.svgTemplates actually changes. If that never
            // happens (VCTM fetch failed, no VCTM published, etc.) this
            // delay completes uncancelled and we settle to the flat layout
            // instead of spinning forever.
            svgState = SvgLoadState.Loading
            delay(5000)
            svgState = SvgLoadState.NotApplicable
            return@LaunchedEffect
        }
        val templates = meta.svgTemplates
        if (templates.isNullOrEmpty()) {
            svgState = SvgLoadState.NotApplicable
            return@LaunchedEffect
        }
        svgState = SvgLoadState.Loading
        val preferredScheme = if (isDarkTheme) "dark" else "light"
        val template = templates.find { it.colorScheme == preferredScheme } ?: templates.first()
        val bytes = fetchAndSubstituteSvg(credential, template.uri)
        svgState = if (bytes != null) SvgLoadState.Loaded(bytes) else SvgLoadState.Failed
    }
    val svgImageLoader = remember(context) {
        ImageLoader.Builder(context).components { add(SvgDecoder.Factory()) }.build()
    }

    Card(
        modifier = modifier
            .fillMaxWidth()
            .aspectRatio(1.6f)
            .then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = bgColor),
        elevation = CardDefaults.cardElevation(defaultElevation = 4.dp),
    ) {
        Box {
            when (val state = svgState) {
                is SvgLoadState.Loaded -> {
                    coil.compose.AsyncImage(
                        model = ImageRequest.Builder(context).data(state.bytes).build(),
                        imageLoader = svgImageLoader,
                        contentDescription = meta?.name ?: credential.format,
                        modifier = Modifier.fillMaxSize(),
                        contentScale = ContentScale.FillBounds,
                    )
                }
                SvgLoadState.Loading -> {
                    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(color = fgColor)
                    }
                }
                SvgLoadState.NotApplicable, SvgLoadState.Failed -> {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(20.dp),
                verticalArrangement = Arrangement.SpaceBetween,
            ) {
            // Top: issuer badge (logo or initial)
            Row(
                verticalAlignment = Alignment.CenterVertically,
            ) {
                val issuerName = meta?.issuer?.name ?: "?"
                val logoUri = meta?.logo?.uri
                if (logoUri != null) {
                    coil.compose.AsyncImage(
                        model = logoUri,
                        contentDescription = meta?.logo?.altText ?: issuerName,
                        modifier = Modifier
                            .size(32.dp)
                            .clip(CircleShape),
                        contentScale = ContentScale.Crop,
                    )
                } else {
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

            // Expired ribbon overlay
            // expiresAt is a JWT `exp` claim - always epoch SECONDS, not millis.
            val isExpired = credential.expiresAt?.let { it * 1000L < System.currentTimeMillis() } ?: false
            if (isExpired) {
                Box(
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .padding(8.dp)
                        .background(
                            color = MaterialTheme.colorScheme.error,
                            shape = RoundedCornerShape(4.dp),
                        )
                        .padding(horizontal = 6.dp, vertical = 2.dp),
                ) {
                    Text(
                        text = "EXPIRED",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onError,
                        fontWeight = FontWeight.Bold,
                    )
                }
            }
        }
    }
}

/** Loading state for a credential card's VCTM SVG template rendering. */
private sealed class SvgLoadState {
    /** This credential's metadata has no svg_templates - render the flat card immediately. */
    data object NotApplicable : SvgLoadState()
    /** Fetch/substitute in progress - show a spinner, not the flat card. */
    data object Loading : SvgLoadState()
    data class Loaded(val bytes: ByteArray) : SvgLoadState()
    /** Fetch or render failed - fall back to the flat card. */
    data object Failed : SvgLoadState()
}

private val svgHttpClient = OkHttpClient()

/**
 * Fetch a VCTM SVG rendering template and substitute this credential's claim
 * values into it (see [SvgTemplateRenderer]). Returns null on any failure
 * (network, non-2xx response, decode) - callers fall back to the flat
 * color+logo card layout rather than showing anything broken.
 */
private suspend fun fetchAndSubstituteSvg(credential: StoredCredential, templateUri: String): ByteArray? {
    return try {
        withContext(Dispatchers.IO) {
            val request = Request.Builder().url(templateUri).build()
            val svgText = svgHttpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) null else response.body?.string()
            } ?: return@withContext null
            val claims = CredentialUtils.extractClaims(credential)
            SvgTemplateRenderer.substitute(svgText, claims).toByteArray(Charsets.UTF_8)
        }
    } catch (e: CancellationException) {
        // The composable left composition (e.g. user navigated away) - not a
        // real failure. Must propagate, not be swallowed: the LaunchedEffect
        // key change that triggers this cancellation also re-runs the block
        // from scratch, so there's nothing to log or fall back to here.
        throw e
    } catch (e: Exception) {
        Timber.w(e, "Failed to fetch/render SVG template for credential ${credential.id}")
        null
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

/** Black or white, whichever contrasts better against [background] (relative luminance). */
internal fun contrastingTextColor(background: Color): Color =
    if (background.luminance() > 0.5f) Color.Black else Color.White
