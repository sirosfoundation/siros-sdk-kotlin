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
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.res.stringResource
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
import org.siros.sdk.credentials.CredentialInstance
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
    /**
     * Every copy in this credential's batch (see [StoredCredential.batchId]),
     * including itself - a single-copy credential still gets a one-element
     * list. Mirrors wallet-frontend's `vcEntity.instances`: the ribbon shows
     * how many copies haven't been used in a presentation yet. Null (the
     * default) hides the ribbon entirely - for callers, like the detail
     * screen's compact header, that don't have batch/usage data on hand
     * rather than showing a misleading "0".
     */
    instances: List<CredentialInstance>? = null,
    /**
     * Called when the user taps "Renew" on a fully-exhausted credential
     * (every batch instance already used - see [instances]). Only ever
     * shown/invoked when [instances] is non-null and every instance's
     * `sigCount > 0`; ignored (no button rendered) if null.
     */
    onRenewClick: (() -> Unit)? = null,
) {
    // Null when the caller doesn't have batch/usage data on hand (see
    // [instances]'s doc comment) - only gates the greyed-out/Renew state
    // when we actually know the count, never on the strength of an absence.
    val unusedCount = instances?.count { it.sigCount == 0 }
    val isExhausted = unusedCount == 0
    val meta = credential.metadata
    val bgColor = meta?.backgroundColor?.toComposeColor()
        ?: MaterialTheme.colorScheme.primaryContainer
    // Falls back to a color derived from the actual bgColor above (not an
    // unrelated theme token) - a credential that declares backgroundColor
    // without textColor previously fell back to onPrimaryContainer, which is
    // only a valid pairing for the theme's OWN primaryContainer, not for an
    // arbitrary issuer-declared background (e.g. a saturated blue), producing
    // unreadable text.
    //
    // A declared textColor is only honored if it actually contrasts
    // adequately against bgColor - confirmed via live testing (a real PID
    // credential's declared pairing was nearly unreadable). Trusting an
    // issuer-declared color pair unconditionally means a bad VCTM display
    // block breaks legibility with no way for the wallet to recover; a
    // computed high-contrast color always exists as a safe fallback, so
    // there's no reason to render text the user can't read.
    val declaredFgColor = meta?.textColor?.toComposeColor()
    val fgColor = if (declaredFgColor != null && contrastRatio(declaredFgColor, bgColor) >= MIN_READABLE_CONTRAST_RATIO) {
        declaredFgColor
    } else {
        contrastingTextColor(bgColor)
    }

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
            Timber.i("CredentialCard ${credential.id} (${meta.vct ?: meta.doctype}): no SVG template, using flat layout")
            svgState = SvgLoadState.NotApplicable
            return@LaunchedEffect
        }
        svgState = SvgLoadState.Loading
        val preferredScheme = if (isDarkTheme) "dark" else "light"
        val template = templates.find { it.colorScheme == preferredScheme } ?: templates.first()
        Timber.i(
            "CredentialCard ${credential.id} (${meta.vct ?: meta.doctype}): using SVG template " +
                "${template.uri} (colorScheme=${template.colorScheme})",
        )
        val bytes = fetchAndSubstituteSvg(credential, template.uri, bgColor)
        svgState = if (bytes != null) SvgLoadState.Loaded(bytes) else SvgLoadState.Failed
    }
    val svgImageLoader = remember(context) {
        ImageLoader.Builder(context).components { add(SvgDecoder.Factory()) }.build()
    }

    Card(
        modifier = modifier
            .fillMaxWidth()
            .aspectRatio(1.6f)
            .then(if (onClick != null && !isExhausted) Modifier.clickable(onClick = onClick) else Modifier),
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
                        model = coilLogoModel(logoUri),
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

            // Expired ribbon overlay - bottom-right, matching wallet-frontend's
            // ExpiredRibbon (CredentialImage.jsx renders it opposite the
            // usages/copy-count ribbon so the two never collide).
            // expiresAt is a JWT `exp` claim - always epoch SECONDS, not millis.
            val isExpired = credential.expiresAt?.let { it * 1000L < System.currentTimeMillis() } ?: false
            if (isExpired) {
                Box(
                    modifier = Modifier
                        .align(Alignment.BottomEnd)
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

            // Remaining-copies ribbon - top-right, mirrors wallet-frontend's
            // UsagesRibbon (CredentialImage.jsx): count of batch copies not
            // yet used in a presentation (sigCount == 0), so it counts down
            // as copies get consumed rather than showing the fixed batch size.
            if (unusedCount != null) {
                Box(
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .padding(8.dp)
                        .background(
                            color = if (unusedCount > 0) {
                                MaterialTheme.colorScheme.tertiaryContainer
                            } else {
                                MaterialTheme.colorScheme.surfaceVariant
                            },
                            shape = RoundedCornerShape(50),
                        )
                        .padding(horizontal = 8.dp, vertical = 3.dp),
                ) {
                    Text(
                        text = unusedCount.toString(),
                        style = MaterialTheme.typography.labelSmall,
                        color = if (unusedCount > 0) {
                            MaterialTheme.colorScheme.onTertiaryContainer
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        },
                        fontWeight = FontWeight.Bold,
                    )
                }
            }

            // Every batch instance already used - grey the whole card out
            // (it can no longer be presented, see CredentialUtils.eligibleInstances)
            // and offer Renew instead of leaving it looking like a normal,
            // selectable credential.
            if (isExhausted) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(Color.Black.copy(alpha = 0.55f)),
                    contentAlignment = Alignment.Center,
                ) {
                    if (onRenewClick != null) {
                        TextButton(onClick = onRenewClick) {
                            Text(
                                text = stringResource(R.string.credential_renew),
                                color = Color.White,
                                fontWeight = FontWeight.Bold,
                            )
                        }
                    }
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
 *
 * [cardBackground] is the same background this card would otherwise render
 * flat against (from VCTM's `background_color`, or the theme default) - used
 * to correct any low-contrast text color the SVG itself declares (see
 * [correctSvgTextContrast]'s doc comment for why this is necessary: a real
 * issuer template rendered unreadably, confirmed via live testing, and
 * [SvgTemplateRenderer.substitute] only replaces claim-value text tokens, it
 * never touches the SVG's own styling).
 */
private suspend fun fetchAndSubstituteSvg(credential: StoredCredential, templateUri: String, cardBackground: Color): ByteArray? {
    return try {
        withContext(Dispatchers.IO) {
            val svgText = if (templateUri.startsWith("data:")) {
                decodeSvgDataUri(templateUri) ?: return@withContext null
            } else {
                val request = Request.Builder().url(templateUri).build()
                svgHttpClient.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) null else response.body?.string()
                } ?: return@withContext null
            }
            val claims = CredentialUtils.extractClaims(credential)
            val substituted = SvgTemplateRenderer.substitute(svgText, claims)
            val sized = ensureSvgImageHeight(substituted)
            if (sized != substituted) {
                Timber.i("CredentialCard ${credential.id}: injected missing height on a percentage-width <image> in SVG template")
            }
            val corrected = correctSvgTextContrast(sized, cardBackground)
            if (corrected != sized) {
                Timber.i("CredentialCard ${credential.id}: corrected low-contrast text fill(s) in SVG template")
            }
            corrected.toByteArray(Charsets.UTF_8)
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
 * Decode a `data:` URI's payload into its SVG text, returning null if it
 * isn't a decodable inline SVG.
 *
 * Confirmed necessary via live testing: re-issuing a credential caused
 * `svgTemplates[].uri` to arrive as a `data:image/svg+xml;base64,...` URI
 * instead of an HTTPS one (same underlying template, different delivery
 * mechanism) - [fetchAndSubstituteSvg]'s OkHttp fetch throws
 * `IllegalArgumentException` for any non-http(s) scheme, so this must be
 * handled before ever reaching [Request.Builder].
 */
internal fun decodeSvgDataUri(uri: String): String? {
    val comma = uri.indexOf(',')
    if (comma < 0) return null
    val meta = uri.substring(0, comma)
    val payload = uri.substring(comma + 1)
    return try {
        if (meta.contains("base64")) {
            java.util.Base64.getDecoder().decode(payload).toString(Charsets.UTF_8)
        } else {
            java.net.URLDecoder.decode(payload, "UTF-8")
        }
    } catch (e: Exception) {
        Timber.w(e, "Failed to decode data: URI SVG template")
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

/**
 * WCAG-style contrast ratio between two colors, from 1 (identical/no
 * contrast) to 21 (pure black on pure white) - `(L1 + 0.05) / (L2 + 0.05)`
 * where L1/L2 are the lighter/darker relative luminances.
 */
internal fun contrastRatio(a: Color, b: Color): Float {
    val lighter = maxOf(a.luminance(), b.luminance())
    val darker = minOf(a.luminance(), b.luminance())
    return (lighter + 0.05f) / (darker + 0.05f)
}

/**
 * Below WCAG's 3:1 minimum for large text - chosen for a card's short
 * name/issuer text, which typically renders at title/label sizes well
 * above the 18pt/14pt-bold threshold that ratio applies to. An
 * issuer-declared text/background pairing below this is treated as
 * unreadable, not merely non-ideal (see [CredentialCard]'s use of this).
 */
internal const val MIN_READABLE_CONTRAST_RATIO = 3.0f

/** Matches a `<text ...>` or `<tspan ...>` opening tag, whose own `fill` attribute (if any) [correctSvgTextContrast] inspects. */
private val SVG_TEXT_TAG = Regex("""<(?:text|tspan)\b[^>]*>""")

/** Matches a `fill="#hex"`/`fill='#hex'` attribute within an already-isolated tag string. */
private val SVG_FILL_ATTR = Regex("""fill=(["'])(#[0-9A-Fa-f]{3,8})\1""")

/**
 * Overrides a low-contrast `fill="#hex"` on each `<text>`/`<tspan>` element
 * in [svg] with a computed high-contrast color against [background], when
 * (and only when) the declared one fails [MIN_READABLE_CONTRAST_RATIO] -
 * confirmed necessary via live testing: a real issuer's SVG credential
 * template baked in unreadable text-color contrast, and
 * [SvgTemplateRenderer.substitute]'s pure `{{claimId}}` token replacement
 * has no way to touch an SVG's own styling.
 *
 * Deliberately narrow, matching what a hand-rolled regex over arbitrary SVG
 * can safely do: only a DIRECT `fill="#hex"` attribute on the text/tspan
 * element itself is inspected/corrected. A fill inherited from a parent
 * `<g>`, set via a CSS class/`<style>` block, or expressed as a named color
 * (`"black"`) or `url(#gradient)` reference is left untouched - resolving
 * those would need a real DOM walk with style/inheritance resolution, well
 * beyond what a string-substitution-based renderer should take on. An
 * already-adequate-contrast fill is also left untouched, preserving the
 * issuer's actual design wherever it already works.
 */
internal fun correctSvgTextContrast(svg: String, background: Color): String =
    SVG_TEXT_TAG.replace(svg) { tagMatch ->
        val tag = tagMatch.value
        val fillMatch = SVG_FILL_ATTR.find(tag)
        val declared = fillMatch?.groupValues?.get(2)?.toComposeColor()
        if (fillMatch == null || declared == null || contrastRatio(declared, background) >= MIN_READABLE_CONTRAST_RATIO) {
            tag
        } else {
            val corrected = contrastingTextColor(background)
            val correctedHex = "#%02X%02X%02X".format(
                (corrected.red * 255).toInt(),
                (corrected.green * 255).toInt(),
                (corrected.blue * 255).toInt(),
            )
            val quote = fillMatch.groupValues[1]
            tag.replaceRange(fillMatch.range, "fill=$quote$correctedHex$quote")
        }
    }

/** Matches a `<image ...>` opening tag (self-closing or not), whose `width`/`height` [ensureSvgImageHeight] inspects. */
private val SVG_IMAGE_TAG = Regex("""<image\b[^>]*>""")

/** Matches a percentage `width="NN%"`/`width='NN%'` attribute within an already-isolated tag string. */
private val SVG_IMAGE_WIDTH_PERCENT_ATTR = Regex("""width=(["'])(\d+%)\1""")

/** True if the tag string already declares a `height` attribute (any value). */
private val SVG_HAS_HEIGHT_ATTR = Regex("""\bheight=["']""")

/**
 * Injects a missing `height` on an `<image>` element that declares a
 * percentage `width` but no `height` at all, mirroring the exact width
 * value - confirmed necessary via live testing: a real issuer's SVG
 * credential template (wwwallet.org's demo PID) has its full-bleed
 * background `<image>` declare `width="100%"` with no `height` attribute
 * whatsoever. Per SVG 1.1 (which this template itself declares via
 * `version="1.1"`), an `<image>` with no height defaults to height 0 -
 * invisible - unless the renderer implements the newer SVG2/CSS
 * auto-sizing fallback (deriving height from the embedded image's own
 * intrinsic dimensions), which browsers commonly do but this app's
 * Android SVG decoder apparently doesn't. The graphic simply never
 * appeared, leaving only this card's own flat `backgroundColor` showing
 * through - not a rendering failure, an invisible-by-spec element.
 *
 * Deliberately narrow, matching what a hand-rolled regex over arbitrary
 * SVG can safely do: only a percentage-width `<image>` missing `height`
 * entirely is corrected, and it's set to the SAME percentage as `width` -
 * a safe, well-justified default when the image is clearly meant to fill
 * its container (which is exactly what `width="100%"` signals). An
 * absolute-unit width (e.g. `width="220"`, seen on this same template's
 * separate placeholder-photo `<image>`) is a different, more ambiguous
 * case - correctly sizing it would need the embedded image's own
 * intrinsic pixel dimensions, which isn't attempted here. An `<image>`
 * that already declares a `height` (any value) is never touched.
 */
internal fun ensureSvgImageHeight(svg: String): String =
    SVG_IMAGE_TAG.replace(svg) { tagMatch ->
        val tag = tagMatch.value
        val widthMatch = SVG_IMAGE_WIDTH_PERCENT_ATTR.find(tag)
        if (widthMatch == null || SVG_HAS_HEIGHT_ATTR.containsMatchIn(tag)) {
            tag
        } else {
            val percentage = widthMatch.groupValues[2]
            val selfClosing = tag.endsWith("/>")
            val body = (if (selfClosing) tag.dropLast(2) else tag.dropLast(1)).trimEnd()
            val closer = if (selfClosing) " />" else ">"
            "$body height=\"$percentage\"$closer"
        }
    }

/**
 * Coil's default components handle raw byte arrays (via `ByteArrayMapper` ->
 * `ByteBufferFetcher`, both built in) but never decode a `data:` URI *string*
 * on their own - passing one straight to `AsyncImage.model` just fails
 * silently. Issuer-published logos are frequently embedded this way (e.g.
 * geneva2026.mdoc.online's `credential_metadata.display[].logo.uri`), so
 * unwrap the base64 payload ourselves and hand Coil the bytes directly
 * instead of the URI string.
 */
internal fun coilLogoModel(uri: String): Any {
    if (!uri.startsWith("data:")) return uri
    val comma = uri.indexOf(',')
    if (comma < 0 || !uri.substring(0, comma).contains("base64")) return uri
    return try {
        java.util.Base64.getDecoder().decode(uri.substring(comma + 1))
    } catch (e: Exception) {
        uri
    }
}
