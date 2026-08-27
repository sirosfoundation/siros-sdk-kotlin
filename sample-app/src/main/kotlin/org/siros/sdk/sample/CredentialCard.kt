// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
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
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun CredentialCard(
    credential: StoredCredential,
    onClick: (() -> Unit)? = null,
    /**
     * Long-press action - shows a Renew/Delete action menu (see
     * [CredentialsTab]'s `pendingActionMenuFor` state). Ignored (no gesture
     * registered) if null, same as [onClick].
     */
    onLongClick: (() -> Unit)? = null,
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
        // A data: URI template can be hundreds of KB - logging it verbatim
        // both floods logcat and gets silently truncated mid-base64 by its
        // per-entry size limit, useless either way. Log its scheme/length
        // instead; an http(s) URI is short and safe to log in full.
        val uriDescription = if (template.uri.startsWith("data:")) {
            "data: URI (${template.uri.length} chars)"
        } else {
            template.uri
        }
        Timber.i(
            "CredentialCard ${credential.id} (${meta.vct ?: meta.doctype}): using SVG template " +
                "$uriDescription (colorScheme=${template.colorScheme})",
        )
        val cacheKey = svgRenderCacheKey(credential, template.uri, preferredScheme, bgColor)
        val cached = svgRenderCache.get(cacheKey)
        val payload = if (cached != null) {
            Timber.i("CredentialCard ${credential.id}: using cached SVG render")
            cached
        } else {
            fetchAndSubstituteSvg(credential, template.uri, bgColor)?.also {
                svgRenderCache.put(cacheKey, it)
            }
        }
        svgState = if (payload != null) {
            SvgLoadState.Loaded(payload.svgBytes, payload.backgroundImageBytes)
        } else {
            SvgLoadState.Failed
        }
    }
    val svgImageLoader = remember(context) {
        ImageLoader.Builder(context).components { add(SvgDecoder.Factory()) }.build()
    }

    Card(
        modifier = modifier
            .fillMaxWidth()
            .aspectRatio(1.6f)
            .then(
                if (!isExhausted && (onClick != null || onLongClick != null)) {
                    Modifier.combinedClickable(onClick = onClick ?: {}, onLongClick = onLongClick)
                } else {
                    Modifier
                },
            ),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = bgColor),
        elevation = CardDefaults.cardElevation(defaultElevation = 4.dp),
    ) {
        Box {
            when (val state = svgState) {
                is SvgLoadState.Loaded -> {
                    // The full-bleed background (if any) is decoded through Coil's
                    // normal bitmap path, not svgImageLoader/AndroidSVG - see
                    // extractFullBleedBackgroundImage's doc comment for why.
                    if (state.backgroundImageBytes != null) {
                        coil.compose.AsyncImage(
                            model = state.backgroundImageBytes,
                            contentDescription = null,
                            modifier = Modifier.fillMaxSize(),
                            contentScale = ContentScale.FillBounds,
                        )
                    }
                    coil.compose.AsyncImage(
                        model = ImageRequest.Builder(context)
                            .data(state.svgBytes)
                            .size(829, 504)
                            .build(),
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
    /**
     * [svgBytes] is the (possibly image-stripped, see [extractFullBleedBackgroundImage])
     * SVG markup; [backgroundImageBytes] is a full-bleed raster `<image>` pulled
     * out of it to be decoded and drawn separately - confirmed via live
     * hardware testing that coil-svg/AndroidSVG mis-renders a full-card
     * embedded base64 `<image>` (a stable ~30%-down dark band that isn't
     * present in the image's own pixel data, doesn't reproduce with inkscape
     * on the exact same bytes, and doesn't reproduce at all on a
     * template with no embedded `<image>`), so the raster background is
     * decoded through Coil's normal (non-SVG) bitmap path instead and
     * layered underneath the (now `<image>`-free) SVG's vector/text content.
     */
    data class Loaded(val svgBytes: ByteArray, val backgroundImageBytes: ByteArray?) : SvgLoadState()
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
private data class SvgRenderPayload(val svgBytes: ByteArray, val backgroundImageBytes: ByteArray?)

/**
 * Process-lifetime cache of rendered card SVGs, keyed by everything that
 * can affect the output (credential, template, color scheme, background).
 * Without this, every recomposition of [CredentialCard] - not just app
 * launch, but every navigation back to the credential list - redid the
 * full fetch/decode-base64 + claim-substitution + viewBox/height/contrast-
 * correction + background-image-extraction pipeline from scratch, even
 * though the result is fully deterministic for a given credential (whose
 * `raw` bytes and metadata never change in place - renewal replaces the
 * whole [StoredCredential] under a new id, per the batch-replacement
 * pattern, rather than mutating one) plus render parameters. 64 entries is
 * comfortably above a realistic on-screen credential count; this is a
 * memory cache only (cleared on process death), not a disk cache - stale
 * output from a leaked cache entry would be a worse bug than a cache miss
 * after a process restart.
 */
private val svgRenderCache = android.util.LruCache<String, SvgRenderPayload>(64)

private fun svgRenderCacheKey(
    credential: StoredCredential,
    templateUri: String,
    colorScheme: String,
    cardBackground: Color,
): String = "${credential.id}|$templateUri|$colorScheme|${cardBackground.value}"

private suspend fun fetchAndSubstituteSvg(credential: StoredCredential, templateUri: String, cardBackground: Color): SvgRenderPayload? {
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
            val viewBoxed = ensureSvgViewBox(substituted)
            val sized = ensureSvgImageHeight(viewBoxed)
            val corrected = correctSvgTextContrast(sized, cardBackground)
            val (stripped, backgroundBytes) = extractFullBleedBackgroundImage(corrected)
            if (backgroundBytes != null) {
                Timber.i("CredentialCard ${credential.id}: extracted a full-bleed background <image> (${backgroundBytes.size} bytes) to render outside AndroidSVG")
            }
            SvgRenderPayload(stripped.toByteArray(Charsets.UTF_8), backgroundBytes)
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

/** Matches the outer `<svg ...>` root tag's opening portion, up to (not including) its `>`. */
private val SVG_ROOT_TAG_OPEN = Regex("""<svg\b[^>]*""")

/** True if a tag string already declares a `viewBox` attribute. */
private val SVG_HAS_VIEWBOX_ATTR = Regex("""\bviewBox=["']""")

/** True if a tag string already declares a `preserveAspectRatio` attribute. */
private val SVG_HAS_PRESERVE_ASPECT_RATIO_ATTR = Regex("""\bpreserveAspectRatio=["']""")

/** Matches a plain-number `width="NNN"`/`height="NNN"` attribute (no unit, no `%`) within an isolated tag string. */
private val SVG_DIMENSION_ATTR = Regex("""\b(width|height)=(["'])(\d+(?:\.\d+)?)\2""")

/**
 * Injects a `viewBox` on the SVG root when it's missing entirely, derived
 * from the root's own plain-number `width`/`height` attributes.
 *
 * Confirmed necessary via live testing: a real issuer's SVG credential
 * template (wwwallet.org's demo PID) declares `<svg width="829"
 * height="504" version="1.1">` with NO `viewBox` at all. Without one,
 * percentage dimensions on children (e.g. [ensureSvgImageHeight]'s
 * `width="100%"` background image) are only unambiguous if every renderer
 * resolves them against the SAME reference size - some resolve against the
 * root's declared width/height, others against whatever pixel canvas they
 * actually decide to rasterize into (which won't exactly match 829x504
 * when the surrounding UI's own aspect ratio differs, however slightly).
 * That mismatch showed up as the whole graphic rendering visibly shifted.
 * An explicit `viewBox="0 0 829 504"` removes the ambiguity outright: every
 * spec-compliant renderer resolves percentages against the viewBox, and
 * fits that fixed coordinate space into whatever final size it's asked
 * for via its own well-defined scaling transform, not per-element guesswork.
 *
 * That fitting transform is where a SECOND bug surfaced, confirmed by
 * rendering the same template through both a browser `<img>` (CSS
 * `object-fit` overrides SVG-internal fitting, so no gap) and an `<object>`
 * embed at a deliberately mismatched aspect ratio (SVG-internal fitting
 * applies, and a visible gap appeared): adding a `viewBox` with no
 * `preserveAspectRatio` activates the SVG default, `xMidYMid meet` -
 * uniform scale-to-fit, letterboxing whichever axis doesn't exactly match.
 * On device, this API's Card composable already stretches non-uniformly to
 * fill (`ContentScale.FillBounds`) - the on-device Android SVG decoder
 * apparently rasterizes at a size whose aspect ratio doesn't match this
 * template's, and `xMidYMid meet`'s letterbox gap baked directly into the
 * decoded bitmap survives that later stretch untouched, showing as the
 * Card's own flat background color visibly filling a fraction of the
 * card. `preserveAspectRatio="none"` (added alongside the viewBox)
 * disables that letterboxing, matching what `FillBounds` already wants.
 *
 * A no-op when a `viewBox` already exists, or when the root's `width`/
 * `height` aren't both plain numbers (e.g. already percentages, or
 * missing) - there's nothing safe to derive a viewBox from in that case.
 */
internal fun ensureSvgViewBox(svg: String): String {
    val rootMatch = SVG_ROOT_TAG_OPEN.find(svg) ?: return svg
    val rootTag = rootMatch.value
    if (SVG_HAS_VIEWBOX_ATTR.containsMatchIn(rootTag)) return svg

    val dimensions = SVG_DIMENSION_ATTR.findAll(rootTag).associate { it.groupValues[1] to it.groupValues[3] }
    val width = dimensions["width"] ?: return svg
    val height = dimensions["height"] ?: return svg

    val preserveAspectRatio = if (SVG_HAS_PRESERVE_ASPECT_RATIO_ATTR.containsMatchIn(rootTag)) {
        ""
    } else {
        " preserveAspectRatio=\"none\""
    }
    return svg.replaceRange(rootMatch.range, "$rootTag viewBox=\"0 0 $width $height\"$preserveAspectRatio")
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

/** Matches an `x="0"`/`y="0"` attribute (any whitespace-equivalent zero), within an already-isolated tag string. */
private val SVG_IMAGE_ZERO_ATTR = mapOf(
    "x" to Regex("""\bx=(["'])0(?:\.0+)?\1"""),
    "y" to Regex("""\by=(["'])0(?:\.0+)?\1"""),
)

/** Matches a `height="NN%"`/`height='NN%'` attribute within an already-isolated tag string. */
private val SVG_IMAGE_HEIGHT_PERCENT_ATTR = Regex("""height=(["'])(\d+%)\1""")

/** Captures an embedded raster `xlink:href="data:image/<mime>;base64,<data>"` (or bare `href=`) value. */
private val SVG_IMAGE_DATA_HREF = Regex("""(?:xlink:href|href)=(["'])data:image/(png|jpeg|jpg|webp);base64,([^"']*)\1""")

/**
 * Pulls a full-card raster `<image>` (x=0, y=0, width=100%, height=100%,
 * embedded as a base64 data URI) out of [svg] entirely, returning the
 * decoded image bytes alongside the SVG with that element removed.
 *
 * Confirmed via live hardware testing (real YubiKey-issued PID credential,
 * 2026-08-10): the exact SVG bytes handed to Coil render perfectly via
 * `inkscape` on a desktop, and the extracted PNG's own pixel data is a
 * uniform light-blue field with no dark region anywhere in it - yet the
 * on-device render (coil-svg / AndroidSVG) consistently shows a dark band
 * roughly 30% down the card. A sibling template with no embedded `<image>`
 * at all (a diploma credential, otherwise passing through the exact same
 * [ensureSvgViewBox]/[ensureSvgImageHeight]/[correctSvgTextContrast]
 * pipeline) renders correctly. That isolates the bug to AndroidSVG's
 * handling of a large embedded base64 `<image>` specifically, not the SVG
 * markup or this app's own substitution logic - so instead of asking
 * AndroidSVG to composite the raster background, it's decoded and drawn as
 * a plain bitmap layer underneath the (now image-free) SVG, which only has
 * to render vector/text content - the same kind of content the working
 * diploma template consists of.
 *
 * Deliberately narrow: only a `<image>` that is unambiguously "cover the
 * whole card" (x=0, y=0, width=100%, height=100%) is extracted. A smaller,
 * absolute-positioned `<image>` (e.g. this same template's placeholder
 * photo) is left in place for AndroidSVG to render as before - there's no
 * evidence that case is affected, and it isn't large enough to be a likely
 * source of the same bug.
 */
internal fun extractFullBleedBackgroundImage(svg: String): Pair<String, ByteArray?> {
    val match = SVG_IMAGE_TAG.findAll(svg).firstOrNull { tagMatch ->
        val tag = tagMatch.value
        SVG_IMAGE_ZERO_ATTR.getValue("x").containsMatchIn(tag) &&
            SVG_IMAGE_ZERO_ATTR.getValue("y").containsMatchIn(tag) &&
            SVG_IMAGE_WIDTH_PERCENT_ATTR.find(tag)?.groupValues?.get(2) == "100%" &&
            SVG_IMAGE_HEIGHT_PERCENT_ATTR.find(tag)?.groupValues?.get(2) == "100%"
    } ?: return svg to null

    val hrefMatch = SVG_IMAGE_DATA_HREF.find(match.value) ?: return svg to null
    val bytes = try {
        java.util.Base64.getDecoder().decode(hrefMatch.groupValues[3])
    } catch (e: IllegalArgumentException) {
        Timber.w(e, "Failed to decode embedded background <image> data URI")
        return svg to null
    }
    return svg.replaceRange(match.range, "") to bytes
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

/**
 * Result of normalizing a logo/preview SVG: [model] is what a Coil
 * `AsyncImage`/`SubcomposeAsyncImage` should load as the (possibly
 * `<image>`-stripped) foreground layer; [backgroundImageBytes] is a
 * full-bleed raster `<image>` pulled out of it (see
 * [extractFullBleedBackgroundImage]) that must be drawn as a separate
 * bitmap layer *underneath* [model] - null when there was nothing to
 * extract, in which case a caller can render [model] alone exactly as
 * before this type existed.
 */
internal data class NormalizedLogo(val model: Any, val backgroundImageBytes: ByteArray? = null)

/**
 * Async counterpart to [coilLogoModel] for logo/preview URIs that need
 * fetching (remote `http(s)`) rather than just base64-decoding an already-
 * inline `data:` URI. Applies the same [ensureSvgViewBox]/
 * [ensureSvgImageHeight]/[extractFullBleedBackgroundImage] normalization an
 * already-stored credential's card SVG gets in [fetchAndSubstituteSvg] -
 * without it, a logo/preview URI pointing at an SVG whose `<image>` element
 * omits `height` (a real, confirmed-live issuer template:
 * demo-issuer.wwwallet.org's EHIC card) renders fully blank with no error,
 * or - if the SVG has a full-bleed embedded raster `<image>` - renders with
 * AndroidSVG's confirmed ~30%-down dark-band mis-render (see
 * [extractFullBleedBackgroundImage]'s doc comment), since the plain
 * [coilLogoModel] path (used by the Add Credentials offer list and the
 * stored-credential detail screen, neither of which goes through
 * [fetchAndSubstituteSvg]'s pipeline) hands Coil the untouched SVG
 * bytes/URI.
 *
 * Falls back to [coilLogoModel]'s existing behavior (or the raw [uri]) on
 * any fetch/decode failure - never worse than what callers had before this
 * function existed.
 */
internal suspend fun fetchAndNormalizeLogoModel(uri: String): NormalizedLogo {
    if (uri.startsWith("data:")) {
        if (!uri.startsWith("data:image/svg+xml", ignoreCase = true)) {
            return NormalizedLogo(coilLogoModel(uri))
        }
        val svgText = decodeSvgDataUri(uri) ?: return NormalizedLogo(coilLogoModel(uri))
        return normalizeSvgLogoOrFallback(svgText, uri)
    }
    if (!uri.startsWith("http")) return NormalizedLogo(uri)
    return try {
        withContext(Dispatchers.IO) {
            val request = Request.Builder().url(uri).build()
            svgHttpClient.newCall(request).execute().use { response ->
                val body = if (response.isSuccessful) response.body?.string() else null
                if (body == null) {
                    NormalizedLogo(uri)
                } else {
                    val contentType = response.header("Content-Type") ?: ""
                    val looksLikeSvg = contentType.contains("svg", ignoreCase = true) ||
                        body.trimStart().startsWith("<svg", ignoreCase = true)
                    if (looksLikeSvg) normalizeSvgLogoOrFallback(body, uri) else NormalizedLogo(uri)
                }
            }
        }
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        Timber.w(e, "Failed to fetch/normalize remote logo: $uri")
        NormalizedLogo(uri)
    }
}

private fun normalizeSvgLogoOrFallback(svgText: String, fallback: String): NormalizedLogo = try {
    val sized = ensureSvgImageHeight(ensureSvgViewBox(svgText))
    val (stripped, backgroundBytes) = extractFullBleedBackgroundImage(sized)
    NormalizedLogo(stripped.toByteArray(Charsets.UTF_8), backgroundBytes)
} catch (e: Exception) {
    Timber.w(e, "Failed to normalize logo SVG, falling back: $fallback")
    NormalizedLogo(fallback)
}

/**
 * Remembers a [NormalizedLogo] for [uri] via [fetchAndNormalizeLogoModel],
 * starting from [coilLogoModel]'s synchronous result so there's no
 * flash-of-nothing while the async fetch/normalize is in flight - it just
 * gets replaced once ready, identically to the synchronous behavior for any
 * URI the normalization doesn't end up touching.
 */
@Composable
internal fun rememberNormalizedLogoModel(uri: String): NormalizedLogo {
    var logo by remember(uri) { mutableStateOf(NormalizedLogo(coilLogoModel(uri))) }
    LaunchedEffect(uri) {
        logo = fetchAndNormalizeLogoModel(uri)
    }
    return logo
}
