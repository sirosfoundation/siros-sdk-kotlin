// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.ui.graphics.Color
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `coilLogoModel` works around Coil's default components not decoding a
 * `data:` URI *string* on their own (they only handle raw byte arrays, via
 * the built-in `ByteArrayMapper` -> `ByteBufferFetcher`) - issuer-published
 * logos are frequently embedded this way (e.g.
 * geneva2026.mdoc.online's `credential_metadata.display[].logo.uri`), which
 * silently failed to render before this fix.
 */
class CredentialCardTest {

    @Test
    fun `decodes a base64 data URI into raw bytes`() {
        val payload = "hello logo bytes".toByteArray(Charsets.UTF_8)
        val encoded = java.util.Base64.getEncoder().encodeToString(payload)
        val uri = "data:image/png;base64,$encoded"

        val model = coilLogoModel(uri)

        assertArrayEquals(payload, model as ByteArray)
    }

    @Test
    fun `leaves an http url unchanged`() {
        val uri = "https://issuer.example.com/logo.png"
        assertEquals(uri, coilLogoModel(uri))
    }

    @Test
    fun `leaves a non-base64 data URI unchanged`() {
        // e.g. a URL-encoded (not base64) data URI - not what we're built to unwrap.
        val uri = "data:image/svg+xml,%3Csvg%2F%3E"
        assertEquals(uri, coilLogoModel(uri))
    }

    @Test
    fun `falls back to the original string when the payload is not valid base64`() {
        val uri = "data:image/png;base64,not-valid-base64!!!"
        assertEquals(uri, coilLogoModel(uri))
    }

    // ── contrastRatio / MIN_READABLE_CONTRAST_RATIO ────────────────────
    //
    // A real credential card's issuer-declared text/background color pair
    // rendered nearly unreadable (confirmed via live testing) - the fix
    // (see CredentialCard.kt) only honors a declared textColor if it clears
    // this ratio, falling back to a computed high-contrast color otherwise.

    @Test
    fun `contrastRatio is maximal for black on white`() {
        assertEquals(21f, contrastRatio(Color.Black, Color.White), 0.01f)
    }

    @Test
    fun `contrastRatio is minimal for identical colors`() {
        assertEquals(1f, contrastRatio(Color(0xFF1B4587), Color(0xFF1B4587)), 0.01f)
    }

    @Test
    fun `contrastRatio is symmetric regardless of argument order`() {
        val a = Color(0xFF1B4587)
        val b = Color(0xFFF3F4F6)
        assertEquals(contrastRatio(a, b), contrastRatio(b, a), 0.001f)
    }

    @Test
    fun `a poor issuer-declared pairing falls below the minimum readable ratio`() {
        // Two similarly-dark, similarly-saturated blues - exactly the kind
        // of "technically different but practically illegible" pairing an
        // issuer's own branding can produce.
        val background = Color(0xFF1B4587)
        val declaredText = Color(0xFF3D66A7)
        assertTrue(
            "a near-identical-luminance pairing must be rejected as unreadable",
            contrastRatio(declaredText, background) < MIN_READABLE_CONTRAST_RATIO,
        )
    }

    @Test
    fun `a strong pairing clears the minimum readable ratio`() {
        val background = Color(0xFF1B4587)
        assertTrue(contrastRatio(Color.White, background) >= MIN_READABLE_CONTRAST_RATIO)
    }

    // ── correctSvgTextContrast ──────────────────────────────────────────
    //
    // Confirmed necessary via live testing: a real issuer's SVG credential
    // template (wwwallet.org's demo PID) baked in unreadable text-color
    // contrast against its own background, and SvgTemplateRenderer.substitute
    // only replaces {{claimId}} text tokens - it never touches SVG styling.

    @Test
    fun `overrides a text fill that fails the contrast check`() {
        val background = Color(0xFF1B4587) // dark navy
        val svg = """<svg><text fill="#3D66A7" x="0" y="0">Alice</text></svg>"""

        val corrected = correctSvgTextContrast(svg, background)

        assertTrue("a low-contrast fill must not survive unchanged", "fill=\"#3D66A7\"" !in corrected)
        assertTrue("Alice" in corrected)
    }

    @Test
    fun `leaves an already-adequate-contrast fill untouched`() {
        val background = Color(0xFF1B4587) // dark navy
        val svg = """<svg><text fill="#FFFFFF" x="0" y="0">Alice</text></svg>"""

        val corrected = correctSvgTextContrast(svg, background)

        assertEquals("a fill that already contrasts well must not be rewritten", svg, corrected)
    }

    @Test
    fun `corrects fill on both text and tspan elements`() {
        val background = Color(0xFF1B4587)
        val svg = """<svg><text fill="#3D66A7"><tspan fill="#3D66A7">Alice</tspan></text></svg>"""

        val corrected = correctSvgTextContrast(svg, background)

        assertEquals(0, Regex("""fill="#3D66A7"""").findAll(corrected).count())
    }

    @Test
    fun `leaves an element with no fill attribute unchanged`() {
        val background = Color(0xFF1B4587)
        val svg = """<svg><text x="0" y="0">Alice</text></svg>"""

        assertEquals(svg, correctSvgTextContrast(svg, background))
    }

    @Test
    fun `leaves a non-hex fill (inherited or named color) unchanged`() {
        val background = Color(0xFF1B4587)
        val svg = """<svg><text fill="currentColor" x="0" y="0">Alice</text></svg>"""

        // Not resolvable without a full DOM/style walk - documented
        // limitation, not a bug: must be left exactly as the issuer wrote it.
        assertEquals(svg, correctSvgTextContrast(svg, background))
    }

    @Test
    fun `does not touch fill on non-text elements like rect or path`() {
        val background = Color(0xFF1B4587)
        val svg = """<svg><rect fill="#3D66A7" width="10" height="10"/><text fill="#FFFFFF">Alice</text></svg>"""

        // A shape's fill is decorative, not text-legibility-critical -
        // only <text>/<tspan> elements are in scope for correction.
        assertTrue("fill=\"#3D66A7\"" in correctSvgTextContrast(svg, background))
    }

    // ── ensureSvgViewBox ─────────────────────────────────────────────────
    //
    // Confirmed necessary via live testing: a real issuer's SVG credential
    // template (wwwallet.org's demo PID) has its root <svg width="829"
    // height="504" version="1.1"> declare NO viewBox at all - without one,
    // percentage dimensions on children only resolve consistently if every
    // renderer picks the same reference size, which isn't guaranteed. The
    // symptom was the whole graphic rendering visibly shifted/distorted.

    @Test
    fun `injects a viewBox and preserveAspectRatio=none derived from width and height when both are plain numbers`() {
        val svg = """<svg xmlns="http://www.w3.org/2000/svg" width="829"
	height="504" version="1.1">
	<image width="100%" xlink:href="data:image/png;base64,AAA=" />
</svg>"""

        val result = ensureSvgViewBox(svg)

        assertTrue("viewBox=\"0 0 829 504\"" in result)
        // Confirmed necessary via rendering the same template through a
        // browser <object> embed at a deliberately mismatched aspect ratio:
        // a viewBox with no preserveAspectRatio activates the SVG default
        // (xMidYMid meet), which letterboxes - the gap is baked into the
        // decoded bitmap and survives Compose's own FillBounds stretch
        // untouched, showing as the Card's flat background color filling
        // part of the card.
        assertTrue("preserveAspectRatio=\"none\"" in result)
    }

    @Test
    fun `leaves an svg that already has a viewBox unchanged`() {
        val svg = """<svg width="829" height="504" viewBox="0 0 829 504"><image width="100%" /></svg>"""

        assertEquals(svg, ensureSvgViewBox(svg))
    }

    @Test
    fun `does not override an already-declared preserveAspectRatio`() {
        val svg = """<svg width="829" height="504" preserveAspectRatio="xMidYMid slice"><image width="100%" /></svg>"""

        val result = ensureSvgViewBox(svg)

        assertTrue("viewBox=\"0 0 829 504\"" in result)
        assertTrue("preserveAspectRatio=\"xMidYMid slice\"" in result)
        assertTrue("preserveAspectRatio=\"none\"" !in result)
    }

    @Test
    fun `leaves an svg with a percentage width or height unchanged`() {
        val svg = """<svg width="100%" height="504"><image width="100%" /></svg>"""

        assertEquals(svg, ensureSvgViewBox(svg))
    }

    @Test
    fun `leaves an svg missing width or height unchanged`() {
        val svg = """<svg height="504"><image width="100%" /></svg>"""

        assertEquals(svg, ensureSvgViewBox(svg))
    }

    // ── ensureSvgImageHeight ────────────────────────────────────────────
    //
    // Confirmed necessary via live testing: a real issuer's SVG credential
    // template (wwwallet.org's demo PID) has its full-bleed background
    // <image> declare width="100%" with NO height attribute at all - per
    // SVG 1.1 (which this template declares via version="1.1"), that
    // defaults height to 0 (invisible) unless the renderer implements the
    // newer SVG2/CSS auto-sizing fallback, which this app's Android SVG
    // decoder apparently doesn't. The graphic never appeared; only this
    // card's own flat backgroundColor showed through.

    @Test
    fun `injects height on a self-closing percentage-width image with no height`() {
        // Mirrors the real template's actual self-closing background image tag.
        val svg = """<svg><image x="0" y="0" width="100%" xlink:href="data:image/png;base64,AAA=" /></svg>"""

        val result = ensureSvgImageHeight(svg)

        assertTrue("height=\"100%\"" in result)
        assertTrue("width=\"100%\"" in result)
        // Must still be a valid self-closing tag, not a mangled one with a stray "/".
        assertTrue(result.contains("""height="100%" />"""))
    }

    @Test
    fun `injects height on a non-self-closing percentage-width image with no height`() {
        val svg = """<svg><image width="100%" xlink:href="data:image/png;base64,AAA="></image></svg>"""

        val result = ensureSvgImageHeight(svg)

        assertTrue("height=\"100%\"" in result)
        assertTrue(result.contains("""height="100%">"""))
    }

    @Test
    fun `leaves an image with an already-declared height unchanged`() {
        val svg = """<svg><image width="100%" height="50%" xlink:href="data:image/png;base64,AAA=" /></svg>"""

        assertEquals(svg, ensureSvgImageHeight(svg))
    }

    @Test
    fun `leaves an absolute-unit-width image with no height unchanged`() {
        // Mirrors the same real template's separate placeholder-photo image
        // (width="220", an absolute unit) - correctly sizing this would need
        // the embedded image's own intrinsic pixel dimensions, not attempted.
        val svg = """<svg><image x="45" y="100" width="220" href="{{picture}}" preserveAspectRatio="xMidYMid meet" /></svg>"""

        assertEquals(svg, ensureSvgImageHeight(svg))
    }

    @Test
    fun `leaves an image with no width attribute at all unchanged`() {
        val svg = """<svg><image xlink:href="data:image/png;base64,AAA=" /></svg>"""

        assertEquals(svg, ensureSvgImageHeight(svg))
    }

    @Test
    fun `corrects only the background image, leaving the placeholder photo image untouched`() {
        // The real template has exactly this shape: one full-bleed
        // percentage-width background image needing correction, and one
        // absolute-width placeholder photo image that must be left alone.
        val svg = """<svg>
            |<image x="0" y="0" width="100%" xlink:href="data:image/png;base64,AAA=" />
            |<image x="45" y="100" width="220" href="{{picture}}" preserveAspectRatio="xMidYMid meet" />
            |</svg>
        """.trimMargin()

        val result = ensureSvgImageHeight(svg)

        // height is always appended at the very end of the tag (after
        // whatever attributes, like the long xlink:href, originally
        // followed width), not spliced in right next to width.
        assertTrue("""width="100%" xlink:href="data:image/png;base64,AAA=" height="100%" />""" in result)
        assertTrue("""width="220" href="{{picture}}"""" in result)
        assertEquals("only the background image's tag should have gained a height", 1, Regex("""height="100%"""").findAll(result).count())
    }

    // ── extractFullBleedBackgroundImage ────────────────────────────────
    //
    // Confirmed necessary via live testing: a real PID credential's SVG
    // template's exact final bytes render perfectly outside the app
    // (inkscape) and its embedded PNG is pixel-uniform with no dark region,
    // yet coil-svg/AndroidSVG still rendered a ~30%-down dark band on
    // device - while a sibling template with no embedded <image> at all
    // (a diploma credential, same pipeline otherwise) rendered correctly.
    // That isolates AndroidSVG's handling of a large embedded base64
    // <image> as the bug, so it's pulled out and decoded via Coil's normal
    // bitmap path instead.

    private val TINY_PNG_BASE64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="

    @Test
    fun `extracts a full-bleed background image and strips it from the svg`() {
        val svg = """<svg viewBox="0 0 829 504">
            |<image x="0" y="0" width="100%" height="100%" xlink:href="data:image/png;base64,$TINY_PNG_BASE64" />
            |<text fill="#000000">Hello</text>
            |</svg>
        """.trimMargin()

        val (stripped, bytes) = extractFullBleedBackgroundImage(svg)

        assertTrue("background bytes should be decoded", bytes != null && bytes.isNotEmpty())
        assertTrue("stripped svg must not contain the extracted <image>", "<image" !in stripped)
        assertTrue("stripped svg must keep unrelated content", "<text" in stripped)
    }

    @Test
    fun `leaves a smaller absolute-positioned placeholder image in place`() {
        val svg = """<svg><image x="45" y="100" width="220" height="150" href="{{picture}}" /></svg>"""

        val (stripped, bytes) = extractFullBleedBackgroundImage(svg)

        assertEquals(svg, stripped)
        assertEquals(null, bytes)
    }

    @Test
    fun `leaves an svg with no image element unchanged`() {
        val svg = """<svg><rect width="100%" height="100%" fill="#fff" /></svg>"""

        val (stripped, bytes) = extractFullBleedBackgroundImage(svg)

        assertEquals(svg, stripped)
        assertEquals(null, bytes)
    }

    // ── decodeSvgDataUri ──────────────────────────────────────────────
    //
    // Confirmed necessary via live testing: re-issuing a credential caused
    // svgTemplates[].uri to arrive as a data:image/svg+xml;base64,... URI
    // instead of an https:// one (same underlying template, different
    // delivery) - fetchAndSubstituteSvg's OkHttp fetch throws
    // IllegalArgumentException for a non-http(s) scheme, so this must be
    // decoded directly instead of fetched.

    @Test
    fun `decodes a base64 data URI SVG template`() {
        val svg = """<svg xmlns="http://www.w3.org/2000/svg"><text>Alice</text></svg>"""
        val encoded = java.util.Base64.getEncoder().encodeToString(svg.toByteArray(Charsets.UTF_8))
        val uri = "data:image/svg+xml;base64,$encoded"

        assertEquals(svg, decodeSvgDataUri(uri))
    }

    @Test
    fun `decodes a URL-encoded (non-base64) data URI SVG template`() {
        val uri = "data:image/svg+xml,%3Csvg%3E%3Ctext%3EAlice%3C%2Ftext%3E%3C%2Fsvg%3E"

        assertEquals("<svg><text>Alice</text></svg>", decodeSvgDataUri(uri))
    }

    @Test
    fun `returns null for invalid base64 payload in a data URI`() {
        val uri = "data:image/svg+xml;base64,not-valid-base64!!!"

        assertEquals(null, decodeSvgDataUri(uri))
    }

    @Test
    fun `returns null for a data URI with no comma separator`() {
        assertEquals(null, decodeSvgDataUri("data:image/svg+xml;base64"))
    }
}
