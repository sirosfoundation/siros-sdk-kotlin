// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

/**
 * Substitutes VCTM claim values into an SVG rendering template.
 *
 * VCTM's `rendering.svg_templates` (section 6) points at an SVG image; claims
 * with a `svg_id` are meant to fill placeholders inside it. In practice (e.g.
 * the dc4eu/vc image set used by real EUDI-style issuers) this is plain
 * Mustache-style text substitution - `{{claimSvgId}}` tokens inside `<text>`
 * elements - not DOM/id-attribute editing, so this is pure string
 * replacement, platform-agnostic and unit-testable without Android.
 */
object SvgTemplateRenderer {

    // Both closing braces must be escaped: the desktop JVM's regex engine
    // accepts a bare "}}" here, but Android's on-device ICU regex compiler
    // throws PatternSyntaxException on it - confirmed crashing on a real
    // device even though this compiled and passed fine in JVM unit tests.
    private val UNMATCHED_TOKEN = Regex("\\{\\{[^}]*\\}\\}")

    /**
     * Replace every `{{claim.svgId}}` token in [svgTemplate] with that claim's
     * resolved, XML-escaped value. Any token left over (a claim the VCTM
     * defines but that isn't present in this particular credential) is
     * blanked rather than shown to the user literally.
     */
    fun substitute(svgTemplate: String, claims: List<DisplayClaim>): String {
        var result = svgTemplate
        for (claim in claims) {
            val id = claim.svgId ?: continue
            result = result.replace("{{$id}}", escapeXml(claim.value))
        }
        return result.replace(UNMATCHED_TOKEN, "")
    }

    /** Escape characters that are special in XML text content/attributes. */
    fun escapeXml(value: String): String {
        return value
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&apos;")
    }
}
