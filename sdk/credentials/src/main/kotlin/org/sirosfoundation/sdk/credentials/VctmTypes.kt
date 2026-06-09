// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.sirosfoundation.sdk.credentials

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * SD-JWT VC Type Metadata (VCTM) per draft-ietf-oauth-sd-jwt-vc section 6.
 *
 * VCTM provides display hints, claim metadata, and rendering information
 * that wallets use to present credentials in a user-friendly way.
 *
 * Typically fetched from `<issuer>/.well-known/vct/<vct-id>` or from a
 * dedicated endpoint like `<issuer>/type-metadata/<scope>`.
 */
@Serializable
data class Vctm(
    /** VCT identifier — must match the `vct` claim in the SD-JWT VC. */
    val vct: String,

    /** Human-readable name (for developers). */
    val name: String? = null,

    /** Human-readable description (for developers). */
    val description: String? = null,

    /** Locale-specific display entries for end users. */
    val display: List<VctmDisplay>? = null,

    /** Claim metadata: labels, SD rules, and rendering hints. */
    val claims: List<VctmClaim>? = null,

    /** URI of a parent type this type extends. */
    val extends: String? = null,

    /** JSON Schema URI for the credential. */
    @SerialName("schema_uri") val schemaUri: String? = null,
)

/**
 * Locale-specific display information for a credential type.
 */
@Serializable
data class VctmDisplay(
    /** BCP 47 language tag. */
    val locale: String,

    /** User-facing credential name. */
    val name: String,

    /** User-facing description. */
    val description: String? = null,

    /** Rendering properties (colors, logos, SVG templates). */
    val rendering: VctmRendering? = null,
)

/**
 * Rendering methods for credential display.
 */
@Serializable
data class VctmRendering(
    /** Simple rendering: colors and logo. */
    val simple: VctmSimpleRendering? = null,

    /** SVG template-based rendering. */
    @SerialName("svg_templates") val svgTemplates: List<VctmSvgTemplate>? = null,
)

@Serializable
data class VctmSimpleRendering(
    val logo: VctmLogo? = null,
    @SerialName("background_image") val backgroundImage: VctmLogo? = null,
    @SerialName("background_color") val backgroundColor: String? = null,
    @SerialName("text_color") val textColor: String? = null,
)

@Serializable
data class VctmLogo(
    val uri: String,
    @SerialName("uri#integrity") val uriIntegrity: String? = null,
    @SerialName("alt_text") val altText: String? = null,
)

@Serializable
data class VctmSvgTemplate(
    val uri: String,
    @SerialName("uri#integrity") val uriIntegrity: String? = null,
    val properties: VctmSvgProperties? = null,
)

@Serializable
data class VctmSvgProperties(
    val orientation: String? = null,
    @SerialName("color_scheme") val colorScheme: String? = null,
    val contrast: String? = null,
)

/**
 * Claim metadata per VCTM section 9.
 */
@Serializable
data class VctmClaim(
    /** JSON path elements selecting the claim. */
    val path: List<String?>,

    /** Locale-specific display labels and descriptions. */
    val display: List<VctmClaimDisplay>? = null,

    /** Selective disclosure rule: "always", "allowed", or "never". */
    val sd: String? = null,

    /** Whether this claim must be present. */
    val mandatory: Boolean? = null,

    /** SVG template placeholder ID. */
    @SerialName("svg_id") val svgId: String? = null,
)

@Serializable
data class VctmClaimDisplay(
    /** BCP 47 language tag. */
    val locale: String,

    /** User-facing label for the claim. */
    val label: String,

    /** User-facing description. */
    val description: String? = null,
)
