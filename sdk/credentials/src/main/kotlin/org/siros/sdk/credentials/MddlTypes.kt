// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.serialization.Serializable

/**
 * MDDL (mso_mdoc) schema type: the mdoc analogue of [Vctm], mirroring
 * `sirosfoundation/vc`'s `pkg/mdoc/schema.go` `MDDLSchema` field-for-field.
 * Drives mdoc issuance server-side and, here, gives the wallet a uniform way
 * to get display labels/claim metadata for mdoc credentials regardless of
 * format - the same role VCTM plays for SD-JWT.
 */
@Serializable
data class MddlSchema(
    val format: String,
    val doctype: String,
    val display: List<MddlDisplay>? = null,
    val claims: Map<String, Map<String, MddlClaimMeta>>? = null,
)

/** Localized display info for an MDDL schema, mirroring `MDDLSchema.Display`. */
@Serializable
data class MddlDisplay(
    val locale: String,
    val name: String,
    val description: String? = null,
    val logo: MddlLogo? = null,
    @kotlinx.serialization.SerialName("background_color") val backgroundColor: String? = null,
    @kotlinx.serialization.SerialName("text_color") val textColor: String? = null,
)

@Serializable
data class MddlLogo(
    val uri: String? = null,
    @kotlinx.serialization.SerialName("alt_text") val altText: String? = null,
)

/**
 * Metadata for a single mdoc data element within a namespace, mirroring
 * `ClaimMetadata` in `pkg/mdoc/schema.go`. `elements` describes nested
 * item/field shape for container (`array`/`map`) claims like
 * `driving_privileges`.
 */
@Serializable
data class MddlClaimMeta(
    val display: List<MddlClaimDisplay>? = null,
    val mandatory: Boolean = false,
    @kotlinx.serialization.SerialName("value_type") val valueType: String? = null,
    val elements: Map<String, MddlClaimMeta>? = null,
)

@Serializable
data class MddlClaimDisplay(
    val locale: String,
    val name: String,
)
