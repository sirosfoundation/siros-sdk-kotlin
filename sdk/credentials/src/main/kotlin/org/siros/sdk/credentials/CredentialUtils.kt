// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import timber.log.Timber
import java.util.Base64

/**
 * Utilities for working with verifiable credentials and VCTM metadata.
 *
 * Provides helpers for:
 * - Parsing JWT/SD-JWT payloads
 * - Extracting claims with VCTM display labels
 * - Building [CredentialMetadata] from issuer metadata and VCTM
 * - Formatting claim keys for display
 */
object CredentialUtils {

    private val json = Json { ignoreUnknownKeys = true }

    private val JWT_SKIP_KEYS = setOf(
        "iss", "sub", "aud", "exp", "nbf", "iat", "jti",
        "_sd", "_sd_alg", "cnf", "vct", "status", "type",
    )

    /**
     * Parse the JWT payload from a raw credential string (JWT or SD-JWT).
     *
     * @return the payload as a [JsonObject], or null if parsing fails.
     */
    fun parseJwtPayload(raw: String): JsonObject? {
        return try {
            val jwtPart = raw.split("~").first()
            val parts = jwtPart.split(".")
            if (parts.size < 2) return null
            val payload = String(
                Base64.getUrlDecoder().decode(padBase64(parts[1])),
                Charsets.UTF_8,
            )
            json.parseToJsonElement(payload).jsonObject
        } catch (e: Exception) {
            Timber.w(e, "Failed to parse JWT payload")
            null
        }
    }

    /**
     * Extract user-facing claims from a credential, optionally using VCTM
     * claim metadata for display labels.
     *
     * @param credential the stored credential
     * @return list of [DisplayClaim] with label, value, and optional description
     */
    fun extractClaims(credential: StoredCredential): List<DisplayClaim> {
        val payload = parseJwtPayload(credential.raw) ?: return emptyList()
        val vctmClaims = credential.metadata?.claims
        val claimLabels = buildClaimLabelMap(vctmClaims)

        return payload.entries
            .filter { it.key !in JWT_SKIP_KEYS }
            .map { (key, value) ->
                val labelInfo = claimLabels[key]
                DisplayClaim(
                    key = key,
                    label = labelInfo?.label ?: formatClaimKey(key),
                    value = formatClaimValue(value),
                    description = labelInfo?.description,
                    mandatory = labelInfo?.mandatory ?: false,
                )
            }
    }

    /**
     * Build [CredentialMetadata] by combining issuer display metadata with VCTM.
     *
     * Call this when storing a new credential to populate its metadata from
     * the issuer metadata and VCTM response.
     *
     * @param offer the credential offer used during issuance
     * @param vctm the fetched VCTM, if available
     * @param rawCredential the raw credential string (for extracting vct/exp/iat)
     * @return populated [CredentialMetadata]
     */
    fun buildMetadata(
        offer: CredentialOffer,
        vctm: Vctm? = null,
        rawCredential: String? = null,
    ): CredentialMetadata {
        // Use VCTM display if available, prefer user's locale
        val locale = java.util.Locale.getDefault().toLanguageTag()
        val vctmDisplay = vctm?.display?.let { displays ->
            displays.find { it.locale == locale }
                ?: displays.find { it.locale.startsWith(locale.take(2)) }
                ?: displays.firstOrNull()
        }

        val simple = vctmDisplay?.rendering?.simple

        // Extract VCT from credential payload
        val payload = rawCredential?.let { parseJwtPayload(it) }
        val vct = payload?.get("vct")?.jsonPrimitive?.content

        // Build claim metadata from VCTM
        val claims = vctm?.claims?.map { claim ->
            val claimDisplay = claim.display?.let { displays ->
                displays.find { it.locale == locale }
                    ?: displays.find { it.locale.startsWith(locale.take(2)) }
                    ?: displays.firstOrNull()
            }
            ClaimMeta(
                path = claim.path.filterNotNull(),
                label = claimDisplay?.label,
                description = claimDisplay?.description,
                sd = claim.sd,
                mandatory = claim.mandatory ?: false,
            )
        }

        return CredentialMetadata(
            name = vctmDisplay?.name ?: offer.credentialName,
            description = vctmDisplay?.description ?: offer.credentialDescription,
            issuer = IssuerInfo(
                name = offer.issuerName,
                url = offer.credentialIssuerIdentifier,
            ),
            vct = vct,
            backgroundColor = simple?.backgroundColor
                ?: offer.backgroundColor,
            textColor = simple?.textColor
                ?: offer.textColor,
            logo = (simple?.logo?.let { LogoInfo(uri = it.uri, altText = it.altText) })
                ?: offer.logoUri?.let { LogoInfo(uri = it) },
            claims = claims,
        )
    }

    /**
     * Build a lookup map from claim path (first element) to its VCTM label info.
     */
    private fun buildClaimLabelMap(claims: List<ClaimMeta>?): Map<String, ClaimMeta> {
        if (claims == null) return emptyMap()
        return claims
            .filter { it.path.isNotEmpty() }
            .associateBy { it.path.first() }
    }

    /**
     * Format a raw claim key like "given_name" into "Given Name".
     */
    fun formatClaimKey(key: String): String {
        return key.split("_", "-")
            .joinToString(" ") { it.replaceFirstChar { c -> c.uppercase() } }
    }

    /**
     * Format a JSON value for display.
     */
    private fun formatClaimValue(value: kotlinx.serialization.json.JsonElement): String {
        return when (value) {
            is kotlinx.serialization.json.JsonPrimitive -> value.content
            else -> value.toString()
        }
    }

    private fun padBase64(s: String): String {
        val rem = s.length % 4
        return if (rem == 0) s else s + "=".repeat(4 - rem)
    }
}

/**
 * A credential claim ready for display.
 */
data class DisplayClaim(
    /** Raw claim key (e.g. "given_name"). */
    val key: String,
    /** User-facing label from VCTM or formatted key (e.g. "Given Name"). */
    val label: String,
    /** Claim value as a string. */
    val value: String,
    /** Optional description from VCTM. */
    val description: String? = null,
    /** Whether this claim is mandatory. */
    val mandatory: Boolean = false,
)
