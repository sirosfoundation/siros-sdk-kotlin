// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.siros.sdk.credentials.mdoc.DocumentMdoc
import org.siros.sdk.credentials.mdoc.MdocCbor
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
     * Split a raw SD-JWT VC (`<jwt>~<disclosure>~<disclosure>~...`) into its
     * individually-decoded parts, for display purposes (e.g. a "Raw" debug
     * tab) - each disclosure is a separate JSON array per the SD-JWT spec, not
     * part of one opaque blob.
     */
    fun parseSdJwtParts(raw: String): SdJwtParts {
        val segments = raw.split("~")
        val jwtSegments = segments.firstOrNull()?.split(".") ?: emptyList()
        val header = jwtSegments.getOrNull(0)?.let { decodeJsonSegment(it) } as? JsonObject
        val payload = jwtSegments.getOrNull(1)?.let { decodeJsonSegment(it) } as? JsonObject
        val disclosures = segments.drop(1)
            .filter { it.isNotBlank() }
            .mapNotNull { decodeJsonSegment(it) }
        return SdJwtParts(header = header, payload = payload, disclosures = disclosures)
    }

    private fun decodeJsonSegment(base64url: String): JsonElement? {
        return try {
            val decoded = String(Base64.getUrlDecoder().decode(padBase64(base64url)), Charsets.UTF_8)
            json.parseToJsonElement(decoded)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Extract user-facing claims from a credential, optionally using VCTM
     * (or, for `mso_mdoc` credentials, MDDL) claim metadata for display labels.
     *
     * @param credential the stored credential
     * @return list of [DisplayClaim] with label, value, and optional description
     */
    fun extractClaims(credential: StoredCredential): List<DisplayClaim> {
        if (credential.format == "mso_mdoc") return extractMdocClaims(credential)
        val payload = parseJwtPayload(credential.raw) ?: return emptyList()
        val vctmClaims = credential.metadata?.claims.orEmpty()

        // VCTM claim paths can be arbitrarily nested (e.g. diploma's ELM schema
        // nests everything under credentialSubject) - each claim must be
        // resolved by walking its own full path, not just matched by its first
        // segment against a top-level key.
        val vctmResolved = vctmClaims.mapNotNull { claim ->
            if (claim.path.isEmpty()) return@mapNotNull null
            val value = resolveClaimPath(payload, claim.path) ?: return@mapNotNull null
            DisplayClaim(
                key = claim.path.joinToString("."),
                label = claim.label ?: formatClaimKey(claim.path.last()),
                value = formatClaimValue(value),
                description = claim.description,
                mandatory = claim.mandatory,
                svgId = claim.svgId,
            )
        }

        // Top-level keys already resolved (as an ancestor) via a VCTM path
        // shouldn't ALSO be dumped raw - e.g. once "credentialSubject.foo" is
        // resolved, don't separately dump the whole "credentialSubject" blob.
        val coveredTopLevelKeys = vctmClaims.mapNotNull { it.path.firstOrNull() }.toSet()
        val uncovered = payload.entries
            .filter { it.key !in JWT_SKIP_KEYS && it.key !in coveredTopLevelKeys }
            .map { (key, value) ->
                DisplayClaim(
                    key = key,
                    label = formatClaimKey(key),
                    value = formatClaimValue(value),
                )
            }

        return vctmResolved + uncovered
    }

    /**
     * mdoc analogue of [extractClaims]: parse a stored mdoc credential's
     * REAL disclosed namespace/element values (via [MdocCbor], not
     * [parseJwtPayload] which assumes a JWT-shaped `raw`) into [DisplayClaim]s,
     * using MDDL claim metadata (`credential.metadata.claims`, populated by
     * [buildMdocMetadata]) for labels/descriptions when available.
     *
     * Claim keys/paths use the `["namespace", "elementIdentifier"]` shape,
     * consistent with how [buildMdocMetadata] populates [ClaimMeta.path].
     */
    fun extractMdocClaims(credential: StoredCredential): List<DisplayClaim> {
        val document = parseMdocDocument(credential) ?: return emptyList()

        val claimMetaByPath = credential.metadata?.claims.orEmpty()
            .associateBy { it.path.joinToString("/") }

        return document.issuerSigned.nameSpaces.flatMap { (namespace, items) ->
            items.map { entry ->
                val elementId = entry.item.elementIdentifier
                val meta = claimMetaByPath["$namespace/$elementId"]
                DisplayClaim(
                    key = "$namespace.$elementId",
                    label = meta?.label ?: formatClaimKey(elementId),
                    value = formatCborValue(entry.item.elementValue),
                    description = meta?.description,
                    mandatory = meta?.mandatory ?: false,
                )
            }
        }
    }

    /**
     * Parse a stored mdoc credential's raw bytes into its [DocumentMdoc] - the
     * credential's own authoritative content (namespaces/items, and the real
     * `docType` embedded in its MSO), independent of [CredentialMetadata]
     * (which is best-effort display data from a network fetch that can fail,
     * e.g. for an mdoc issued by a third party with no MDDL schema endpoint at
     * all). DC API registry entries need the real docType for DCQL matching
     * even when display metadata never arrived - see the sample app's
     * DCAPICredentialEntryBuilder.
     */
    fun parseMdocDocument(credential: StoredCredential): DocumentMdoc? {
        return try {
            MdocCbor.parseStoredCredential(Base64.getUrlDecoder().decode(padBase64(credential.raw)))
        } catch (e: Exception) {
            Timber.w(e, "Failed to parse mdoc credential ${credential.id}")
            null
        }
    }

    /**
     * Build [CredentialMetadata] for an mdoc credential from its MDDL schema -
     * the mdoc analogue of [buildMetadata]. Populates [CredentialMetadata.doctype]
     * (unused for SD-JWT credentials) instead of [CredentialMetadata.vct].
     */
    fun buildMdocMetadata(offer: CredentialOffer, mddlSchema: MddlSchema? = null): CredentialMetadata {
        val locale = java.util.Locale.getDefault().toLanguageTag()
        val display = mddlSchema?.display?.let { displays ->
            displays.find { it.locale == locale }
                ?: displays.find { it.locale.startsWith(locale.take(2)) }
                ?: displays.firstOrNull()
        }

        val claims = mddlSchema?.claims?.flatMap { (namespace, elements) ->
            elements.map { (elementId, meta) ->
                val claimDisplay = meta.display?.let { displays ->
                    displays.find { it.locale == locale }
                        ?: displays.find { it.locale.startsWith(locale.take(2)) }
                        ?: displays.firstOrNull()
                }
                ClaimMeta(
                    path = listOf(namespace, elementId),
                    label = claimDisplay?.name,
                    mandatory = meta.mandatory,
                )
            }
        }

        return CredentialMetadata(
            name = display?.name ?: offer.credentialName,
            description = display?.description ?: offer.credentialDescription,
            issuer = IssuerInfo(name = offer.issuerName, url = offer.credentialIssuerIdentifier),
            doctype = mddlSchema?.doctype,
            backgroundColor = display?.backgroundColor ?: offer.backgroundColor,
            textColor = display?.textColor ?: offer.textColor,
            logo = display?.logo?.let { LogoInfo(uri = it.uri, altText = it.altText) }
                ?: offer.logoUri?.let { LogoInfo(uri = it) },
            claims = claims,
        )
    }

    /** Format a decoded CBOR element value for display. */
    private fun formatCborValue(value: com.upokecenter.cbor.CBORObject): String {
        return when (value.type) {
            com.upokecenter.cbor.CBORType.TextString -> value.AsString()
            com.upokecenter.cbor.CBORType.ByteString -> "<${value.GetByteString().size} bytes>"
            else -> value.toString()
        }
    }

    /**
     * Walk a VCTM claim path (e.g. ["credentialSubject", "hasClaim", "awardedBy"])
     * through nested JSON to the leaf value it selects. Returns null if any
     * segment is missing - the claim just isn't present in this credential.
     */
    private fun resolveClaimPath(root: JsonElement, path: List<String>): JsonElement? {
        var current: JsonElement = root
        for (segment in path) {
            current = (current as? JsonObject)?.get(segment) ?: return null
        }
        return current
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
                svgId = claim.svgId,
            )
        }

        val svgTemplates = vctmDisplay?.rendering?.svgTemplates?.map { template ->
            SvgTemplateInfo(
                uri = template.uri,
                colorScheme = template.properties?.colorScheme,
                contrast = template.properties?.contrast,
                orientation = template.properties?.orientation,
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
            svgTemplates = svgTemplates,
        )
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

    /**
     * Group stored credentials into display-ready families, mirroring
     * wallet-frontend's `CredentialsContextProvider.fetchVcData`: only the
     * `instanceId == 0` credential of a batch (see [StoredCredential.batchId])
     * is returned as a visible entry, with every sibling copy's usage count
     * attached as [CredentialWithInstances.instances] - the UI derives its
     * "remaining copies" badge from `instances.count { it.sigCount == 0 }`.
     * A credential with no [StoredCredential.batchId] (single-copy issuance)
     * is returned as its own one-instance family.
     */
    fun groupForDisplay(
        credentials: List<StoredCredential>,
        presentationHistory: List<PresentationRecord>,
    ): List<CredentialWithInstances> {
        fun sigCountFor(credentialId: Long) =
            presentationHistory.count { credentialId in it.credentialIds }

        // Every issuance response - batch of one or of many - shares one
        // batchId (see StoredCredential.batchId), so grouping is uniform:
        // no separate "standalone" case, matching wallet-frontend exactly.
        val results = credentials.groupBy { it.batchId }.values.mapNotNull { members ->
            val visible = members.find { it.instanceId == 0 } ?: return@mapNotNull null
            val instances = members
                .sortedBy { it.instanceId }
                .map { CredentialInstance(it.instanceId, sigCountFor(it.id)) }
            CredentialWithInstances(visible, instances)
        }

        return results.sortedByDescending { it.credential.issuedAt ?: 0 }
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
    /** VCTM SVG template placeholder ID this claim fills, if any. */
    val svgId: String? = null,
)

/** One member of a batch-issued credential family, alongside its usage count. */
data class CredentialInstance(val instanceId: Int, val sigCount: Int)

/** A visible credential card plus every instance in its batch (see [CredentialUtils.groupForDisplay]). */
data class CredentialWithInstances(val credential: StoredCredential, val instances: List<CredentialInstance>)

/**
 * The individually-decoded parts of a raw SD-JWT VC string, for display.
 */
data class SdJwtParts(
    val header: JsonObject?,
    val payload: JsonObject?,
    /** Each disclosure is a JSON array (`[salt, name, value]` or `[salt, value]`). */
    val disclosures: List<JsonElement>,
)
