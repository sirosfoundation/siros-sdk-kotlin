// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.sirosfoundation.sdk.credentials

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import timber.log.Timber

/**
 * Client-side credential matching against DCQL queries.
 *
 * Since the wallet engine does not perform credential matching, the SDK
 * must parse DCQL (Digital Credential Query Language) queries and filter
 * stored credentials locally. The DCQL query comes from the verifier via
 * the engine's `match_request` message.
 *
 * DCQL query structure (OID4VP draft):
 * ```json
 * {
 *   "credentials": [
 *     {
 *       "id": "query-id",
 *       "format": "vc+sd-jwt",
 *       "meta": { "vct_values": ["urn:eu.europa.ec.eudi:pid:1"] },
 *       "claims": [{ "path": ["given_name"] }]
 *     }
 *   ]
 * }
 * ```
 *
 * Matching rules:
 * 1. Each credential query has an optional `format` — must match [StoredCredential.format]
 * 2. `meta.vct_values` — credential's vct must be in the list
 * 3. `meta.doctype_value` — credential's doctype must match (mso_mdoc)
 * 4. If no format/vct/doctype constraints, any credential matches
 */
object CredentialMatcher {

    /**
     * Result of matching credentials against a DCQL query.
     */
    data class MatchResult(
        /** DCQL credential query ID. */
        val queryId: String,
        /** Requested format, if specified. */
        val format: String?,
        /** Credentials that matched this query. */
        val candidates: List<StoredCredential>,
        /** Claim paths requested by the verifier. */
        val requestedClaims: List<List<String>>,
    )

    /**
     * Match stored credentials against a DCQL query.
     *
     * @param dcqlQuery The DCQL query JSON from the verifier
     * @param credentials All stored credentials
     * @return A list of [MatchResult] — one per credential query in the DCQL
     */
    fun match(dcqlQuery: JsonObject, credentials: List<StoredCredential>): List<MatchResult> {
        val credentialQueries = dcqlQuery["credentials"]?.jsonArray ?: run {
            Timber.w("DCQL query has no 'credentials' array, returning all credentials")
            return listOf(MatchResult(
                queryId = "_default",
                format = null,
                candidates = credentials,
                requestedClaims = emptyList(),
            ))
        }

        return credentialQueries.mapNotNull { queryElement ->
            matchSingleQuery(queryElement.jsonObject, credentials)
        }
    }

    /**
     * Flatten match results into a single list of matching credential IDs.
     * Suitable for passing to the engine's match response.
     */
    fun matchedCredentialIds(dcqlQuery: JsonObject, credentials: List<StoredCredential>): List<String> {
        return match(dcqlQuery, credentials)
            .flatMap { it.candidates }
            .distinctBy { it.id }
            .map { it.id }
    }

    private fun matchSingleQuery(
        query: JsonObject,
        credentials: List<StoredCredential>,
    ): MatchResult? {
        val queryId = query["id"]?.jsonPrimitive?.contentOrNull ?: return null
        val format = query["format"]?.jsonPrimitive?.contentOrNull
        val meta = query["meta"]?.jsonObject
        val claims = parseClaims(query["claims"])

        // Extract type constraints
        val vctValues = meta?.get("vct_values")?.jsonArray
            ?.mapNotNull { it.jsonPrimitive.contentOrNull }
            ?.toSet()

        val doctypeValue = meta?.get("doctype_value")?.jsonPrimitive?.contentOrNull

        val matched = credentials.filter { cred ->
            matchesFormat(cred, format) &&
                matchesVct(cred, vctValues) &&
                matchesDoctype(cred, doctypeValue)
        }

        Timber.d("DCQL query '$queryId': format=$format vct=$vctValues doctype=$doctypeValue → ${matched.size} matches")

        return MatchResult(
            queryId = queryId,
            format = format,
            candidates = matched,
            requestedClaims = claims,
        )
    }

    private fun matchesFormat(credential: StoredCredential, format: String?): Boolean {
        if (format == null) return true
        return credential.format.equals(format, ignoreCase = true)
    }

    private fun matchesVct(credential: StoredCredential, vctValues: Set<String>?): Boolean {
        if (vctValues == null || vctValues.isEmpty()) return true
        val credVct = credential.metadata?.vct ?: return false
        return credVct in vctValues
    }

    private fun matchesDoctype(credential: StoredCredential, doctypeValue: String?): Boolean {
        if (doctypeValue == null) return true
        val credDoctype = credential.metadata?.doctype ?: return false
        return credDoctype == doctypeValue
    }

    private fun parseClaims(element: JsonElement?): List<List<String>> {
        if (element == null || element !is JsonArray) return emptyList()
        return element.mapNotNull { claimElement ->
            val obj = claimElement as? JsonObject ?: return@mapNotNull null
            val path = (obj["path"] as? JsonArray)
                ?.mapNotNull { it.jsonPrimitive.contentOrNull }
            path
        }
    }
}
