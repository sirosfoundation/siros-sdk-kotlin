// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.sirosfoundation.sdk.credentials

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import timber.log.Timber

/**
 * Client-side credential matching against DCQL queries (OID4VP 1.0 §6).
 *
 * Since the wallet engine does not perform credential matching, the SDK
 * must parse DCQL (Digital Credential Query Language) queries and filter
 * stored credentials locally. The DCQL query comes from the verifier via
 * the engine's `match_request` message.
 *
 * DCQL query structure (OID4VP 1.0 §6):
 * ```json
 * {
 *   "credentials": [
 *     {
 *       "id": "query-id",
 *       "format": "dc+sd-jwt",
 *       "meta": { "vct_values": ["urn:eu.europa.ec.eudi:pid:1"] },
 *       "claims": [{ "path": ["given_name"] }]
 *     }
 *   ],
 *   "credential_sets": [
 *     {
 *       "options": [["query-id-a"], ["query-id-b", "query-id-c"]],
 *       "required": true
 *     }
 *   ]
 * }
 * ```
 *
 * Matching rules (§6.4.2):
 * 1. Each credential query has an optional `format` — must match [StoredCredential.format]
 * 2. `meta.vct_values` — credential's vct must be in the list
 * 3. `meta.doctype_value` — credential's doctype must match (mso_mdoc)
 * 4. If no format/vct/doctype constraints, any credential matches
 *
 * Credential sets selection (§6.4.2):
 * - If `credential_sets` is not provided → return presentations for ALL credentials
 * - Otherwise → satisfy all required credential set queries, optionally any others
 * - To satisfy a set → return presentations matching ONE of its `options`
 */
object CredentialMatcher {

    /**
     * Result of matching credentials against a single DCQL credential query.
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
     * A credential set query from DCQL `credential_sets` (OID4VP §6.2).
     *
     * Represents one grouping constraint: the wallet must satisfy
     * one of the [options] by providing matching credentials for
     * all credential query IDs in that option.
     */
    data class CredentialSetQuery(
        /** Each option is a list of credential query IDs that together satisfy this set. */
        val options: List<List<String>>,
        /** Whether this credential set is required (default true per spec). */
        val required: Boolean = true,
    )

    /**
     * An option within a credential set that can be satisfied by the wallet's credentials.
     */
    data class SatisfiableOption(
        /** Index of the credential set in the `credential_sets` array. */
        val credentialSetIndex: Int,
        /** Index of the option within the credential set's `options` array. */
        val optionIndex: Int,
        /** The credential query IDs in this option. */
        val queryIds: List<String>,
    )

    /**
     * Full DCQL match output including per-query results and credential set constraints.
     */
    data class DcqlMatchOutput(
        /** Per-credential-query match results. */
        val queryResults: List<MatchResult>,
        /** Parsed credential set constraints, or null if `credential_sets` was absent. */
        val credentialSets: List<CredentialSetQuery>?,
        /** Options that can be satisfied given the wallet's current credentials. */
        val satisfiableOptions: List<SatisfiableOption>,
    )

    /**
     * Match stored credentials against a DCQL query.
     *
     * @param dcqlQuery The DCQL query JSON from the verifier
     * @param credentials All stored credentials
     * @return A list of [MatchResult] — one per credential query in the DCQL
     */
    fun match(dcqlQuery: JsonObject, credentials: List<StoredCredential>): List<MatchResult> {
        return matchDcql(dcqlQuery, credentials).queryResults
    }

    /**
     * Match stored credentials against a full DCQL query, including `credential_sets`.
     *
     * Returns per-query match results, parsed credential set constraints,
     * and which options are satisfiable given the wallet's credentials.
     *
     * @param dcqlQuery The DCQL query JSON from the verifier
     * @param credentials All stored credentials
     * @return A [DcqlMatchOutput] with full matching information
     */
    fun matchDcql(dcqlQuery: JsonObject, credentials: List<StoredCredential>): DcqlMatchOutput {
        val credentialQueries = dcqlQuery["credentials"]?.jsonArray ?: run {
            Timber.w("DCQL query has no 'credentials' array, returning all credentials")
            return DcqlMatchOutput(
                queryResults = listOf(MatchResult(
                    queryId = "_default",
                    format = null,
                    candidates = credentials,
                    requestedClaims = emptyList(),
                )),
                credentialSets = null,
                satisfiableOptions = emptyList(),
            )
        }

        val queryResults = credentialQueries.mapNotNull { queryElement ->
            matchSingleQuery(queryElement.jsonObject, credentials)
        }

        val credentialSets = parseCredentialSets(dcqlQuery)
        val satisfiableOptions = if (credentialSets != null) {
            findSatisfiableOptions(credentialSets, queryResults)
        } else {
            emptyList()
        }

        return DcqlMatchOutput(
            queryResults = queryResults,
            credentialSets = credentialSets,
            satisfiableOptions = satisfiableOptions,
        )
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

    /**
     * Parse the `credential_sets` array from a DCQL query (OID4VP §6.2).
     *
     * @return Parsed credential set queries, or null if `credential_sets` is absent
     */
    fun parseCredentialSets(dcqlQuery: JsonObject): List<CredentialSetQuery>? {
        val setsArray = dcqlQuery["credential_sets"] as? JsonArray ?: return null
        if (setsArray.isEmpty()) return null

        return setsArray.mapNotNull { element ->
            val obj = element as? JsonObject ?: return@mapNotNull null
            val options = (obj["options"] as? JsonArray)?.mapNotNull { optElement ->
                (optElement as? JsonArray)?.mapNotNull { it.jsonPrimitive.contentOrNull }
                    ?.takeIf { it.isNotEmpty() }
            } ?: return@mapNotNull null
            if (options.isEmpty()) return@mapNotNull null

            val required = obj["required"]?.jsonPrimitive?.booleanOrNull ?: true
            CredentialSetQuery(options = options, required = required)
        }.takeIf { it.isNotEmpty() }
    }

    /**
     * Find which credential set options are satisfiable given match results.
     *
     * An option is satisfiable if every credential query ID in it has at
     * least one matching credential in the query results.
     */
    fun findSatisfiableOptions(
        credentialSets: List<CredentialSetQuery>,
        queryResults: List<MatchResult>,
    ): List<SatisfiableOption> {
        val queryResultsById = queryResults.associateBy { it.queryId }

        return credentialSets.flatMapIndexed { setIndex, credentialSet ->
            credentialSet.options.mapIndexedNotNull { optionIndex, queryIds ->
                val allSatisfied = queryIds.all { queryId ->
                    val result = queryResultsById[queryId]
                    result != null && result.candidates.isNotEmpty()
                }
                if (allSatisfied) {
                    SatisfiableOption(
                        credentialSetIndex = setIndex,
                        optionIndex = optionIndex,
                        queryIds = queryIds,
                    )
                } else {
                    null
                }
            }
        }
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
