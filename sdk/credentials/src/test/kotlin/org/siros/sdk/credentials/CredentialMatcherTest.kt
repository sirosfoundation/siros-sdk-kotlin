package org.siros.sdk.credentials

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CredentialMatcherTest {

    private val json = Json { ignoreUnknownKeys = true }

    @Test
    fun match_filters_by_format_and_vct() {
        val credentials = listOf(
            StoredCredential(
                id = 1L,
                format = "dc+sd-jwt",
                raw = "raw-1",
                metadata = CredentialMetadata(vct = "urn:eu:pid:1"),
                batchId = 1L,
                instanceId = 0,
            ),
            StoredCredential(
                id = 2L,
                format = "mso_mdoc",
                raw = "raw-2",
                metadata = CredentialMetadata(doctype = "eu.europa.ec.eudi.pid.1"),
                batchId = 2L,
                instanceId = 0,
            ),
        )

        val query = json.parseToJsonElement(
            """
            {
              "credentials": [
                {
                  "id": "q-pid",
                  "format": "dc+sd-jwt",
                  "meta": {
                    "vct_values": ["urn:eu:pid:1"]
                  },
                  "claims": [
                    { "path": ["given_name"] }
                  ]
                }
              ]
            }
            """.trimIndent()
        ).jsonObject

        val results = CredentialMatcher.match(query, credentials)

        assertEquals(1, results.size)
        assertEquals("q-pid", results.first().queryId)
        assertEquals(listOf(1L), results.first().candidates.map { it.id })
        assertEquals(listOf(listOf("given_name")), results.first().requestedClaims)
    }

    @Test
    fun match_filters_by_doctype_for_mdoc() {
        val credentials = listOf(
            StoredCredential(
                id = 1L,
                format = "mso_mdoc",
                raw = "raw-1",
                metadata = CredentialMetadata(doctype = "eu.europa.ec.eudi.pid.1"),
                batchId = 1L,
                instanceId = 0,
            ),
            StoredCredential(
                id = 2L,
                format = "mso_mdoc",
                raw = "raw-2",
                metadata = CredentialMetadata(doctype = "com.example.other"),
                batchId = 2L,
                instanceId = 0,
            ),
        )

        val query = json.parseToJsonElement(
            """
            {
              "credentials": [
                {
                  "id": "q-doc",
                  "format": "mso_mdoc",
                  "meta": {
                    "doctype_value": "eu.europa.ec.eudi.pid.1"
                  }
                }
              ]
            }
            """.trimIndent()
        ).jsonObject

        val matchedIds = CredentialMatcher.matchedCredentialIds(query, credentials)
        assertEquals(listOf(1L), matchedIds)
    }

    @Test
    fun match_filters_by_doctype_for_mdoc_with_no_metadata() {
        // Mirrors a credential from a third-party issuer with no MDDL schema
        // endpoint at our internal /type-metadata/<scope> convention - the
        // metadata fetch fails, so `metadata` stays null, but the docType is
        // still authoritatively present in the credential's own MSO/CBOR, so
        // it must still be matchable.
        val credentials = listOf(
            StoredCredential(
                id = 1L,
                format = "mso_mdoc",
                raw = buildMdocRaw("eu.europa.ec.eudi.pid.1"),
                metadata = null,
                batchId = 1L,
                instanceId = 0,
            ),
        )

        val query = json.parseToJsonElement(
            """
            {
              "credentials": [
                {
                  "id": "q-doc",
                  "format": "mso_mdoc",
                  "meta": {
                    "doctype_value": "eu.europa.ec.eudi.pid.1"
                  }
                }
              ]
            }
            """.trimIndent()
        ).jsonObject

        val matchedIds = CredentialMatcher.matchedCredentialIds(query, credentials)
        assertEquals(listOf(1L), matchedIds)
    }

    /** Build a synthetic mdoc credential's raw (base64url) bytes: a bare IssuerSigned structure with the given docType embedded in a stub MSO. */
    private fun buildMdocRaw(docType: String): String {
        val mso = com.upokecenter.cbor.CBORObject.NewMap()
        mso[com.upokecenter.cbor.CBORObject.FromObject("docType")] = com.upokecenter.cbor.CBORObject.FromObject(docType)
        val msoTagged = com.upokecenter.cbor.CBORObject.FromObjectAndTag(mso.EncodeToBytes(), 24)
        val issuerAuth = com.upokecenter.cbor.CBORObject.NewArray()
        issuerAuth.Add(com.upokecenter.cbor.CBORObject.FromObject(ByteArray(0)))
        issuerAuth.Add(com.upokecenter.cbor.CBORObject.NewMap())
        issuerAuth.Add(com.upokecenter.cbor.CBORObject.FromObject(msoTagged.EncodeToBytes()))
        issuerAuth.Add(com.upokecenter.cbor.CBORObject.FromObject(ByteArray(0)))

        val issuerSigned = com.upokecenter.cbor.CBORObject.NewMap()
        issuerSigned[com.upokecenter.cbor.CBORObject.FromObject("nameSpaces")] = com.upokecenter.cbor.CBORObject.NewMap()
        issuerSigned[com.upokecenter.cbor.CBORObject.FromObject("issuerAuth")] = issuerAuth

        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(issuerSigned.EncodeToBytes())
    }

    @Test
    fun match_returns_all_when_query_has_no_credentials_array() {
        val credentials = listOf(
            StoredCredential(id = 1L, format = "dc+sd-jwt", raw = "raw-a", batchId = 1L, instanceId = 0),
            StoredCredential(id = 2L, format = "mso_mdoc", raw = "raw-b", batchId = 2L, instanceId = 0),
        )

        val query = json.parseToJsonElement("""{ "unexpected": true }""").jsonObject
        val results = CredentialMatcher.match(query, credentials)

        assertEquals(1, results.size)
        assertEquals("_default", results.first().queryId)
        assertTrue(results.first().candidates.map { it.id }.containsAll(listOf(1L, 2L)))
    }

    @Test
    fun matched_credential_ids_are_distinct_across_multiple_queries() {
        val credentials = listOf(
            StoredCredential(
                id = 1L,
                format = "dc+sd-jwt",
                raw = "raw-1",
                metadata = CredentialMetadata(vct = "urn:eu:pid:1"),
                batchId = 1L,
                instanceId = 0,
            )
        )

        val query = json.parseToJsonElement(
            """
            {
              "credentials": [
                {
                  "id": "q-1",
                  "format": "DC+SD-JWT",
                  "meta": { "vct_values": ["urn:eu:pid:1"] }
                },
                {
                  "id": "q-2",
                  "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["urn:eu:pid:1"] }
                }
              ]
            }
            """.trimIndent()
        ).jsonObject

        val matchedIds = CredentialMatcher.matchedCredentialIds(query, credentials)

        assertEquals(listOf(1L), matchedIds)
    }

    @Test
    fun match_excludes_credentials_without_required_vct_or_doctype_metadata() {
        val credentials = listOf(
            StoredCredential(id = 1L, format = "dc+sd-jwt", raw = "raw-1", batchId = 1L, instanceId = 0),
            StoredCredential(id = 2L, format = "mso_mdoc", raw = "raw-2", batchId = 2L, instanceId = 0),
        )

        val query = json.parseToJsonElement(
            """
            {
              "credentials": [
                {
                  "id": "q-vct",
                  "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["urn:eu:pid:1"] }
                },
                {
                  "id": "q-doc",
                  "format": "mso_mdoc",
                  "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" }
                }
              ]
            }
            """.trimIndent()
        ).jsonObject

        val results = CredentialMatcher.match(query, credentials)

        assertEquals(emptyList<StoredCredential>(), results.first { it.queryId == "q-vct" }.candidates)
        assertEquals(emptyList<StoredCredential>(), results.first { it.queryId == "q-doc" }.candidates)
    }

    @Test
    fun match_skips_queries_without_ids_and_ignores_malformed_claim_entries() {
        val credentials = listOf(
            StoredCredential(
                id = 1L,
                format = "dc+sd-jwt",
                raw = "raw-1",
                metadata = CredentialMetadata(vct = "urn:eu:pid:1"),
                batchId = 1L,
                instanceId = 0,
            )
        )

        val query = json.parseToJsonElement(
            """
            {
              "credentials": [
                {
                  "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["urn:eu:pid:1"] }
                },
                {
                  "id": "q-valid",
                  "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["urn:eu:pid:1"] },
                  "claims": [
                    { "path": ["given_name"] },
                    { "path": "not-an-array" },
                    true
                  ]
                }
              ]
            }
            """.trimIndent()
        ).jsonObject

        val results = CredentialMatcher.match(query, credentials)

        assertEquals(1, results.size)
        assertEquals("q-valid", results.single().queryId)
        assertEquals(listOf(listOf("given_name")), results.single().requestedClaims)
    }

    // --- credential_sets tests (OID4VP §6.2) ---

    @Test
    fun parseCredentialSets_returns_null_when_absent() {
        val query = json.parseToJsonElement("""{ "credentials": [] }""").jsonObject
        val sets = CredentialMatcher.parseCredentialSets(query)
        assertEquals(null, sets)
    }

    @Test
    fun parseCredentialSets_parses_required_and_optional_sets() {
        val query = json.parseToJsonElement(
            """
            {
              "credentials": [],
              "credential_sets": [
                {
                  "options": [["pid"], ["other_pid"], ["cred_1", "cred_2"]]
                },
                {
                  "required": false,
                  "options": [["nice_to_have"]]
                }
              ]
            }
            """.trimIndent()
        ).jsonObject

        val sets = CredentialMatcher.parseCredentialSets(query)!!
        assertEquals(2, sets.size)

        // First set: required (default), 3 options
        assertTrue(sets[0].required)
        assertEquals(3, sets[0].options.size)
        assertEquals(listOf("pid"), sets[0].options[0])
        assertEquals(listOf("other_pid"), sets[0].options[1])
        assertEquals(listOf("cred_1", "cred_2"), sets[0].options[2])

        // Second set: optional, 1 option
        assertEquals(false, sets[1].required)
        assertEquals(1, sets[1].options.size)
        assertEquals(listOf("nice_to_have"), sets[1].options[0])
    }

    @Test
    fun parseCredentialSets_skips_malformed_entries() {
        val query = json.parseToJsonElement(
            """
            {
              "credentials": [],
              "credential_sets": [
                { "options": [] },
                { "options": [["valid"]] }
              ]
            }
            """.trimIndent()
        ).jsonObject

        val sets = CredentialMatcher.parseCredentialSets(query)!!
        assertEquals(1, sets.size)
        assertEquals(listOf(listOf("valid")), sets[0].options)
    }

    @Test
    fun findSatisfiableOptions_identifies_satisfiable_options() {
        val queryResults = listOf(
            CredentialMatcher.MatchResult("pid", "dc+sd-jwt",
                listOf(StoredCredential(id = 1L, format = "dc+sd-jwt", raw = "r", batchId = 1L, instanceId = 0)),
                emptyList()),
            CredentialMatcher.MatchResult("other_pid", "dc+sd-jwt",
                emptyList(), // no matches
                emptyList()),
            CredentialMatcher.MatchResult("cred_1", "dc+sd-jwt",
                listOf(StoredCredential(id = 2L, format = "dc+sd-jwt", raw = "r", batchId = 2L, instanceId = 0)),
                emptyList()),
            CredentialMatcher.MatchResult("cred_2", "dc+sd-jwt",
                listOf(StoredCredential(id = 3L, format = "dc+sd-jwt", raw = "r", batchId = 3L, instanceId = 0)),
                emptyList()),
        )

        val credentialSets = listOf(
            CredentialMatcher.CredentialSetQuery(
                options = listOf(listOf("pid"), listOf("other_pid"), listOf("cred_1", "cred_2")),
                required = true,
            )
        )

        val satisfiable = CredentialMatcher.findSatisfiableOptions(credentialSets, queryResults)

        // "pid" option is satisfiable (has matches)
        // "other_pid" option is NOT satisfiable (no matches)
        // "cred_1" + "cred_2" option IS satisfiable (both have matches)
        assertEquals(2, satisfiable.size)
        assertEquals(0, satisfiable[0].credentialSetIndex)
        assertEquals(0, satisfiable[0].optionIndex) // "pid"
        assertEquals(listOf("pid"), satisfiable[0].queryIds)

        assertEquals(0, satisfiable[1].credentialSetIndex)
        assertEquals(2, satisfiable[1].optionIndex) // "cred_1", "cred_2"
        assertEquals(listOf("cred_1", "cred_2"), satisfiable[1].queryIds)
    }

    @Test
    fun matchDcql_returns_full_output_with_credential_sets() {
        val credentials = listOf(
            StoredCredential(
                id = 1L,
                format = "dc+sd-jwt",
                raw = "raw-1",
                metadata = CredentialMetadata(vct = "urn:eu:pid:1"),
                batchId = 1L,
                instanceId = 0,
            ),
            StoredCredential(
                id = 2L,
                format = "mso_mdoc",
                raw = "raw-2",
                metadata = CredentialMetadata(doctype = "org.iso.18013.5.1.mDL"),
                batchId = 2L,
                instanceId = 0,
            ),
        )

        val query = json.parseToJsonElement(
            """
            {
              "credentials": [
                {
                  "id": "pid",
                  "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["urn:eu:pid:1"] },
                  "claims": [{ "path": ["given_name"] }]
                },
                {
                  "id": "mdl",
                  "format": "mso_mdoc",
                  "meta": { "doctype_value": "org.iso.18013.5.1.mDL" }
                }
              ],
              "credential_sets": [
                {
                  "options": [["pid"], ["mdl"]]
                }
              ]
            }
            """.trimIndent()
        ).jsonObject

        val output = CredentialMatcher.matchDcql(query, credentials)

        // Both query results should have matches
        assertEquals(2, output.queryResults.size)
        assertEquals("pid", output.queryResults[0].queryId)
        assertEquals(1, output.queryResults[0].candidates.size)
        assertEquals("mdl", output.queryResults[1].queryId)
        assertEquals(1, output.queryResults[1].candidates.size)

        // credential_sets should be parsed
        val sets = output.credentialSets!!
        assertEquals(1, sets.size)
        assertTrue(sets[0].required)

        // Both options should be satisfiable
        assertEquals(2, output.satisfiableOptions.size)
    }

    @Test
    fun matchDcql_without_credential_sets_returns_null_sets() {
        val credentials = listOf(
            StoredCredential(id = 1L, format = "dc+sd-jwt", raw = "r",
                metadata = CredentialMetadata(vct = "urn:eu:pid:1"), batchId = 1L, instanceId = 0),
        )

        val query = json.parseToJsonElement(
            """
            {
              "credentials": [
                {
                  "id": "pid",
                  "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["urn:eu:pid:1"] }
                }
              ]
            }
            """.trimIndent()
        ).jsonObject

        val output = CredentialMatcher.matchDcql(query, credentials)
        assertEquals(null, output.credentialSets)
        assertTrue(output.satisfiableOptions.isEmpty())
        assertEquals(1, output.queryResults.size)
    }

    @Test
    fun match_still_returns_flat_list_for_backward_compatibility() {
        val credentials = listOf(
            StoredCredential(id = 1L, format = "dc+sd-jwt", raw = "r",
                metadata = CredentialMetadata(vct = "urn:eu:pid:1"), batchId = 1L, instanceId = 0),
        )

        val query = json.parseToJsonElement(
            """
            {
              "credentials": [
                {
                  "id": "pid",
                  "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["urn:eu:pid:1"] }
                }
              ],
              "credential_sets": [
                { "options": [["pid"]] }
              ]
            }
            """.trimIndent()
        ).jsonObject

        // match() should still work as before, ignoring credential_sets
        val results = CredentialMatcher.match(query, credentials)
        assertEquals(1, results.size)
        assertEquals("pid", results[0].queryId)
    }
}
