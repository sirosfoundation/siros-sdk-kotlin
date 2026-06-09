package org.sirosfoundation.sdk.credentials

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
                id = "1",
                format = "dc+sd-jwt",
                raw = "raw-1",
                metadata = CredentialMetadata(vct = "urn:eu:pid:1"),
            ),
            StoredCredential(
                id = "2",
                format = "mso_mdoc",
                raw = "raw-2",
                metadata = CredentialMetadata(doctype = "eu.europa.ec.eudi.pid.1"),
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
        assertEquals(listOf("1"), results.first().candidates.map { it.id })
        assertEquals(listOf(listOf("given_name")), results.first().requestedClaims)
    }

    @Test
    fun match_filters_by_doctype_for_mdoc() {
        val credentials = listOf(
            StoredCredential(
                id = "pid-doc",
                format = "mso_mdoc",
                raw = "raw-1",
                metadata = CredentialMetadata(doctype = "eu.europa.ec.eudi.pid.1"),
            ),
            StoredCredential(
                id = "other-doc",
                format = "mso_mdoc",
                raw = "raw-2",
                metadata = CredentialMetadata(doctype = "com.example.other"),
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
        assertEquals(listOf("pid-doc"), matchedIds)
    }

    @Test
    fun match_returns_all_when_query_has_no_credentials_array() {
        val credentials = listOf(
            StoredCredential(id = "a", format = "dc+sd-jwt", raw = "raw-a"),
            StoredCredential(id = "b", format = "mso_mdoc", raw = "raw-b"),
        )

        val query = json.parseToJsonElement("""{ "unexpected": true }""").jsonObject
        val results = CredentialMatcher.match(query, credentials)

        assertEquals(1, results.size)
        assertEquals("_default", results.first().queryId)
        assertTrue(results.first().candidates.map { it.id }.containsAll(listOf("a", "b")))
    }

    @Test
    fun matched_credential_ids_are_distinct_across_multiple_queries() {
        val credentials = listOf(
            StoredCredential(
                id = "pid-1",
                format = "dc+sd-jwt",
                raw = "raw-1",
                metadata = CredentialMetadata(vct = "urn:eu:pid:1"),
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

        assertEquals(listOf("pid-1"), matchedIds)
    }

    @Test
    fun match_excludes_credentials_without_required_vct_or_doctype_metadata() {
        val credentials = listOf(
            StoredCredential(id = "missing-vct", format = "dc+sd-jwt", raw = "raw-1"),
            StoredCredential(id = "missing-doc", format = "mso_mdoc", raw = "raw-2"),
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
                id = "1",
                format = "dc+sd-jwt",
                raw = "raw-1",
                metadata = CredentialMetadata(vct = "urn:eu:pid:1"),
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
}
