// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class Ts11RegistryClientTest {

    private fun schemaJson(id: String, attestationLoS: String = "iso_18045_high"): String = """
        {
          "id": "$id",
          "version": "1.0",
          "attestationLoS": "$attestationLoS",
          "bindingType": "jwk",
          "supportedFormats": ["dc+sd-jwt"],
          "schemaURIs": [
            { "formatIdentifier": "dc+sd-jwt", "uri": "https://registry.siros.org/schemas/$id/vctm.json" }
          ],
          "rulebookURI": "https://registry.siros.org/schemas/$id/rulebook.json"
        }
    """.trimIndent()

    // ── Current (paginated data/total/limit/offset) shape ─────────────

    @Test
    fun `fetchSchemas follows pagination across multiple pages of the current shape`() = runTest {
        val page1 = """
            {"data": [${schemaJson("diploma")}, ${schemaJson("mdl")}], "total": 4, "limit": 2, "offset": 0}
        """.trimIndent()
        val page2 = """
            {"data": [${schemaJson("passport")}, ${schemaJson("visa")}], "total": 4, "limit": 2, "offset": 2}
        """.trimIndent()

        val calledUrls = mutableListOf<String>()
        val client = Ts11RegistryClient(httpGet = { url ->
            calledUrls.add(url)
            when (url) {
                "https://registry.siros.org/api/v1/schemas.json" -> page1
                "https://registry.siros.org/api/v1/schemas.json?offset=2" -> page2
                else -> null
            }
        })

        val schemas = client.fetchSchemas()

        assertEquals(4, schemas.size)
        assertEquals(listOf("diploma", "mdl", "passport", "visa"), schemas.map { it.id })
        assertEquals(2, calledUrls.size)
        assertEquals("iso_18045_high", schemas[0].attestationLoS)
        assertEquals("jwk", schemas[0].bindingType)
        assertEquals(listOf("dc+sd-jwt"), schemas[0].supportedFormats)
        assertEquals(1, schemas[0].schemaURIs.size)
        assertEquals("dc+sd-jwt", schemas[0].schemaURIs[0].formatIdentifier)
    }

    @Test
    fun `fetchSchemas stops pagination when offset plus entries reaches total`() = runTest {
        var callCount = 0
        val client = Ts11RegistryClient(httpGet = { url ->
            callCount++
            when (url) {
                "https://registry.siros.org/api/v1/schemas.json" ->
                    """{"data": [${schemaJson("only-one")}], "total": 1, "limit": 20, "offset": 0}"""
                else -> null
            }
        })

        val schemas = client.fetchSchemas()

        assertEquals(1, schemas.size)
        assertEquals("only-one", schemas[0].id)
        assertEquals(1, callCount) // no second page fetched
    }

    // ── Legacy (schemas/next) shape ────────────────────────────────────

    @Test
    fun `fetchSchemas follows pagination across the legacy schemas next shape`() = runTest {
        val page1 = """
            {"schemas": [${schemaJson("legacy-a")}], "next": "https://registry.siros.org/api/v1/schemas.json?page=2"}
        """.trimIndent()
        val page2 = """
            {"schemas": [${schemaJson("legacy-b")}], "next": ""}
        """.trimIndent()

        val client = Ts11RegistryClient(httpGet = { url ->
            when (url) {
                "https://registry.siros.org/api/v1/schemas.json" -> page1
                "https://registry.siros.org/api/v1/schemas.json?page=2" -> page2
                else -> null
            }
        })

        val schemas = client.fetchSchemas()

        assertEquals(2, schemas.size)
        assertEquals(listOf("legacy-a", "legacy-b"), schemas.map { it.id })
    }

    @Test
    fun `fetchSchemas handles a single-page legacy response with no next field`() = runTest {
        val client = Ts11RegistryClient(httpGet = { url ->
            if (url == "https://registry.siros.org/api/v1/schemas.json") {
                """{"schemas": [${schemaJson("solo")}]}"""
            } else {
                null
            }
        })

        val schemas = client.fetchSchemas()

        assertEquals(1, schemas.size)
        assertEquals("solo", schemas[0].id)
    }

    // ── registry.json (all-credentials, non-paginated) shape ───────────

    @Test
    fun `fetchSchemas parses the non-paginated registry json shape`() = runTest {
        val client = Ts11RegistryClient(
            sources = listOf("https://registry.siros.org/api/v1/registry.json"),
            httpGet = { url ->
                if (url == "https://registry.siros.org/api/v1/registry.json") {
                    """
                    {
                      "total": 2,
                      "credentials": [
                        {"id": "diploma", "version": "1.0", "supportedFormats": ["dc+sd-jwt"], "attestationLoS": "iso_18045_basic", "bindingType": "jwk"},
                        {"id": "mdl", "version": "1.0", "supportedFormats": ["mso_mdoc"], "attestationLoS": "iso_18045_high", "bindingType": "cose_key"}
                      ]
                    }
                    """.trimIndent()
                } else {
                    null
                }
            },
        )

        val schemas = client.fetchSchemas()

        assertEquals(2, schemas.size)
        assertEquals("diploma", schemas[0].id)
        assertEquals("iso_18045_basic", schemas[0].attestationLoS)
        assertEquals("mdl", schemas[1].id)
        assertEquals("iso_18045_high", schemas[1].attestationLoS)
        assertTrue(schemas[0].schemaURIs.isEmpty())
    }

    // ── Empty result ────────────────────────────────────────────────────

    @Test
    fun `fetchSchemas returns an empty list for an empty result`() = runTest {
        val client = Ts11RegistryClient(httpGet = { url ->
            if (url == "https://registry.siros.org/api/v1/schemas.json") {
                """{"data": [], "total": 0, "limit": 20, "offset": 0}"""
            } else {
                null
            }
        })

        val schemas = client.fetchSchemas()

        assertTrue(schemas.isEmpty())
    }

    // ── Malformed / error responses ────────────────────────────────────

    @Test
    fun `fetchSchemas returns an empty list for a malformed JSON response`() = runTest {
        val client = Ts11RegistryClient(httpGet = { "this is not { valid json" })

        val schemas = client.fetchSchemas()

        assertTrue(schemas.isEmpty())
    }

    @Test
    fun `fetchSchemas returns an empty list when the HTTP fetch fails`() = runTest {
        val client = Ts11RegistryClient(httpGet = { null })

        val schemas = client.fetchSchemas()

        assertTrue(schemas.isEmpty())
    }

    @Test
    fun `fetchSchemas returns an empty list when httpGet throws`() = runTest {
        val client = Ts11RegistryClient(httpGet = { throw java.io.IOException("network error") })

        val schemas = client.fetchSchemas()

        assertTrue(schemas.isEmpty())
    }

    @Test
    fun `fetchSchemas stops pagination gracefully when a later page is malformed`() = runTest {
        val client = Ts11RegistryClient(httpGet = { url ->
            when (url) {
                "https://registry.siros.org/api/v1/schemas.json" ->
                    """{"data": [${schemaJson("first")}], "total": 4, "limit": 1, "offset": 0}"""
                "https://registry.siros.org/api/v1/schemas.json?offset=1" -> "not valid json"
                else -> null
            }
        })

        val schemas = client.fetchSchemas()

        // First page's entries are preserved even though the second page failed.
        assertEquals(1, schemas.size)
        assertEquals("first", schemas[0].id)
    }

    // ── Multi-source config ─────────────────────────────────────────────

    @Test
    fun `fetchSchemas defaults to a single registry siros org source`() = runTest {
        var calledUrl: String? = null
        val client = Ts11RegistryClient(httpGet = { url ->
            calledUrl = url
            null
        })

        client.fetchSchemas()

        assertEquals("https://registry.siros.org/api/v1/schemas.json", calledUrl)
    }

    @Test
    fun `fetchSchemas merges entries across sources with later sources overwriting earlier ones`() = runTest {
        val client = Ts11RegistryClient(
            sources = listOf(
                "https://registry.siros.org",
                "https://other-registry.example.org",
            ),
            httpGet = { url ->
                when (url) {
                    "https://registry.siros.org/api/v1/schemas.json" ->
                        """{"data": [${schemaJson("diploma", "iso_18045_basic")}, ${schemaJson("mdl")}], "total": 2, "limit": 20, "offset": 0}"""
                    "https://other-registry.example.org/api/v1/schemas.json" ->
                        """{"data": [${schemaJson("diploma", "iso_18045_high")}], "total": 1, "limit": 20, "offset": 0}"""
                    else -> null
                }
            },
        )

        val schemas = client.fetchSchemas()

        assertEquals(2, schemas.size)
        val diploma = schemas.first { it.id == "diploma" }
        // The second source's entry for "diploma" overwrote the first's.
        assertEquals("iso_18045_high", diploma.attestationLoS)
        assertTrue(schemas.any { it.id == "mdl" })
    }

    @Test
    fun `fetchSchemas skips a failing source and still returns entries from a succeeding one`() = runTest {
        val client = Ts11RegistryClient(
            sources = listOf(
                "https://unreachable-registry.example.org",
                "https://registry.siros.org",
            ),
            httpGet = { url ->
                when (url) {
                    "https://registry.siros.org/api/v1/schemas.json" ->
                        """{"data": [${schemaJson("diploma")}], "total": 1, "limit": 20, "offset": 0}"""
                    else -> null // unreachable source fails
                }
            },
        )

        val schemas = client.fetchSchemas()

        assertEquals(1, schemas.size)
        assertEquals("diploma", schemas[0].id)
    }

    @Test
    fun `fetchSchemas uses an explicit json URL source as-is`() = runTest {
        var calledUrl: String? = null
        val client = Ts11RegistryClient(
            sources = listOf("https://registry.siros.org/api/v1/registry.json"),
            httpGet = { url ->
                calledUrl = url
                null
            },
        )

        client.fetchSchemas()

        assertEquals("https://registry.siros.org/api/v1/registry.json", calledUrl)
    }

    // ── Ts11CredentialDiscovery: display-identity enrichment (feedback: TS11
    // discovery showed a raw registry UUID instead of a real name) ──────────

    @Test
    fun `discover resolves vct name and description from a mocked VCTM document`() = runTest {
        val registryClient = Ts11RegistryClient(httpGet = { url ->
            when (url) {
                "https://registry.siros.org/api/v1/schemas.json" ->
                    """{"data": [${schemaJson("diploma")}], "total": 1, "limit": 20, "offset": 0}"""
                else -> null
            }
        })
        val discovery = Ts11CredentialDiscovery(
            registryClient = registryClient,
            httpGet = { url ->
                if (url == "https://registry.siros.org/schemas/diploma/vctm.json") {
                    """
                    {
                      "vct": "https://example.org/vct/diploma",
                      "name": "University Diploma",
                      "description": "A verifiable higher-education diploma"
                    }
                    """.trimIndent()
                } else {
                    null
                }
            },
        )

        val discovered = discovery.discover()

        assertEquals(1, discovered.size)
        val dc = discovered[0]
        assertEquals("diploma", dc.schema.id)
        assertEquals("https://example.org/vct/diploma", dc.identifier)
        assertEquals("University Diploma", dc.name)
        assertEquals("A verifiable higher-education diploma", dc.description)
        assertEquals("University Diploma", dc.displayName)
    }

    @Test
    fun `discover resolves doctype and display name from a mocked MDDL document`() = runTest {
        val mdlSchemaJson = """
            {
              "id": "mdl",
              "version": "1.0",
              "attestationLoS": "iso_18045_high",
              "bindingType": "cose_key",
              "supportedFormats": ["mso_mdoc"],
              "schemaURIs": [
                { "formatIdentifier": "mso_mdoc", "uri": "https://registry.siros.org/schemas/mdl/mddl.json" }
              ]
            }
        """.trimIndent()
        val registryClient = Ts11RegistryClient(httpGet = { url ->
            when (url) {
                "https://registry.siros.org/api/v1/schemas.json" ->
                    """{"data": [$mdlSchemaJson], "total": 1, "limit": 20, "offset": 0}"""
                else -> null
            }
        })
        val discovery = Ts11CredentialDiscovery(
            registryClient = registryClient,
            httpGet = { url ->
                if (url == "https://registry.siros.org/schemas/mdl/mddl.json") {
                    """
                    {
                      "format": "mso_mdoc",
                      "doctype": "org.iso.18013.5.1.mDL",
                      "display": [
                        {"locale": "en", "name": "Mobile Driving Licence", "description": "ISO 18013-5 mDL"}
                      ]
                    }
                    """.trimIndent()
                } else {
                    null
                }
            },
        )

        val discovered = discovery.discover()

        assertEquals(1, discovered.size)
        val dc = discovered[0]
        assertEquals("mdl", dc.schema.id)
        assertEquals("org.iso.18013.5.1.mDL", dc.identifier)
        assertEquals("Mobile Driving Licence", dc.name)
        assertEquals("ISO 18013-5 mDL", dc.description)
    }

    @Test
    fun `discover falls back to the raw registry id when the schema document fetch fails`() = runTest {
        val registryClient = Ts11RegistryClient(httpGet = { url ->
            when (url) {
                "https://registry.siros.org/api/v1/schemas.json" ->
                    """{"data": [${schemaJson("diploma")}], "total": 1, "limit": 20, "offset": 0}"""
                else -> null
            }
        })
        // Document fetch always fails (network error) - discovery must degrade
        // gracefully to the raw id, not throw, and not drop the entry.
        val discovery = Ts11CredentialDiscovery(
            registryClient = registryClient,
            httpGet = { throw java.io.IOException("network error") },
        )

        val discovered = discovery.discover()

        assertEquals(1, discovered.size)
        val dc = discovered[0]
        assertEquals("diploma", dc.identifier)
        assertEquals(null, dc.name)
        assertEquals(null, dc.description)
        assertEquals("diploma", dc.displayName)
    }

    @Test
    fun `discover falls back to the raw registry id when no recognized format is in schemaURIs`() = runTest {
        val unknownFormatSchema = """
            {
              "id": "unknown-fmt",
              "version": "1.0",
              "attestationLoS": "iso_18045_basic",
              "bindingType": "jwk",
              "supportedFormats": ["some_future_format"],
              "schemaURIs": [
                { "formatIdentifier": "some_future_format", "uri": "https://registry.siros.org/schemas/unknown-fmt/doc.json" }
              ]
            }
        """.trimIndent()
        val registryClient = Ts11RegistryClient(httpGet = { url ->
            when (url) {
                "https://registry.siros.org/api/v1/schemas.json" ->
                    """{"data": [$unknownFormatSchema], "total": 1, "limit": 20, "offset": 0}"""
                else -> null
            }
        })
        val discovery = Ts11CredentialDiscovery(
            registryClient = registryClient,
            httpGet = { fail("should never fetch a document for an unrecognized format"); null },
        )

        val discovered = discovery.discover()

        assertEquals(1, discovered.size)
        assertEquals("unknown-fmt", discovered[0].identifier)
        assertEquals(null, discovered[0].name)
    }

    @Test
    fun `discover falls back to the raw registry id when the document body is unparseable`() = runTest {
        val registryClient = Ts11RegistryClient(httpGet = { url ->
            when (url) {
                "https://registry.siros.org/api/v1/schemas.json" ->
                    """{"data": [${schemaJson("diploma")}], "total": 1, "limit": 20, "offset": 0}"""
                else -> null
            }
        })
        val discovery = Ts11CredentialDiscovery(
            registryClient = registryClient,
            httpGet = { "not valid json at all" },
        )

        val discovered = discovery.discover()

        assertEquals(1, discovered.size)
        assertEquals("diploma", discovered[0].identifier)
        assertEquals(null, discovered[0].name)
    }

    @Test
    fun `discover enriches multiple entries independently, one bad entry does not block the rest`() = runTest {
        val page = """{"data": [${schemaJson("diploma")}, ${schemaJson("passport")}], "total": 2, "limit": 20, "offset": 0}"""
        val registryClient = Ts11RegistryClient(httpGet = { url ->
            if (url == "https://registry.siros.org/api/v1/schemas.json") page else null
        })
        val discovery = Ts11CredentialDiscovery(
            registryClient = registryClient,
            httpGet = { url ->
                when (url) {
                    "https://registry.siros.org/schemas/diploma/vctm.json" ->
                        """{"vct": "https://example.org/vct/diploma", "name": "Diploma"}"""
                    // passport's document fetch fails - only that entry should fall back.
                    else -> null
                }
            },
        )

        val discovered = discovery.discover()

        assertEquals(2, discovered.size)
        val diploma = discovered.first { it.schema.id == "diploma" }
        val passport = discovered.first { it.schema.id == "passport" }
        assertEquals("Diploma", diploma.name)
        assertEquals("https://example.org/vct/diploma", diploma.identifier)
        assertEquals(null, passport.name)
        assertEquals("passport", passport.identifier)
    }
}
