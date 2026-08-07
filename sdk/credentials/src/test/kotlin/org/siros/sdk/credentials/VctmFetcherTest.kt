package org.siros.sdk.credentials

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class VctmFetcherTest {

    private val sampleVctmJson = """
        {
          "vct": "urn:example:diploma",
          "name": "University Diploma",
          "display": [
            {
              "locale": "en",
              "name": "University Diploma",
              "description": "A diploma credential",
              "rendering": {
                "simple": {
                  "background_color": "#003366",
                  "text_color": "#ffffff",
                  "logo": { "uri": "https://example.com/logo.png", "alt_text": "Logo" }
                }
              }
            }
          ],
          "claims": [
            {
              "path": ["given_name"],
              "display": [{ "locale": "en", "label": "Given Name" }],
              "sd": "allowed",
              "mandatory": true
            },
            {
              "path": ["family_name"],
              "display": [{ "locale": "en", "label": "Family Name" }],
              "sd": "always"
            }
          ]
        }
    """.trimIndent()

    @Test
    fun `parseVctm parses valid JSON`() {
        val fetcher = VctmFetcher()
        val vctm = fetcher.parseVctm(sampleVctmJson)
        assertNotNull(vctm)
        assertEquals("urn:example:diploma", vctm!!.vct)
        assertEquals("University Diploma", vctm.name)
        assertEquals(1, vctm.display!!.size)
        assertEquals("en", vctm.display!![0].locale)
        assertEquals("#003366", vctm.display!![0].rendering?.simple?.backgroundColor)
        assertEquals(2, vctm.claims!!.size)
        assertEquals("given_name", vctm.claims!![0].path[0])
        assertEquals(true, vctm.claims!![0].mandatory)
        assertEquals("always", vctm.claims!![1].sd)
    }

    @Test
    fun `parseVctm returns null for invalid JSON`() {
        val fetcher = VctmFetcher()
        assertNull(fetcher.parseVctm("{not valid json"))
    }

    @Test
    fun `parseVctm returns null for empty string`() {
        val fetcher = VctmFetcher()
        assertNull(fetcher.parseVctm(""))
    }

    @Test
    fun `parseVctm handles minimal VCTM`() {
        val fetcher = VctmFetcher()
        val vctm = fetcher.parseVctm("""{"vct": "urn:minimal"}""")
        assertNotNull(vctm)
        assertEquals("urn:minimal", vctm!!.vct)
        assertNull(vctm.display)
        assertNull(vctm.claims)
    }

    @Test
    fun `fetch returns VCTM from type-metadata endpoint`() = runTest {
        val fetcher = VctmFetcher(httpGet = { url ->
            if (url == "https://issuer.example.com/type-metadata/diploma_scope") {
                sampleVctmJson
            } else {
                null
            }
        })
        val vctm = fetcher.fetch("https://issuer.example.com", "diploma_scope")
        assertNotNull(vctm)
        assertEquals("urn:example:diploma", vctm!!.vct)
    }

    @Test
    fun `fetch falls back to well-known when type-metadata fails`() = runTest {
        val fetcher = VctmFetcher(httpGet = { url ->
            when {
                url.contains("type-metadata") -> null
                url == "https://issuer.example.com/.well-known/vct/diploma" -> sampleVctmJson
                else -> null
            }
        })
        val vctm = fetcher.fetch(
            "https://issuer.example.com",
            "diploma_scope",
            vct = "https://issuer.example.com/diploma",
        )
        assertNotNull(vctm)
        assertEquals("urn:example:diploma", vctm!!.vct)
    }

    @Test
    fun `fetch returns null when both strategies fail`() = runTest {
        val fetcher = VctmFetcher(httpGet = { null })
        val vctm = fetcher.fetch("https://issuer.example.com", "missing_scope")
        assertNull(vctm)
    }

    @Test
    fun `fetch returns null when httpGet throws`() = runTest {
        val fetcher = VctmFetcher(httpGet = { throw java.io.IOException("network error") })
        val vctm = fetcher.fetch("https://issuer.example.com", "scope")
        assertNull(vctm)
    }

    @Test
    fun `fetch trims trailing slash from issuer URL`() = runTest {
        var calledUrl: String? = null
        val fetcher = VctmFetcher(httpGet = { url ->
            calledUrl = url
            null
        })
        fetcher.fetch("https://issuer.example.com/", "scope")
        assertEquals("https://issuer.example.com/type-metadata/scope", calledUrl)
    }

    @Test
    fun `fetch handles malformed VCT for well-known resolution`() = runTest {
        val fetcher = VctmFetcher(httpGet = { null })
        // Non-HTTP VCT should not produce a well-known URL
        val vctm = fetcher.fetch("https://issuer.example.com", "scope", vct = "not-a-url")
        assertNull(vctm)
    }

    @Test
    fun `fetch returns VCTM from registry service when registryUrl and vct are known`() = runTest {
        var calledUrl: String? = null
        val fetcher = VctmFetcher(httpGet = { url ->
            calledUrl = url
            if (url == "https://wallet.example.com/registry/type-metadata?vct=urn%3Aexample%3Adiploma") {
                sampleVctmJson
            } else {
                null
            }
        })
        val vctm = fetcher.fetch(
            issuerUrl = "https://issuer.example.com",
            scope = "diploma_scope",
            vct = "urn:example:diploma",
            registryUrl = "https://wallet.example.com/registry",
        )
        assertNotNull(vctm)
        assertEquals("urn:example:diploma", vctm!!.vct)
        assertEquals(
            "https://wallet.example.com/registry/type-metadata?vct=urn%3Aexample%3Adiploma",
            calledUrl,
        )
    }

    @Test
    fun `fetch trims trailing slash from registryUrl`() = runTest {
        val calledUrls = mutableListOf<String>()
        val fetcher = VctmFetcher(httpGet = { url ->
            calledUrls.add(url)
            null
        })
        fetcher.fetch(
            issuerUrl = "https://issuer.example.com",
            scope = "scope",
            vct = "urn:example:diploma",
            registryUrl = "https://wallet.example.com/registry/",
        )
        assertEquals(
            "https://wallet.example.com/registry/type-metadata?vct=urn%3Aexample%3Adiploma",
            calledUrls.first(),
        )
    }

    @Test
    fun `fetch falls through to issuer-direct strategies when registry has no entry`() = runTest {
        val fetcher = VctmFetcher(httpGet = { url ->
            when {
                url.contains("/registry/") -> null // registry 404 / miss
                url == "https://issuer.example.com/type-metadata/diploma_scope" -> sampleVctmJson
                else -> null
            }
        })
        val vctm = fetcher.fetch(
            issuerUrl = "https://issuer.example.com",
            scope = "diploma_scope",
            vct = "urn:example:diploma",
            registryUrl = "https://wallet.example.com/registry",
        )
        assertNotNull(vctm)
        assertEquals("urn:example:diploma", vctm!!.vct)
    }

    @Test
    fun `fetch skips registry strategy when registryUrl is null`() = runTest {
        var registryQueried = false
        val fetcher = VctmFetcher(httpGet = { url ->
            if (url.contains("/registry/")) registryQueried = true
            if (url == "https://issuer.example.com/type-metadata/diploma_scope") sampleVctmJson else null
        })
        val vctm = fetcher.fetch(
            issuerUrl = "https://issuer.example.com",
            scope = "diploma_scope",
            vct = "urn:example:diploma",
            registryUrl = null,
        )
        assertNotNull(vctm)
        assertEquals(false, registryQueried)
    }

    @Test
    fun `fetch skips registry strategy when vct is not yet known`() = runTest {
        var registryQueried = false
        val fetcher = VctmFetcher(httpGet = { url ->
            if (url.contains("/registry/")) registryQueried = true
            if (url == "https://issuer.example.com/type-metadata/diploma_scope") sampleVctmJson else null
        })
        val vctm = fetcher.fetch(
            issuerUrl = "https://issuer.example.com",
            scope = "diploma_scope",
            vct = null,
            registryUrl = "https://wallet.example.com/registry",
        )
        assertNotNull(vctm)
        assertEquals(false, registryQueried)
    }

    // ── Caching ─────────────────────────────────────────────────────

    @Test
    fun `fetch caches successful result and does not hit network again within ttl`() = runTest {
        var callCount = 0
        val fetcher = VctmFetcher(httpGet = { url ->
            callCount++
            if (url == "https://issuer.example.com/type-metadata/diploma_scope") sampleVctmJson else null
        })

        val first = fetcher.fetch("https://issuer.example.com", "diploma_scope")
        val second = fetcher.fetch("https://issuer.example.com", "diploma_scope")

        assertNotNull(first)
        assertNotNull(second)
        assertEquals("urn:example:diploma", second!!.vct)
        assertEquals(1, callCount)
    }

    @Test
    fun `fetch does not serve a different key from another entry's cache`() = runTest {
        var callCount = 0
        val fetcher = VctmFetcher(httpGet = { url ->
            callCount++
            when (url) {
                "https://issuer.example.com/type-metadata/diploma_scope" -> sampleVctmJson
                "https://issuer.example.com/type-metadata/other_scope" ->
                    """{"vct": "urn:example:other"}"""
                "https://other-issuer.example.com/type-metadata/diploma_scope" ->
                    """{"vct": "urn:example:from-other-issuer"}"""
                else -> null
            }
        })

        val diploma = fetcher.fetch("https://issuer.example.com", "diploma_scope")
        val otherScope = fetcher.fetch("https://issuer.example.com", "other_scope")
        val otherIssuer = fetcher.fetch("https://other-issuer.example.com", "diploma_scope")

        assertEquals("urn:example:diploma", diploma!!.vct)
        assertEquals("urn:example:other", otherScope!!.vct)
        assertEquals("urn:example:from-other-issuer", otherIssuer!!.vct)
        // Three distinct cache keys, none served from another's entry, so all three hit the network.
        assertEquals(3, callCount)

        // Repeating each is now served from cache: no additional network calls.
        fetcher.fetch("https://issuer.example.com", "diploma_scope")
        fetcher.fetch("https://issuer.example.com", "other_scope")
        fetcher.fetch("https://other-issuer.example.com", "diploma_scope")
        assertEquals(3, callCount)
    }

    @Test
    fun `fetch re-fetches after the cache entry's ttl has expired`() = runTest {
        var callCount = 0
        var now = 0L
        val fetcher = VctmFetcher(
            httpGet = { url ->
                callCount++
                if (url == "https://issuer.example.com/type-metadata/diploma_scope") sampleVctmJson else null
            },
            cacheTtlSeconds = 10,
            nowMillis = { now },
        )

        fetcher.fetch("https://issuer.example.com", "diploma_scope")
        assertEquals(1, callCount)

        // Still within the 10s TTL: served from cache.
        now += 5_000
        fetcher.fetch("https://issuer.example.com", "diploma_scope")
        assertEquals(1, callCount)

        // Past the TTL: must hit the network again.
        now += 6_000
        fetcher.fetch("https://issuer.example.com", "diploma_scope")
        assertEquals(2, callCount)
    }

    @Test
    fun `fetch never caches a null result`() = runTest {
        var callCount = 0
        val fetcher = VctmFetcher(httpGet = { callCount++; null })

        val first = fetcher.fetch("https://issuer.example.com", "missing_scope")
        val second = fetcher.fetch("https://issuer.example.com", "missing_scope")

        assertNull(first)
        assertNull(second)
        // Both calls retried the network - a miss is never cached.
        assertEquals(2, callCount)
    }
}
