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

    // ── Persistent cache (negative caching + backoff) ───────────────

    private companion object {
        const val HOUR = 60L * 60L * 1000L
        const val DAY = 24 * HOUR
    }

    @Test
    fun `persistent cache records a miss and suppresses the network until the retry is due`() = runTest {
        var callCount = 0
        var now = 1_000_000L
        val cache = InMemoryFetchCache()
        val fetcher = VctmFetcher(
            httpGet = { callCount++; null },
            nowMillis = { now },
            persistentCache = cache,
        )

        assertNull(fetcher.fetch("https://issuer.example.com", "missing_scope"))
        assertEquals(1, callCount)
        val entry = cache.snapshot().values.single()
        assertEquals(FetchCacheStatus.MISS, entry.status)
        assertEquals(1, entry.attempts)
        assertEquals(now + HOUR, entry.nextRetryAtMillis)

        // Not due yet: no network call at all, immediate null. This is the
        // per-launch spinner fix - a second fetcher instance stands in for a
        // second process launch sharing the same on-disk cache.
        now += 30 * 60 * 1000
        val relaunched = VctmFetcher(httpGet = { callCount++; null }, nowMillis = { now }, persistentCache = cache)
        assertNull(relaunched.fetch("https://issuer.example.com", "missing_scope"))
        assertEquals(1, callCount)

        // Due: retried, still failing, backoff grows.
        now += 31 * 60 * 1000
        assertNull(relaunched.fetch("https://issuer.example.com", "missing_scope"))
        assertEquals(2, callCount)
        assertEquals(2, cache.snapshot().values.single().attempts)
        assertEquals(now + 6 * HOUR, cache.snapshot().values.single().nextRetryAtMillis)
    }

    @Test
    fun `backoff follows the shared schedule and caps at a week`() {
        assertEquals(1 * HOUR, FetchBackoff.intervalMillis(1))
        assertEquals(6 * HOUR, FetchBackoff.intervalMillis(2))
        assertEquals(24 * HOUR, FetchBackoff.intervalMillis(3))
        assertEquals(7 * DAY, FetchBackoff.intervalMillis(4))
        assertEquals(7 * DAY, FetchBackoff.intervalMillis(5))
        assertEquals(7 * DAY, FetchBackoff.intervalMillis(50))
        // Defensive: a zero/negative count is treated as the first failure.
        assertEquals(1 * HOUR, FetchBackoff.intervalMillis(0))
    }

    @Test
    fun `a due retry that succeeds flips the entry to a hit`() = runTest {
        var now = 0L
        var serve = false
        var callCount = 0
        val cache = InMemoryFetchCache()
        val fetcher = VctmFetcher(
            httpGet = { url ->
                callCount++
                if (serve && url == "https://issuer.example.com/type-metadata/diploma_scope") sampleVctmJson else null
            },
            nowMillis = { now },
            persistentCache = cache,
        )

        assertNull(fetcher.fetch("https://issuer.example.com", "diploma_scope"))
        assertEquals(FetchCacheStatus.MISS, cache.snapshot().values.single().status)

        serve = true
        now += HOUR + 1
        val vctm = fetcher.fetch("https://issuer.example.com", "diploma_scope")
        assertNotNull(vctm)
        assertEquals("urn:example:diploma", vctm!!.vct)
        assertEquals(2, callCount)
        val entry = cache.snapshot().values.single()
        assertEquals(FetchCacheStatus.HIT, entry.status)
        assertEquals(0, entry.attempts)
        assertEquals(sampleVctmJson, entry.body)
        assertEquals(now, entry.fetchedAtMillis)
    }

    @Test
    fun `a persisted hit is served across instances with no network while fresh`() = runTest {
        var now = 0L
        var callCount = 0
        val cache = InMemoryFetchCache()
        val first = VctmFetcher(
            httpGet = { url ->
                callCount++
                if (url == "https://issuer.example.com/type-metadata/diploma_scope") sampleVctmJson else null
            },
            nowMillis = { now },
            persistentCache = cache,
        )
        assertNotNull(first.fetch("https://issuer.example.com", "diploma_scope"))
        assertEquals(1, callCount)

        // "Process restart": a fresh instance with an empty in-memory layer.
        now += 12 * HOUR
        val second = VctmFetcher(httpGet = { callCount++; null }, nowMillis = { now }, persistentCache = cache)
        val vctm = second.fetch("https://issuer.example.com", "diploma_scope")
        assertNotNull(vctm)
        assertEquals("urn:example:diploma", vctm!!.vct)
        assertEquals(1, callCount)
    }

    @Test
    fun `a stale hit is served immediately and revalidated in the background when a scope is given`() = runTest {
        var now = 0L
        val calls = mutableListOf<String>()
        val cache = InMemoryFetchCache()
        val updated = """{"vct": "urn:example:diploma", "name": "Diploma v2"}"""
        var body = sampleVctmJson
        val fetcher = VctmFetcher(
            httpGet = { url ->
                calls.add(url)
                if (url == "https://issuer.example.com/type-metadata/diploma_scope") body else null
            },
            nowMillis = { now },
            persistentCache = cache,
            revalidateScope = backgroundScope,
        )
        assertEquals("University Diploma", fetcher.fetch("https://issuer.example.com", "diploma_scope")!!.name)
        assertEquals(1, calls.size)

        // Past the 24 h fresh window, inside the 7 d hard window, from a new
        // instance (so the in-memory layer can't answer).
        now += 2 * DAY
        body = updated
        val relaunched = VctmFetcher(
            httpGet = { url ->
                calls.add(url)
                if (url == "https://issuer.example.com/type-metadata/diploma_scope") body else null
            },
            nowMillis = { now },
            persistentCache = cache,
            revalidateScope = backgroundScope,
        )
        // Served the stale document synchronously...
        assertEquals("University Diploma", relaunched.fetch("https://issuer.example.com", "diploma_scope")!!.name)
        // ...and the refresh lands on the background scope. Polled in real
        // time: the network hop goes through Dispatchers.IO, which the test
        // scheduler's virtual clock cannot advance.
        awaitRealTime { cache.snapshot().values.single().body == updated }
        assertEquals(2, calls.size)
        assertEquals(now, cache.snapshot().values.single().fetchedAtMillis)
        // A second stale read in the meantime would not have started another.
        assertEquals("Diploma v2", relaunched.fetch("https://issuer.example.com", "diploma_scope")!!.name)
        assertEquals(2, calls.size)
    }

    private suspend fun awaitRealTime(timeoutMillis: Long = 5_000, condition: suspend () -> Boolean) {
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Default) {
            kotlinx.coroutines.withTimeout(timeoutMillis) {
                while (!condition()) kotlinx.coroutines.delay(10)
            }
        }
    }

    @Test
    fun `a stale hit is served as-is without a revalidate scope`() = runTest {
        var now = 0L
        var callCount = 0
        val cache = InMemoryFetchCache()
        cache.put(
            fetchCacheKey("vctm", "https://issuer.example.com", "diploma_scope", null, null),
            FetchBackoff.recordHit(sampleVctmJson, nowMillis = now),
        )
        now += 3 * DAY
        val fetcher = VctmFetcher(httpGet = { callCount++; null }, nowMillis = { now }, persistentCache = cache)
        assertNotNull(fetcher.fetch("https://issuer.example.com", "diploma_scope"))
        assertEquals(0, callCount)
    }

    @Test
    fun `a hard-expired hit is refetched inline and its old body kept if the refetch fails`() = runTest {
        var now = 0L
        var callCount = 0
        val cache = InMemoryFetchCache()
        cache.put(
            fetchCacheKey("vctm", "https://issuer.example.com", "diploma_scope", null, null),
            FetchBackoff.recordHit(sampleVctmJson, nowMillis = now),
        )
        now += 8 * DAY
        val fetcher = VctmFetcher(httpGet = { callCount++; null }, nowMillis = { now }, persistentCache = cache)

        // Network was tried (hard TTL passed), failed, and the week-old
        // document is still what the caller gets - better than a blank card.
        val vctm = fetcher.fetch("https://issuer.example.com", "diploma_scope")
        assertEquals(1, callCount)
        assertNotNull(vctm)
        assertEquals("urn:example:diploma", vctm!!.vct)
        val entry = cache.snapshot().values.single()
        assertEquals(FetchCacheStatus.MISS, entry.status)
        assertEquals(sampleVctmJson, entry.body)
        assertEquals(1, entry.attempts)

        // And while that miss is not due, still no network but still the old body.
        now += 10 * 60 * 1000
        assertNotNull(fetcher.fetch("https://issuer.example.com", "diploma_scope"))
        assertEquals(1, callCount)
    }

    @Test
    fun `a 200 whose body is not a VCTM is a miss, not a poisoned hit`() = runTest {
        var now = 0L
        var callCount = 0
        val cache = InMemoryFetchCache()
        val fetcher = VctmFetcher(
            httpGet = { callCount++; "<html>Service Unavailable</html>" },
            nowMillis = { now },
            persistentCache = cache,
        )
        assertNull(fetcher.fetch("https://issuer.example.com", "diploma_scope"))
        assertEquals(FetchCacheStatus.MISS, cache.snapshot().values.single().status)
        assertNull(cache.snapshot().values.single().body)
        now += 1
        assertNull(fetcher.fetch("https://issuer.example.com", "diploma_scope"))
        // One attempt covered every strategy for the first call; the second
        // call was suppressed entirely.
        assertEquals(1, callCount)
    }

    @Test
    fun `persistent cache keys are namespaced and unambiguous`() {
        val a = fetchCacheKey("vctm", "https://issuer.example.com", "scope", null, null)
        val b = fetchCacheKey("mddl", "https://issuer.example.com", "scope", null, null)
        assertEquals(false, a == b)
        // A separator-based join would collide these two; a JSON array can't.
        assertEquals(
            false,
            fetchCacheKey("x", "a|b", null) == fetchCacheKey("x", "a", "b"),
        )
        assertEquals(a, fetchCacheKey("vctm", "https://issuer.example.com", "scope", null, null))
    }
}
