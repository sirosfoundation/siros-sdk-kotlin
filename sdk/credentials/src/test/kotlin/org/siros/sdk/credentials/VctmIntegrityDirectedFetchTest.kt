package org.siros.sdk.credentials

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.util.Base64

/**
 * Resolution directed by `vct#integrity`.
 *
 * A credential pins a digest over its type metadata so the issuer, rather than
 * whoever serves the document, decides what the type means. These tests cover
 * what that means for resolution: a document that does not hash to the pin is
 * not the document, whatever cache or source produced it.
 *
 * The bug these were written for: a wallet checked an issued credential against
 * a copy of the type metadata cached a week earlier, refused the credential,
 * and - because the failed lookup was itself cached with a six-hour backoff
 * that still served that old body - stayed wrong for hours after the issuer
 * was fixed.
 */
class VctmIntegrityDirectedFetchTest {

    private val issuer = "https://issuer.example"
    private val scope = "pid_1_8"
    private val registry = "https://backend.example/registry"

    private val current = """{"vct":"urn:eudi:pid:arf-1.8:1","name":"PID"}"""
    private val stale = """{"vct":"urn:eudi:pid:arf-1.8:1","name":"PID (old)"}"""

    private fun sri(body: String): String =
        "sha256-" + Base64.getEncoder()
            .encodeToString(MessageDigest.getInstance("SHA-256").digest(body.toByteArray()))

    private fun key(vct: String?) =
        fetchCacheKey("vctm", issuer, scope, vct, registry)

    @Test
    fun `a cached document that does not match the pin is not used`() = runTest {
        val cache = InMemoryFetchCache()
        cache.put(
            key(null),
            FetchCacheEntry(status = FetchCacheStatus.HIT, body = stale, fetchedAtMillis = 0),
        )

        var served = 0
        val fetcher = VctmFetcher(
            httpGet = { served++; current },
            nowMillis = { 1_000 },
            persistentCache = cache,
        )

        val doc = fetcher.fetchDocument(
            issuerUrl = issuer,
            scope = scope,
            registryUrl = registry,
            expectedIntegrity = sri(current),
        )

        assertNotNull(doc)
        assertEquals(current, doc!!.raw)
        assertTrue("the network must be consulted when the cached copy fails the pin", served > 0)
    }

    @Test
    fun `a negative entry cannot serve a stale body against a pin`() = runTest {
        val cache = InMemoryFetchCache()
        // Exactly the state the bug left a device in: the last fetch failed, the
        // retry is hours away, and the entry still carries the old document.
        cache.put(
            key(null),
            FetchCacheEntry(
                status = FetchCacheStatus.MISS,
                body = stale,
                fetchedAtMillis = 0,
                attempts = 2,
                nextRetryAtMillis = 6 * 60 * 60 * 1_000,
            ),
        )

        var served = 0
        val fetcher = VctmFetcher(
            httpGet = { served++; current },
            nowMillis = { 1_000 },
            persistentCache = cache,
        )

        val doc = fetcher.fetchDocument(
            issuerUrl = issuer,
            scope = scope,
            registryUrl = registry,
            expectedIntegrity = sri(current),
        )

        assertNotNull("the backoff must not outlive a caller that knows the answer is wrong", doc)
        assertEquals(current, doc!!.raw)
        assertTrue(served > 0)
    }

    @Test
    fun `without a pin the negative entry still serves its retained body`() = runTest {
        val cache = InMemoryFetchCache()
        cache.put(
            key(null),
            FetchCacheEntry(
                status = FetchCacheStatus.MISS,
                body = stale,
                fetchedAtMillis = 0,
                attempts = 2,
                nextRetryAtMillis = 6 * 60 * 60 * 1_000,
            ),
        )

        var served = 0
        val fetcher = VctmFetcher(
            httpGet = { served++; current },
            nowMillis = { 1_000 },
            persistentCache = cache,
        )

        val doc = fetcher.fetchDocument(issuerUrl = issuer, scope = scope, registryUrl = registry)

        assertEquals("offline resilience is unchanged when nothing is pinned", stale, doc?.raw)
        assertEquals(0, served)
    }

    @Test
    fun `a source serving the wrong document is passed over for one that matches`() = runTest {
        // The registry answers with the old document; the issuer's own endpoint
        // has the one the credential was signed over.
        val fetcher = VctmFetcher(
            httpGet = { url -> if (url.startsWith(registry)) stale else current },
            nowMillis = { 1_000 },
        )

        val doc = fetcher.fetchDocument(
            issuerUrl = issuer,
            scope = scope,
            vct = "urn:eudi:pid:arf-1.8:1",
            registryUrl = registry,
            expectedIntegrity = sri(current),
        )

        assertEquals(current, doc?.raw)
    }

    @Test
    fun `nothing matching anywhere resolves to nothing rather than to the wrong document`() = runTest {
        val fetcher = VctmFetcher(httpGet = { stale }, nowMillis = { 1_000 })

        val doc = fetcher.fetchDocument(
            issuerUrl = issuer,
            scope = scope,
            registryUrl = registry,
            expectedIntegrity = sri(current),
        )

        assertNull(doc)
    }
}
