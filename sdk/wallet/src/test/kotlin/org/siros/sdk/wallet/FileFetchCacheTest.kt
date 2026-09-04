// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.siros.sdk.credentials.FetchBackoff
import org.siros.sdk.credentials.FetchCacheEntry
import org.siros.sdk.credentials.FetchCacheStatus
import java.io.File

class FileFetchCacheTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private fun file() = File(tmp.root, "cache/display-metadata.json")

    @Test
    fun `entries survive a new instance over the same file`() = runTest {
        val first = FileFetchCache(file())
        first.put("k1", FetchBackoff.recordHit("""{"vct":"a"}""", nowMillis = 1000))
        first.put("k2", FetchBackoff.recordMiss(null, nowMillis = 2000))

        // "Process restart."
        val second = FileFetchCache(file())
        val hit = second.get("k1")!!
        assertEquals(FetchCacheStatus.HIT, hit.status)
        assertEquals("""{"vct":"a"}""", hit.body)
        assertEquals(1000L, hit.fetchedAtMillis)
        val miss = second.get("k2")!!
        assertEquals(FetchCacheStatus.MISS, miss.status)
        assertEquals(1, miss.attempts)
        assertEquals(2000L + FetchBackoff.intervalMillis(1), miss.nextRetryAtMillis)
        assertNull(second.get("absent"))
    }

    @Test
    fun `a corrupt file is treated as empty and then overwritten cleanly`() = runTest {
        val f = file()
        f.parentFile!!.mkdirs()
        f.writeText("{ this is not json")

        val cache = FileFetchCache(f)
        assertNull(cache.get("anything"))
        cache.put("k", FetchBackoff.recordHit("body", nowMillis = 5))
        assertEquals("body", FileFetchCache(f).get("k")!!.body)
    }

    @Test
    fun `a missing file is simply empty`() = runTest {
        val cache = FileFetchCache(file())
        assertNull(cache.get("k"))
        assertEquals(0, cache.size())
    }

    @Test
    fun `put replaces an existing entry`() = runTest {
        val cache = FileFetchCache(file())
        cache.put("k", FetchBackoff.recordMiss(null, nowMillis = 1))
        cache.put("k", FetchBackoff.recordHit("now good", nowMillis = 2))
        val entry = FileFetchCache(file()).get("k")!!
        assertEquals(FetchCacheStatus.HIT, entry.status)
        assertEquals(0, entry.attempts)
        assertEquals(1, cache.size())
    }

    @Test
    fun `oldest entries are evicted past the bound`() = runTest {
        val cache = FileFetchCache(file(), maxEntries = 3)
        for (i in 1..5) {
            cache.put("k$i", FetchCacheEntry(FetchCacheStatus.HIT, "b$i", fetchedAtMillis = i.toLong()))
        }
        assertEquals(3, cache.size())
        assertNull(cache.get("k1"))
        assertNull(cache.get("k2"))
        assertEquals("b5", cache.get("k5")!!.body)
    }

    @Test
    fun `no temp file is left behind after a write`() = runTest {
        val cache = FileFetchCache(file())
        cache.put("k", FetchBackoff.recordHit("b", nowMillis = 1))
        val names = file().parentFile!!.list()!!.toList()
        assertEquals(listOf(file().name), names)
        assertTrue(file().readText().contains("\"k\""))
    }

    @Test
    fun `clear removes everything including the file`() = runTest {
        val cache = FileFetchCache(file())
        cache.put("k", FetchBackoff.recordHit("b", nowMillis = 1))
        cache.clear()
        assertEquals(false, file().exists())
        assertNull(FileFetchCache(file()).get("k"))
    }
}
