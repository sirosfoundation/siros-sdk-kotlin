// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.dcapi

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.siros.sdk.credentials.FetchBackoff

/**
 * The file/backoff half of [PickerIconCache], with the download and the
 * Bitmap rendering swapped for pure fakes - `android.graphics` is stubs on
 * the JVM, and the geometry it depends on has its own test.
 */
class PickerIconCacheTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val logo = "https://issuer.example.com/logo.png"
    private val fakePng = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 1, 2, 3)

    private fun cache(
        now: () -> Long,
        download: (String) -> ByteArray?,
        render: (ByteArray, String?) -> ByteArray? = { bytes, _ -> if (bytes.isEmpty()) null else fakePng },
    ) = PickerIconCache(dir = tmp.root, nowMillis = now, download = download, render = render)

    @Test
    fun `nothing cached and due before any fetch`() = runTest {
        val c = cache(now = { 0 }, download = { null })
        assertNull(c.cached(logo, "#112233"))
        assertTrue(c.isDue(logo, "#112233"))
    }

    @Test
    fun `a successful fetch stores the rendered PNG and is served by a fresh instance`() = runTest {
        var downloads = 0
        val c = cache(now = { 0 }, download = { downloads++; byteArrayOf(1, 2, 3) })
        assertArrayEquals(fakePng, c.fetchAndStore(logo, "#112233"))
        assertEquals(1, downloads)

        val again = PickerIconCache(dir = tmp.root, nowMillis = { 0 }, download = { downloads++; null })
        assertArrayEquals(fakePng, again.cached(logo, "#112233"))
        assertFalse(again.isDue(logo, "#112233"))
        assertEquals(1, downloads)
    }

    @Test
    fun `a failed download records a miss with backoff and is not due until it lapses`() = runTest {
        var now = 1_000_000L
        val c = cache(now = { now }, download = { null })
        assertNull(c.fetchAndStore(logo, null))
        assertNull(c.cached(logo, null))
        assertFalse(c.isDue(logo, null))

        now += FetchBackoff.intervalMillis(1) - 1
        assertFalse(c.isDue(logo, null))
        now += 1
        assertTrue(c.isDue(logo, null))

        // Second failure: attempts=2 -> the next interval.
        assertNull(c.fetchAndStore(logo, null))
        now += FetchBackoff.intervalMillis(2) - 1
        assertFalse(c.isDue(logo, null))
        now += 1
        assertTrue(c.isDue(logo, null))
    }

    @Test
    fun `an undecodable body - an SVG say - is a miss too`() = runTest {
        // download succeeds, render (BitmapFactory in production) says no.
        val c = cache(now = { 0 }, download = { "<svg/>".toByteArray() }, render = { _, _ -> null })
        assertNull(c.fetchAndStore(logo, null))
        assertFalse(c.isDue(logo, null))
    }

    @Test
    fun `a later success clears the miss`() = runTest {
        var now = 0L
        var body: ByteArray? = null
        val c = cache(now = { now }, download = { body })
        assertNull(c.fetchAndStore(logo, null))
        now += FetchBackoff.intervalMillis(1)
        body = byteArrayOf(9)
        assertArrayEquals(fakePng, c.fetchAndStore(logo, null))
        assertArrayEquals(fakePng, c.cached(logo, null))
        assertEquals(1, tmp.root.list()!!.size) // only the .png remains
    }

    @Test
    fun `a throwing downloader is a miss, never an exception`() = runTest {
        val c = cache(now = { 0 }, download = { throw java.io.IOException("boom") })
        assertNull(c.fetchAndStore(logo, null))
        assertFalse(c.isDue(logo, null))
    }

    @Test
    fun `keys separate colours, normalise their case, and are safe file names`() {
        val a = PickerIconCache.key(logo, "#1a365d")
        assertEquals(a, PickerIconCache.key(logo, "#1A365D"))
        assertEquals(a, PickerIconCache.key(logo, null)) // default colour is #1A365D
        assertNotEquals(a, PickerIconCache.key(logo, "#FFFFFF"))
        assertNotEquals(a, PickerIconCache.key("$logo?v=2", "#1A365D"))
        assertTrue(a.matches(Regex("[0-9a-f]{64}")))
    }

    @Test
    fun `data URIs decode inline`() {
        val png = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47)
        val b64 = java.util.Base64.getEncoder().encodeToString(png)
        assertArrayEquals(png, PickerIconCache.decodeDataUri("data:image/png;base64,$b64"))
        assertArrayEquals(png, PickerIconCache.downloadWithUrlConnection("data:image/png;base64,$b64"))
        assertNull(PickerIconCache.decodeDataUri("data:image/png;base64"))
        assertNull(PickerIconCache.decodeDataUri("data:image/png;base64,%%%not-base64%%%"))
    }

    @Test
    fun `percent-encoded data URIs decode to raw bytes, with plus taken literally`() {
        // PNG signature (all eight bytes escaped, two of them above 0x7F or
        // control characters), then a literal `+` and an unescaped `x`.
        val expected = byteArrayOf(
            0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, '+'.code.toByte(), 'x'.code.toByte(),
        )
        assertArrayEquals(expected, PickerIconCache.decodeDataUri("data:image/png,%89PNG%0D%0A%1A%0A+x"))
        assertArrayEquals(byteArrayOf(0xFF.toByte(), 0x00), PickerIconCache.percentDecode("%ff%00"))
        assertNull(PickerIconCache.percentDecode("%4")) // truncated escape
        assertNull(PickerIconCache.percentDecode("%zz")) // non-hex escape
    }

    @Test
    fun `only http, https and data schemes are fetched`() {
        assertNull(PickerIconCache.downloadWithUrlConnection("file:///etc/passwd"))
        assertNull(PickerIconCache.downloadWithUrlConnection("ftp://example.com/logo.png"))
        assertNull(PickerIconCache.downloadWithUrlConnection("not a url at all"))
    }
}
