// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.dcapi

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import org.siros.sdk.credentials.FetchBackoff
import org.siros.sdk.credentials.FetchCacheEntry
import org.siros.sdk.credentials.FetchCacheStatus
import timber.log.Timber
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.security.MessageDigest

/**
 * On-device cache of the 64x64 PNG icons the OS credential picker shows,
 * rendered from issuer logos by [PickerIconRenderer].
 *
 * ### Layout
 *
 * One directory (`noBackupFilesDir/siros-picker-icons/` by default - public
 * images, nothing to protect or back up) holding, per icon key:
 *
 * - `<key>.png` - the rendered icon, when the logo was fetched and decoded;
 * - `<key>.miss` - a JSON [FetchCacheEntry] recording that it could not be,
 *   with [FetchBackoff]'s retry schedule, so a dead URL or an SVG logo is not
 *   downloaded again on every registration.
 *
 * The key is the SHA-256 of the logo URL *and* the background colour it was
 * composited over - two credentials sharing a logo but with different card
 * colours legitimately need two icons.
 *
 * ### Contract with the registry
 *
 * [cached] is a plain file read and is what registration uses, so
 * registering never waits on the network. [fetchAndStore] does the download
 * and is meant to run afterwards, in the background; it never throws.
 *
 * ### Download limits
 *
 * `http(s)` and `data:` URIs only. Connect/read timeouts of
 * [TIMEOUT_MILLIS]; bodies over [MAX_DOWNLOAD_BYTES] are abandoned (a logo
 * that large is a mistake, and the picker will show it at 64 px anyway).
 *
 * @param dir where icons live; tests pass a temp directory.
 * @param nowMillis clock for backoff, overridable for tests.
 * @param download the HTTP GET; overridable for tests. Returns the body or
 *        null on any failure.
 * @param render turns raw image bytes + background colour into PNG bytes,
 *        or null when the bytes aren't a raster image. Defaults to
 *        [PickerIconRenderer.render]; tests substitute a pure function since
 *        `android.graphics` is stubs on the JVM.
 */
class PickerIconCache(
    private val dir: File,
    private val nowMillis: () -> Long = { System.currentTimeMillis() },
    private val download: (String) -> ByteArray? = ::downloadWithUrlConnection,
    private val render: (ByteArray, String?) -> ByteArray? = PickerIconRenderer::render,
) {
    constructor(context: Context) : this(File(context.noBackupFilesDir, DIR_NAME))

    private val json = Json { ignoreUnknownKeys = true }
    private val mutex = Mutex()

    /** The rendered icon for [logoUrl] over [backgroundColor], if one is on disk. No network. */
    suspend fun cached(logoUrl: String, backgroundColor: String?): ByteArray? = withContext(Dispatchers.IO) {
        mutex.withLock {
            val png = pngFile(logoUrl, backgroundColor)
            try {
                if (png.isFile) png.readBytes().takeIf { it.isNotEmpty() } else null
            } catch (e: Exception) {
                Timber.w(e, "PickerIconCache: unreadable ${png.name}")
                null
            }
        }
    }

    /**
     * Whether a download of [logoUrl] may be attempted now: true when there
     * is neither an icon nor a still-current negative entry for it.
     */
    suspend fun isDue(logoUrl: String, backgroundColor: String?): Boolean = withContext(Dispatchers.IO) {
        mutex.withLock {
            if (pngFile(logoUrl, backgroundColor).isFile) return@withLock false
            val miss = readMissLocked(missFile(logoUrl, backgroundColor)) ?: return@withLock true
            nowMillis() >= miss.nextRetryAtMillis
        }
    }

    /**
     * Download [logoUrl], render it over [backgroundColor], store and return
     * the PNG. Records a negative entry (extending any existing backoff) and
     * returns null when anything along the way fails. Does NOT consult
     * [isDue] - callers decide when to retry.
     */
    suspend fun fetchAndStore(logoUrl: String, backgroundColor: String?): ByteArray? = withContext(Dispatchers.IO) {
        val bytes = try {
            download(logoUrl)
        } catch (e: Exception) {
            Timber.d(e, "PickerIconCache: download failed for $logoUrl")
            null
        }
        val png = bytes?.let {
            try {
                render(it, backgroundColor)
            } catch (e: Exception) {
                Timber.d(e, "PickerIconCache: render failed for $logoUrl")
                null
            }
        }
        mutex.withLock {
            if (png != null) {
                storeIconLocked(logoUrl, backgroundColor, png)
            } else {
                recordMissLocked(logoUrl, backgroundColor)
            }
        }
        png
    }

    /** Write the rendered icon and retire any negative entry for it. Caller holds [mutex]. */
    private fun storeIconLocked(logoUrl: String, backgroundColor: String?, png: ByteArray) {
        val missFile = missFile(logoUrl, backgroundColor)
        try {
            dir.mkdirs()
            writeAtomically(pngFile(logoUrl, backgroundColor), png)
            // A miss marker that outlives its icon is harmless to [cached] and
            // [isDue], which check for the PNG first - but it is still wrong
            // on disk, so say so rather than silently leaving it.
            if (!missFile.delete() && missFile.exists()) {
                Timber.w("PickerIconCache: could not remove stale ${missFile.name}")
            }
            Timber.d("PickerIconCache: stored ${png.size}-byte icon for $logoUrl")
        } catch (e: Exception) {
            Timber.w(e, "PickerIconCache: failed to store icon for $logoUrl")
        }
    }

    /**
     * Write via a sibling temp file and rename. The bytes themselves are
     * never partially visible: a write interrupted halfway leaves a stray
     * `.tmp`, not a truncated [target] that [cached] would serve forever
     * (nothing downstream validates the bytes). Replacement is best-effort
     * rather than strictly atomic: on a filesystem that refuses to rename
     * over an existing file, the old one is removed first, and if the retry
     * then fails too the entry is briefly absent - a cache miss, refetched
     * on the next sweep, never a corrupt file.
     */
    private fun writeAtomically(target: File, bytes: ByteArray) {
        val tmp = File(target.parentFile, "${target.name}.tmp")
        tmp.writeBytes(bytes)
        if (tmp.renameTo(target)) return
        val cleared = target.delete() || !target.exists()
        if (cleared && tmp.renameTo(target)) return
        if (!tmp.delete()) Timber.d("PickerIconCache: ${tmp.name} left behind")
        throw IOException("could not move ${tmp.name} into place")
    }

    /** Extend (or start) the backoff for a logo that yielded no icon. Caller holds [mutex]. */
    private fun recordMissLocked(logoUrl: String, backgroundColor: String?) {
        val missFile = missFile(logoUrl, backgroundColor)
        val miss = FetchBackoff.recordMiss(readMissLocked(missFile), nowMillis())
        try {
            dir.mkdirs()
            // Atomic for the same reason as the icon: a half-written marker
            // reads as corrupt, corrupt reads as absent, and absent means
            // `isDue` says yes - the backoff this file exists to enforce
            // would be gone.
            writeAtomically(missFile, json.encodeToString(FetchCacheEntry.serializer(), miss).toByteArray())
        } catch (e: Exception) {
            Timber.w(e, "PickerIconCache: failed to record miss for $logoUrl")
        }
        Timber.d(
            "PickerIconCache: no usable icon from $logoUrl (attempt ${miss.attempts}, " +
                "next in ${(miss.nextRetryAtMillis - nowMillis()) / 1000}s)",
        )
    }

    /** Remove everything - for tests and a "clear caches" affordance. */
    suspend fun clear() = withContext(Dispatchers.IO) {
        mutex.withLock {
            try {
                dir.listFiles()?.forEach { it.delete() }
            } catch (e: Exception) {
                Timber.w(e, "PickerIconCache: failed to clear ${dir.name}")
            }
        }
    }

    private fun readMissLocked(file: File): FetchCacheEntry? = try {
        if (file.isFile) {
            json.decodeFromString(FetchCacheEntry.serializer(), file.readText())
                .takeIf { it.status == FetchCacheStatus.MISS }
        } else {
            null
        }
    } catch (e: Exception) {
        Timber.w(e, "PickerIconCache: corrupt ${file.name}, ignoring")
        null
    }

    private fun pngFile(logoUrl: String, backgroundColor: String?) = File(dir, "${key(logoUrl, backgroundColor)}.png")
    private fun missFile(logoUrl: String, backgroundColor: String?) = File(dir, "${key(logoUrl, backgroundColor)}.miss")

    companion object {
        /** Directory name under `noBackupFilesDir`. */
        const val DIR_NAME = "siros-picker-icons"

        /** Larger than any sane logo; a PNG at this size would still only ever be shown at 64 px. */
        const val MAX_DOWNLOAD_BYTES = 2L * 1024 * 1024

        /** Connect and read timeout for a logo download. */
        const val TIMEOUT_MILLIS = 10_000

        /**
         * Cache key for one (logo URL, background colour) pair: hex SHA-256
         * over both, so no URL character can ever produce an unsafe file
         * name and two colours of the same logo don't collide. The colour is
         * normalised to upper case so `#1a365d` and `#1A365D` share a file.
         */
        fun key(logoUrl: String, backgroundColor: String?): String {
            val colour = (backgroundColor ?: PickerIconRenderer.DEFAULT_BACKGROUND).trim().uppercase()
            val digest = MessageDigest.getInstance("SHA-256")
                .digest("$logoUrl\n$colour".toByteArray(Charsets.UTF_8))
            return digest.joinToString("") { "%02x".format(it) }
        }

        /**
         * GET [url] with [java.net.HttpURLConnection], or decode a `data:`
         * URI inline. Returns null for any other scheme, any non-200, a body
         * over [MAX_DOWNLOAD_BYTES], or an I/O error.
         */
        fun downloadWithUrlConnection(url: String): ByteArray? {
            if (url.startsWith("data:", ignoreCase = true)) return decodeDataUri(url)
            val uri = try {
                URI(url)
            } catch (_: Exception) {
                return null
            }
            if (uri.scheme?.lowercase() !in setOf("http", "https")) return null
            val connection = uri.toURL().openConnection() as HttpURLConnection
            connection.requestMethod = "GET"
            connection.connectTimeout = TIMEOUT_MILLIS
            connection.readTimeout = TIMEOUT_MILLIS
            connection.instanceFollowRedirects = true
            return try {
                if (connection.responseCode != HttpURLConnection.HTTP_OK) {
                    Timber.d("PickerIconCache: HTTP ${connection.responseCode} from $url")
                    return null
                }
                val declared = connection.contentLengthLong
                if (declared > MAX_DOWNLOAD_BYTES) {
                    Timber.d("PickerIconCache: $url declares $declared bytes, over the cap")
                    return null
                }
                connection.inputStream.use { input ->
                    val out = ByteArrayOutputStream()
                    val buffer = ByteArray(16 * 1024)
                    var total = 0L
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) break
                        total += read
                        if (total > MAX_DOWNLOAD_BYTES) {
                            Timber.d("PickerIconCache: $url exceeded the download cap mid-stream")
                            return null
                        }
                        out.write(buffer, 0, read)
                    }
                    out.toByteArray()
                }
            } finally {
                connection.disconnect()
            }
        }

        /** The payload of a `data:[<mediatype>][;base64],<data>` URI, or null if malformed. */
        internal fun decodeDataUri(uri: String): ByteArray? {
            val comma = uri.indexOf(',')
            if (comma < 0) return null
            val header = uri.substring(5, comma)
            val payload = uri.substring(comma + 1)
            return try {
                if (header.endsWith(";base64", ignoreCase = true)) {
                    // Strict decoder over a whitespace-stripped payload: some
                    // issuers wrap long data URIs across lines, but anything
                    // else outside the alphabet is a malformed URI, not noise.
                    java.util.Base64.getDecoder().decode(payload.filterNot { it.isWhitespace() })
                } else {
                    percentDecode(payload)
                }
            } catch (_: Exception) {
                null
            }?.takeIf { it.size <= MAX_DOWNLOAD_BYTES }
        }

        /**
         * RFC 3986 percent-decoding straight to bytes: `%XX` is one byte,
         * everything else is taken literally - including `+`, which
         * `URLDecoder` would turn into a space under its form-encoding rules.
         * Decoding to a `String` and back was the other problem: any byte at
         * or above 0x80 came out mangled by the UTF-8/Latin-1 round trip.
         * Non-ASCII characters, which a well-formed data URI does not carry,
         * contribute their UTF-8 bytes, which is what browsers do with them.
         * Null on a truncated or non-hex escape.
         */
        internal fun percentDecode(payload: String): ByteArray? {
            val input = payload.toByteArray(Charsets.UTF_8)
            val out = ByteArrayOutputStream(input.size)
            var i = 0
            while (i < input.size) {
                val b = input[i].toInt()
                if (b != '%'.code) {
                    out.write(b)
                    i++
                    continue
                }
                if (i + 2 >= input.size) return null
                val hi = Character.digit(input[i + 1].toInt(), 16)
                val lo = Character.digit(input[i + 2].toInt(), 16)
                if (hi < 0 || lo < 0) return null
                out.write((hi shl 4) or lo)
                i += 3
            }
            return out.toByteArray()
        }
    }
}
