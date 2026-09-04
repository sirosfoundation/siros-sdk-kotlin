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
            val pngFile = pngFile(logoUrl, backgroundColor)
            val missFile = missFile(logoUrl, backgroundColor)
            if (png != null) {
                try {
                    dir.mkdirs()
                    pngFile.writeBytes(png)
                    missFile.delete()
                    Timber.d("PickerIconCache: stored ${png.size}-byte icon for $logoUrl")
                } catch (e: Exception) {
                    Timber.w(e, "PickerIconCache: failed to store icon for $logoUrl")
                }
            } else {
                val previous = readMissLocked(missFile)
                val miss = FetchBackoff.recordMiss(previous, nowMillis())
                try {
                    dir.mkdirs()
                    missFile.writeText(json.encodeToString(FetchCacheEntry.serializer(), miss))
                } catch (e: Exception) {
                    Timber.w(e, "PickerIconCache: failed to record miss for $logoUrl")
                }
                Timber.d(
                    "PickerIconCache: no usable icon from $logoUrl (attempt ${miss.attempts}, " +
                        "next in ${(miss.nextRetryAtMillis - nowMillis()) / 1000}s)",
                )
            }
        }
        png
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
                    java.net.URLDecoder.decode(payload, "UTF-8").toByteArray(Charsets.ISO_8859_1)
                }
            } catch (_: Exception) {
                null
            }?.takeIf { it.size <= MAX_DOWNLOAD_BYTES }
        }
    }
}
