// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.dcapi

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Rect
import java.io.ByteArrayOutputStream
import timber.log.Timber

/**
 * Turns an issuer logo into the fixed-size PNG the OS credential picker
 * shows next to an entry.
 *
 * The picker's contract, learned on hardware rather than from
 * documentation: an entry with a null or empty icon is silently dropped,
 * and a 64x64 PNG is known to render. So the output here is always exactly
 * [ICON_SIZE] square and always a PNG, whatever the input was - and callers
 * fall back to a solid colour square when this returns null, never to
 * nothing.
 *
 * ### What it does with the image
 *
 * Decodes with `inJustDecodeBounds` first and picks an `inSampleSize` so
 * that a multi-megapixel logo (they exist) is never fully decoded into
 * memory. The logo is then scaled to fit inside the icon with a small inset,
 * preserving aspect ratio, and drawn centred over the credential's own
 * background colour - the same colour the flat card uses, so the picker
 * entry and the wallet card read as the same thing.
 *
 * ### What it refuses
 *
 * Anything [BitmapFactory] can't decode. That includes SVG, which is what a
 * good fraction of issuer logos are: rendering SVG needs a parser this SDK
 * deliberately doesn't depend on (the sample app uses Coil's decoder; the
 * SDK stays dependency-light). Such logos get the colour-square placeholder
 * and are recorded as a negative-cache entry by [PickerIconCache] so they
 * aren't refetched on every registration. Supporting them is a known
 * follow-up.
 *
 * The pure geometry ([sampleSizeFor], [fitInside]) is separate from the
 * Bitmap calls so it can be unit-tested on the JVM, where `android.graphics`
 * is stubs.
 */
object PickerIconRenderer {

    /** Icon edge length, in pixels. The size known to work in the picker. */
    const val ICON_SIZE = 64

    /**
     * Pixels of background left around the logo on each side. Logos drawn
     * edge-to-edge in a 64 px tile look cramped next to the picker's own
     * text; a 4 px margin is enough to read as "a logo on a card".
     */
    const val INSET = 4

    /** The card colour used when the credential declares none - matches the flat placeholder. */
    const val DEFAULT_BACKGROUND = "#1A365D"

    /**
     * Composite [imageBytes] onto a [backgroundColor] tile.
     *
     * @return PNG bytes, or null if [imageBytes] isn't a decodable raster
     *         image (SVG, HTML error page, truncated download, ...).
     */
    fun render(imageBytes: ByteArray, backgroundColor: String?): ByteArray? {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(imageBytes, 0, imageBytes.size, bounds)
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) {
            Timber.d("PickerIconRenderer: not a decodable raster image (${imageBytes.size} bytes)")
            return null
        }
        val opts = BitmapFactory.Options().apply {
            inSampleSize = sampleSizeFor(bounds.outWidth, bounds.outHeight, ICON_SIZE - 2 * INSET)
            inPreferredConfig = Bitmap.Config.ARGB_8888
        }
        val source = BitmapFactory.decodeByteArray(imageBytes, 0, imageBytes.size, opts) ?: run {
            Timber.d("PickerIconRenderer: bounds decoded but full decode failed")
            return null
        }
        try {
            return onTile(backgroundColor) { canvas ->
                val dst = fitInside(source.width, source.height, ICON_SIZE, INSET)
                canvas.drawBitmap(
                    source,
                    null,
                    Rect(dst[0], dst[1], dst[2], dst[3]),
                    Paint(Paint.FILTER_BITMAP_FLAG or Paint.ANTI_ALIAS_FLAG),
                )
            }
        } finally {
            source.recycle()
        }
    }

    /** A solid [backgroundColor] tile - the floor every picker entry gets when no logo is usable. */
    fun placeholder(backgroundColor: String?): ByteArray = onTile(backgroundColor) {}

    /**
     * A [backgroundColor]-filled [ICON_SIZE] tile with [draw] applied, as PNG
     * bytes. The bitmap is recycled before returning: pixel buffers are native
     * memory, and this runs once per credential per registration, so leaving
     * them to the GC would let an icon sweep pile them up.
     */
    private inline fun onTile(backgroundColor: String?, draw: (Canvas) -> Unit): ByteArray {
        val tile = Bitmap.createBitmap(ICON_SIZE, ICON_SIZE, Bitmap.Config.ARGB_8888)
        try {
            val canvas = Canvas(tile)
            canvas.drawColor(parseColor(backgroundColor))
            draw(canvas)
            return ByteArrayOutputStream().use { out ->
                tile.compress(Bitmap.CompressFormat.PNG, 100, out)
                out.toByteArray()
            }
        } finally {
            tile.recycle()
        }
    }

    /** [DEFAULT_BACKGROUND] for anything `Color.parseColor` rejects, so a bad VCTM colour can't throw here. */
    private fun parseColor(color: String?): Int = try {
        Color.parseColor(color ?: DEFAULT_BACKGROUND)
    } catch (_: Exception) {
        Color.parseColor(DEFAULT_BACKGROUND)
    }

    /**
     * The largest power-of-two `inSampleSize` that still leaves both decoded
     * dimensions at or above [target] - the standard Android downsampling
     * recipe. Decoding a 4000x4000 logo at full size for a 56 px tile would
     * be 64 MB of ARGB; at sample size 64 it is under 16 KB.
     */
    fun sampleSizeFor(width: Int, height: Int, target: Int): Int {
        var sample = 1
        while (width / (sample * 2) >= target && height / (sample * 2) >= target) {
            sample *= 2
        }
        return sample
    }

    /**
     * Destination rectangle `[left, top, right, bottom]` that fits a
     * [srcWidth]x[srcHeight] image inside a [size]-square tile with [inset]
     * on every side, preserving aspect ratio and centring. Never larger than
     * the source's aspect allows, never smaller than 1 px in either
     * direction.
     */
    fun fitInside(srcWidth: Int, srcHeight: Int, size: Int, inset: Int): IntArray {
        val inner = (size - 2 * inset).coerceAtLeast(1)
        val scale = minOf(inner.toDouble() / srcWidth, inner.toDouble() / srcHeight)
        val w = (srcWidth * scale).toInt().coerceIn(1, inner)
        val h = (srcHeight * scale).toInt().coerceIn(1, inner)
        val left = (size - w) / 2
        val top = (size - h) / 2
        return intArrayOf(left, top, left + w, top + h)
    }
}
