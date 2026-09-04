// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.dcapi

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

/** The pure geometry behind [PickerIconRenderer.render]; the Bitmap calls themselves need a device. */
class PickerIconRendererTest {

    @Test
    fun `sample size halves until either dimension would drop below the target`() {
        assertEquals(1, PickerIconRenderer.sampleSizeFor(56, 56, 56))
        assertEquals(1, PickerIconRenderer.sampleSizeFor(100, 100, 56))
        assertEquals(2, PickerIconRenderer.sampleSizeFor(112, 112, 56))
        assertEquals(2, PickerIconRenderer.sampleSizeFor(200, 200, 56))
        assertEquals(64, PickerIconRenderer.sampleSizeFor(4000, 4000, 56))
        // A wide banner: height is the limiting dimension.
        assertEquals(2, PickerIconRenderer.sampleSizeFor(4000, 120, 56))
        // Already smaller than the target: never upsample-by-sampling.
        assertEquals(1, PickerIconRenderer.sampleSizeFor(16, 16, 56))
    }

    @Test
    fun `a square logo fills the inset area exactly`() {
        assertArrayEquals(intArrayOf(4, 4, 60, 60), PickerIconRenderer.fitInside(500, 500, 64, 4))
        assertArrayEquals(intArrayOf(4, 4, 60, 60), PickerIconRenderer.fitInside(10, 10, 64, 4))
    }

    @Test
    fun `a wide logo is letterboxed and centred vertically`() {
        // 2:1 -> 56 x 28, centred: top = (64 - 28) / 2 = 18.
        assertArrayEquals(intArrayOf(4, 18, 60, 46), PickerIconRenderer.fitInside(200, 100, 64, 4))
    }

    @Test
    fun `a tall logo is pillarboxed and centred horizontally`() {
        // 1:2 -> 28 x 56, centred: left = (64 - 28) / 2 = 18.
        assertArrayEquals(intArrayOf(18, 4, 46, 60), PickerIconRenderer.fitInside(100, 200, 64, 4))
    }

    @Test
    fun `degenerate sizes never produce an empty or oversized rectangle`() {
        val extreme = PickerIconRenderer.fitInside(10_000, 1, 64, 4)
        assertEquals(56, extreme[2] - extreme[0])
        assertEquals(1, extreme[3] - extreme[1])
        val noRoom = PickerIconRenderer.fitInside(10, 10, 64, 40)
        assertEquals(1, noRoom[2] - noRoom[0])
        assertEquals(1, noRoom[3] - noRoom[1])
    }
}
