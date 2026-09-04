// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import com.github.luben.zstd.Zstd
import org.siros.sdk.credentials.ZkCircuitDescriptor
import timber.log.Timber
import java.nio.ByteBuffer

/**
 * Decompresses a zstd-compressed zk-circuits catalog artifact
 * (`ZkCircuitClient.downloadArtifact`'s raw, as-served bytes) straight into
 * a direct destination [ByteBuffer] - shared by [VegaProofSystem] and
 * [LongfellowZkProofSystem], whose prover/verifier keys and circuits are
 * both multi-hundred-MB.
 *
 * Sizes the destination to the exact value recorded in the zstd frame's own
 * header (`Zstd.getFrameContentSize`) when present - these artifacts
 * compress at roughly 300-400x, so any fixed multiplier guess is fragile -
 * falling back to [ZkCircuitDescriptor.artifact]'s `uncompressed.size`
 * catalog metadata, and only as a last resort to a generous fixed
 * multiplier.
 *
 * zstd-jni's `Zstd.decompress(ByteBuffer, Int)` requires BOTH its source
 * and destination buffers to already be direct (confirmed via
 * `ZstdDecompressCtx.decompressDirectByteBuffer`'s own
 * `IllegalArgumentException` checks), so [compressedBytes] is first copied
 * into a small direct buffer - cheap, this is the compressed size, a few MB
 * at most - and the native call writes its result straight into a
 * destination buffer of exactly the resolved size. That destination buffer
 * IS the final result: no second, same-size copy. A prior per-class
 * decompress-to-heap-array-then-copy-to-direct-buffer path held two full
 * copies of a circuit key in memory simultaneously at the peak - confirmed
 * to OOM-crash a real device decompressing the ~157MB r11 Vega verifier
 * key.
 */
internal fun decompressZkCircuitArtifact(compressedBytes: ByteArray, descriptor: ZkCircuitDescriptor): ByteBuffer {
    val frameSize = Zstd.getFrameContentSize(compressedBytes)
    val outputSize = if (frameSize > 0) {
        frameSize
    } else {
        val uncompressedSize = descriptor.artifact?.uncompressed?.size
        if (uncompressedSize != null && uncompressedSize > 0) {
            Timber.w("Circuit '${descriptor.id}' zstd frame has no embedded content size; using catalog metadata")
            uncompressedSize
        } else {
            Timber.w("Circuit '${descriptor.id}' has no known uncompressed size; guessing buffer size")
            compressedBytes.size.toLong() * 400
        }
    }
    val directCompressed = ByteBuffer.allocateDirect(compressedBytes.size).put(compressedBytes).apply { flip() }
    return Zstd.decompress(directCompressed, outputSize.toInt())
}
