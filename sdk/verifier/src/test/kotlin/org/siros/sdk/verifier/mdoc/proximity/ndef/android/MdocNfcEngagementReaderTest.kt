// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.mdoc.proximity.ndef.android

import java.io.IOException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.verifier.mdoc.proximity.ndef.MdocNfcHandoverParseException

@OptIn(ExperimentalCoroutinesApi::class)
class MdocNfcEngagementReaderTest {

    @Test
    fun successfulRead_usesParserAndClosesTagAndReaderMode() = runTest {
        val tag = FakeType4Tag(hex(OFFICIAL_D33_HANDOVER_SELECT))
        val backend = FakeBackend(immediateTag = tag)
        val reader = reader(backend)

        val handover = reader.read()

        assertArrayEquals(hex(OFFICIAL_D33_HANDOVER_SELECT), handover.handoverSelectBytes)
        assertEquals(1, backend.enableAttempts)
        assertEquals(1, backend.disableCount)
        assertEquals(1, tag.closeCount)
    }

    @Test
    fun unavailableAndDisabledNfc_haveDistinctTypedFailures() = runTest {
        val unavailable = runCatching { reader(FakeBackend(available = false)).read() }.exceptionOrNull()
        val disabled = runCatching { reader(FakeBackend(enabled = false)).read() }.exceptionOrNull()

        assertTrue(unavailable is MdocNfcEngagementException.NfcUnavailable)
        assertTrue(disabled is MdocNfcEngagementException.NfcDisabled)
    }

    @Test
    fun noTagDeadline_disarmsReaderMode() = runTest {
        val backend = FakeBackend()

        val failure = runCatching { reader(backend).read(timeoutMillis = 1_000) }.exceptionOrNull()

        assertTrue(failure is MdocNfcEngagementException.NoTag)
        assertEquals(1, backend.enableAttempts)
        assertEquals(1, backend.disableCount)
    }

    @Test
    fun callerCancellation_remainsCancellationAndDisarmsReaderMode() = runTest {
        val backend = FakeBackend()
        val read = async { reader(backend).read() }
        runCurrent()
        assertEquals(1, backend.enableAttempts)

        read.cancel()
        val failure = runCatching { read.await() }.exceptionOrNull()

        assertTrue(failure is CancellationException)
        assertTrue(failure !is MdocNfcEngagementException)
        assertEquals(1, backend.disableCount)
    }

    @Test
    fun oneOutstandingRead_isEnforced() = runTest {
        val backend = FakeBackend()
        val reader = reader(backend)
        val first = async { reader.read() }
        runCurrent()

        val failure = runCatching { reader.read() }.exceptionOrNull()
        assertTrue(failure is MdocNfcEngagementException.ReadInProgress)
        assertEquals(1, backend.enableAttempts)

        first.cancel()
        runCatching { first.await() }
        val timeout = runCatching { reader.read(timeoutMillis = 10) }.exceptionOrNull()
        assertTrue(timeout is MdocNfcEngagementException.NoTag)
    }

    @Test
    fun temporarilyRefusedReaderMode_isRetriedUntilActivityResumes() = runTest {
        val tag = FakeType4Tag(hex(OFFICIAL_D33_HANDOVER_SELECT))
        val backend = FakeBackend(immediateTag = tag, enableRefusals = 2)

        val handover = reader(backend).read()

        assertArrayEquals(hex(OFFICIAL_D33_HANDOVER_SELECT), handover.handoverSelectBytes)
        assertEquals(3, backend.enableAttempts)
        assertEquals(1, backend.disableCount)
        assertEquals(1, tag.closeCount)
    }

    @Test
    fun apduAndParseFailures_stillCloseTag() = runTest {
        val failedTag = FakeType4Tag(ByteArray(0)).apply { failTransceive = true }
        val failedBackend = FakeBackend(immediateTag = failedTag)
        val apduFailure = runCatching { reader(failedBackend).read() }.exceptionOrNull()
        assertTrue(apduFailure is MdocNfcEngagementException.ApduFailure)
        assertEquals(1, failedTag.closeCount)
        assertEquals(1, failedBackend.disableCount)

        val invalidTag = FakeType4Tag(ByteArray(0))
        val invalidBackend = FakeBackend(immediateTag = invalidTag)
        val parseFailure = runCatching { reader(invalidBackend).read() }.exceptionOrNull()
        assertTrue(parseFailure is MdocNfcHandoverParseException)
        assertEquals(1, invalidTag.closeCount)
        assertEquals(1, invalidBackend.disableCount)
    }

    private fun reader(backend: FakeBackend) = MdocNfcEngagementReader(
        backend,
        Dispatchers.Unconfined,
        Dispatchers.Unconfined,
    )

    private class FakeBackend(
        var available: Boolean = true,
        var enabled: Boolean = true,
        private val immediateTag: NfcEngagementTag? = null,
        private val enableRefusals: Int = 0,
    ) : NfcEngagementBackend {
        override val isAvailable: Boolean get() = available
        override val isEnabled: Boolean get() = enabled

        var enableAttempts = 0
        var disableCount = 0
        private var callback: ((NfcEngagementTag) -> Unit)? = null

        override fun enableReaderMode(onTag: (NfcEngagementTag) -> Unit) {
            enableAttempts++
            if (enableAttempts <= enableRefusals) throw IllegalStateException("Activity is not resumed")
            callback = onTag
            immediateTag?.let(onTag)
        }

        override fun disableReaderMode() {
            disableCount++
            callback = null
        }
    }

    private class FakeType4Tag(private val ndef: ByteArray) : NfcEngagementTag {
        override val maxReadChunkBytes: Int = NdefType4Protocol.MAX_READ_CHUNK_BYTES
        var closeCount = 0
        var failTransceive = false

        override fun connect(timeoutMillis: Int) = Unit

        override fun transceive(command: ByteArray): ByteArray {
            if (failTransceive) throw IOException("tag lost")
            return when (command[1].toInt() and 0xFF) {
                0xA4 -> SUCCESS
                0xB0 -> {
                    val offset = ((command[2].toInt() and 0xFF) shl 8) or (command[3].toInt() and 0xFF)
                    val length = command[4].toInt() and 0xFF
                    val data = if (offset == 0) {
                        byteArrayOf((ndef.size ushr 8).toByte(), ndef.size.toByte())
                    } else {
                        ndef.copyOfRange(offset - 2, offset - 2 + length)
                    }
                    data + SUCCESS
                }
                else -> error("Unexpected command")
            }
        }

        override fun close() {
            closeCount++
        }
    }

    private companion object {
        val SUCCESS = hex("9000")
        const val OFFICIAL_D33_HANDOVER_SELECT =
            "91020f487315d10209616301013001046d646f631a200c016170706c69636174696f6e2f766e642e626c7565746f6f7468" +
                "2e6c652e6f6f6230081b28128b37282801021c015c1e580469736f2e6f72673a31383031333a646576696365656e676167" +
                "656d656e746d646f63a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968f" +
                "f289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67"

        fun hex(value: String): ByteArray {
            require(value.length % 2 == 0)
            return ByteArray(value.length / 2) {
                value.substring(it * 2, it * 2 + 2).toInt(16).toByte()
            }
        }
    }
}
