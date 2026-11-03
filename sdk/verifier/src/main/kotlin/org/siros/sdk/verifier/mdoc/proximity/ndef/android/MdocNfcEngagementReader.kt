// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.mdoc.proximity.ndef.android

import android.app.Activity
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.siros.sdk.verifier.mdoc.proximity.ndef.MdocNfcHandover
import org.siros.sdk.verifier.mdoc.proximity.ndef.MdocNfcHandoverParser

/**
 * Reads ISO 18013-5 NFC static handover from an NFC Forum Type 4 Tag for a subsequent BLE transport.
 *
 * Reader mode is scoped to one [read] call and uses the supplied foreground Activity. A temporarily
 * paused Activity is retried until the read deadline. Only one read may be
 * outstanding per reader. The discovered ISO-DEP connection is closed on success, failure, timeout,
 * and caller cancellation. Caller cancellation is never converted to [MdocNfcEngagementException.Timeout].
 *
 * This implements static handover only: it neither exchanges SessionData over NFC nor performs negotiated
 * handover. The host application must declare the normal Android NFC permission.
 */
class MdocNfcEngagementReader internal constructor(
    private val nfc: NfcEngagementBackend,
    private val readerModeDispatcher: CoroutineDispatcher,
    private val ioDispatcher: CoroutineDispatcher,
) {
    constructor(activity: Activity) : this(
        AndroidNfcEngagementBackend(activity),
        Dispatchers.Main.immediate,
        Dispatchers.IO,
    )

    private val readInProgress = AtomicBoolean(false)

    /**
     * Waits for one ISO-DEP tag, reads its complete raw NDEF Handover Select message, and validates it with
     * [MdocNfcHandoverParser.parse]. The timeout covers reader-mode startup, tag discovery, and APDU exchanges.
     *
     * @throws MdocNfcEngagementException.NoTag if no tag arrives before the deadline while reader mode is armed.
     * @throws MdocNfcEngagementException.Timeout for other expirations of the overall deadline.
     * @throws kotlinx.coroutines.CancellationException unchanged when the caller's coroutine is cancelled.
     */
    suspend fun read(timeoutMillis: Long = DEFAULT_TIMEOUT_MILLIS): MdocNfcHandover {
        require(timeoutMillis > 0) { "timeoutMillis must be positive" }
        if (!readInProgress.compareAndSet(false, true)) {
            throw MdocNfcEngagementException.ReadInProgress()
        }

        val tags = Channel<NfcEngagementTag>(capacity = 1)
        val activeTag = AtomicReference<NfcEngagementTag?>()
        val tagDiscovered = AtomicBoolean(false)
        val readerModeArmed = AtomicBoolean(false)
        val readerModeWasArmed = AtomicBoolean(false)

        try {
            withContext(readerModeDispatcher) {
                if (!nfc.isAvailable) throw MdocNfcEngagementException.NfcUnavailable()
                if (!nfc.isEnabled) throw MdocNfcEngagementException.NfcDisabled()
            }

            val handover = withTimeoutOrNull(timeoutMillis) {
                armReaderMode(tags, readerModeArmed, readerModeWasArmed)
                val tag = tags.receive()
                tagDiscovered.set(true)
                activeTag.set(tag)

                // One tag is sufficient. Disarm before blocking APDU work so repeated discoveries cannot accumulate.
                disableReaderMode(readerModeArmed)
                withContext(ioDispatcher) { readTag(tag) }
            }

            return handover ?: if (readerModeWasArmed.get() && !tagDiscovered.get()) {
                throw MdocNfcEngagementException.NoTag("No NFC tag discovered within $timeoutMillis ms")
            } else {
                throw MdocNfcEngagementException.Timeout(timeoutMillis)
            }
        } finally {
            tags.close()
            disableReaderMode(readerModeArmed)
            withContext(NonCancellable + ioDispatcher) {
                activeTag.getAndSet(null)?.close()
                while (true) {
                    val unusedTag = tags.tryReceive().getOrNull() ?: break
                    unusedTag.close()
                }
            }
            readInProgress.set(false)
        }
    }

    private suspend fun armReaderMode(
        tags: Channel<NfcEngagementTag>,
        readerModeArmed: AtomicBoolean,
        readerModeWasArmed: AtomicBoolean,
    ) {
        while (true) {
            try {
                withContext(readerModeDispatcher) {
                    nfc.enableReaderMode { tag ->
                        if (tags.trySend(tag).isFailure) tag.close()
                    }
                    // Set these in the same main-thread block as enableReaderMode. If cancellation is
                    // delivered when withContext returns, finally still knows that disable is required.
                    readerModeArmed.set(true)
                    readerModeWasArmed.set(true)
                }
                return
            } catch (e: IllegalStateException) {
                // Android rejects enableReaderMode unless the Activity is RESUMED. Dialog transitions are
                // commonly brief, so wait for a later lifecycle state inside the caller's overall deadline.
                delay(READER_MODE_RETRY_MILLIS)
            }
        }
    }

    private suspend fun disableReaderMode(readerModeArmed: AtomicBoolean) {
        if (!readerModeArmed.compareAndSet(true, false)) return
        withContext(NonCancellable + readerModeDispatcher) {
            nfc.disableReaderMode()
        }
    }

    private fun readTag(tag: NfcEngagementTag): MdocNfcHandover {
        val rawNdef = try {
            tag.connect(ISO_DEP_TIMEOUT_MILLIS)
            NdefType4Protocol.readNdef(tag.maxReadChunkBytes, tag::transceive)
        } catch (e: CancellationException) {
            throw e
        } catch (e: MdocNfcEngagementException) {
            throw e
        } catch (e: Exception) {
            throw MdocNfcEngagementException.ApduFailure(
                "ISO-DEP connection",
                "Could not connect to the NFC Type 4 Tag",
                e,
            )
        }
        return MdocNfcHandoverParser.parse(rawNdef)
    }

    companion object {
        const val DEFAULT_TIMEOUT_MILLIS: Long = 30_000L
        private const val ISO_DEP_TIMEOUT_MILLIS = 10_000
        private const val READER_MODE_RETRY_MILLIS = 100L
    }
}

/** Internal Android seam: JVM tests exercise reader scoping without making hardware claims. */
internal interface NfcEngagementBackend {
    val isAvailable: Boolean
    val isEnabled: Boolean

    fun enableReaderMode(onTag: (NfcEngagementTag) -> Unit)
    fun disableReaderMode()
}

internal interface NfcEngagementTag {
    val maxReadChunkBytes: Int

    fun connect(timeoutMillis: Int)
    fun transceive(command: ByteArray): ByteArray
    fun close()
}

private class AndroidNfcEngagementBackend(
    private val activity: Activity,
) : NfcEngagementBackend {
    private val adapter: NfcAdapter?
        get() = NfcAdapter.getDefaultAdapter(activity)

    override val isAvailable: Boolean
        get() = adapter != null

    override val isEnabled: Boolean
        get() = adapter?.isEnabled == true

    override fun enableReaderMode(onTag: (NfcEngagementTag) -> Unit) {
        val nfc = adapter ?: throw MdocNfcEngagementException.NfcUnavailable()
        if (!nfc.isEnabled) throw MdocNfcEngagementException.NfcDisabled()
        nfc.enableReaderMode(
            activity,
            { tag: Tag -> onTag(AndroidIsoDepTag(tag)) },
            NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
            null,
        )
    }

    override fun disableReaderMode() {
        try {
            adapter?.disableReaderMode(activity)
        } catch (_: IllegalStateException) {
            // A paused/destroyed Activity has already lost reader mode; there is nothing left to disarm.
        }
    }
}

private class AndroidIsoDepTag(private val tag: Tag) : NfcEngagementTag {
    private val lock = Any()
    private var isoDep: IsoDep? = null
    private var closed = false

    override val maxReadChunkBytes: Int
        get() {
            val maxTransceive = synchronized(lock) {
                if (closed) throw IOException("ISO-DEP tag is closed")
                isoDep?.maxTransceiveLength ?: throw IOException("ISO-DEP tag is not connected")
            }
            if (maxTransceive <= 2) throw IOException("ISO-DEP maximum transceive length is too small")
            return (maxTransceive - 2).coerceAtMost(NdefType4Protocol.MAX_READ_CHUNK_BYTES)
        }

    override fun connect(timeoutMillis: Int) {
        val tech = IsoDep.get(tag)
            ?: throw MdocNfcEngagementException.NoTag("The discovered NFC tag does not support ISO-DEP")
        synchronized(lock) {
            if (closed) {
                runCatching { tech.close() }
                throw IOException("ISO-DEP tag is closed")
            }
            // Publish before setting the timeout or connecting so close always reaches the real object.
            isoDep = tech
        }
        try {
            tech.timeout = timeoutMillis
            if (!tech.isConnected) tech.connect()
        } catch (e: Exception) {
            close()
            throw e
        }
    }

    override fun transceive(command: ByteArray): ByteArray {
        val tech = synchronized(lock) {
            if (closed) throw IOException("ISO-DEP tag is closed")
            isoDep ?: throw IOException("ISO-DEP tag is not connected")
        }
        return tech.transceive(command)
    }

    override fun close() {
        val tech = synchronized(lock) {
            if (closed) return
            closed = true
            isoDep.also { isoDep = null }
        }
        runCatching { tech?.close() }
    }
}
