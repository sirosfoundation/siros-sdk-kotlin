// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.mdoc.proximity

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import java.util.concurrent.CancellationException
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.TimeoutCancellationException

/** A BLE discovery, connection, protocol, disconnect, or I/O failure. */
class MdocBleTransportException internal constructor(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)

internal interface MdocBleCandidate : MdocMessageTransport {
    val role: String
    fun start()
}

/** Radio-independent session logic; Android roles only implement discovery and one-chunk I/O. */
internal abstract class AbstractMdocBleTransport(
    final override val role: String,
    private val onReady: (MdocBleCandidate) -> Unit,
    private val onFailure: (MdocBleCandidate, Throwable) -> Unit,
    private val readyTimeoutMs: Long = READY_TIMEOUT_MS,
    private val ioTimeoutMs: Long = IO_TIMEOUT_MS,
) : MdocBleCandidate {
    protected val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO.limitedParallelism(1))

    private val active = AtomicBoolean(true)
    private val ready = AtomicBoolean(false)
    private val incoming = Channel<ByteArray>(INCOMING_MESSAGE_QUEUE_SIZE)
    private val reassembler = MdocBleReassembler()
    private val sendLock = Mutex()
    private val receiveLock = Mutex()

    @Volatile
    private var terminalError: Throwable? = null

    private var readyTimeoutJob: Job? = null

    protected val isActive: Boolean
        get() = active.get()

    final override fun start() {
        readyTimeoutJob = scope.launch {
            delay(readyTimeoutMs)
            fail(MdocBleTransportException("$role did not become ready within $readyTimeoutMs ms"))
        }
        try {
            startRadio()
        } catch (e: Exception) {
            fail(MdocBleTransportException("$role could not start", e))
        }
    }

    final override suspend fun send(message: ByteArray) {
        ensureActive()
        if (message.size > MdocBleProtocol.MAX_MESSAGE_SIZE) {
            val error = MdocBleTransportException("Outgoing BLE message exceeds ${MdocBleProtocol.MAX_MESSAGE_SIZE} bytes")
            fail(error)
            throw error
        }
        try {
            sendLock.withLock {
                ensureActive()
                withTimeout(ioTimeoutMs) {
                    for (chunk in MdocBleProtocol.chunk(message, currentMaxChunkSize())) {
                        ensureActive()
                        sendChunk(chunk)
                    }
                }
            }
        } catch (e: TimeoutCancellationException) {
            val error = MdocBleTransportException("$role send timed out after $ioTimeoutMs ms", e)
            fail(error)
            throw error
        } catch (e: CancellationException) {
            close()
            throw e
        } catch (e: MdocBleTransportException) {
            fail(e)
            throw e
        } catch (e: Exception) {
            val error = MdocBleTransportException("$role send failed", e)
            fail(error)
            throw error
        }
    }

    final override suspend fun receive(): ByteArray {
        ensureActive()
        try {
            return receiveLock.withLock {
                ensureActive()
                withTimeout(ioTimeoutMs) { incoming.receive() }
            }
        } catch (e: TimeoutCancellationException) {
            val error = MdocBleTransportException("$role receive timed out after $ioTimeoutMs ms", e)
            fail(error)
            throw error
        } catch (e: ClosedReceiveChannelException) {
            throw terminalError ?: MdocBleTransportException("$role is closed", e)
        } catch (e: CancellationException) {
            close()
            throw e
        } catch (e: MdocBleTransportException) {
            throw e
        } catch (e: Exception) {
            throw terminalError ?: MdocBleTransportException("$role receive failed", e)
        }
    }

    final override suspend fun close() {
        if (!active.compareAndSet(true, false)) return
        val error = MdocBleTransportException("$role is closed")
        terminalError = error
        readyTimeoutJob?.cancel()
        incoming.close()
        runCatching { closeRadio() }
        scope.cancel()
    }

    protected fun markReady() {
        if (!isActive || !ready.compareAndSet(false, true)) return
        readyTimeoutJob?.cancel()
        onReady(this)
    }

    protected fun fail(message: String, cause: Throwable? = null) {
        fail(MdocBleTransportException("$role: $message", cause))
    }

    protected fun fail(error: MdocBleTransportException) {
        if (!active.compareAndSet(true, false)) return
        terminalError = error
        readyTimeoutJob?.cancel()
        incoming.close(error)
        runCatching { closeRadio() }
        scope.cancel()
        onFailure(this, error)
    }

    protected fun onIncomingChunk(chunk: ByteArray) {
        if (!isActive) return
        val message = try {
            reassembler.feed(chunk)
        } catch (e: Exception) {
            fail("malformed or oversized BLE message", e)
            return
        }
        if (message != null && incoming.trySend(message).isFailure) {
            fail("incoming whole-message queue is full or closed")
        }
    }

    private fun ensureActive() {
        if (!isActive) throw terminalError ?: MdocBleTransportException("$role is closed")
    }

    protected abstract fun startRadio()

    protected abstract fun closeRadio()

    protected abstract fun currentMaxChunkSize(): Int

    /** Write or notify exactly one framed chunk, waiting for Android's previous-operation callback as necessary. */
    protected abstract suspend fun sendChunk(chunk: ByteArray)

    private companion object {
        const val READY_TIMEOUT_MS = 60_000L
        const val IO_TIMEOUT_MS = 120_000L
        const val INCOMING_MESSAGE_QUEUE_SIZE = 2
    }
}
