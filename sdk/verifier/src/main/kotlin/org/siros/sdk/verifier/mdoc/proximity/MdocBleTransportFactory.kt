// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.mdoc.proximity

import android.content.Context
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.concurrent.CancellationException

/**
 * Starts the reader side of every BLE role offered by an [MdocEngagement].
 *
 * The host application, not this transport-neutral verifier module, must request
 * and hold the relevant Bluetooth permissions. On Android 12/API 31+, scanning
 * requires `BLUETOOTH_SCAN`, advertising requires `BLUETOOTH_ADVERTISE`, and both
 * roles require `BLUETOOTH_CONNECT`. On API 28-30, the host needs `BLUETOOTH`,
 * `BLUETOOTH_ADMIN`, and location permission required by BLE scanning. The host is
 * also responsible for manifest declarations and runtime permission prompts.
 */
object MdocBleTransportFactory {
    /**
     * Starts all offered roles immediately. Call [MdocBleTransportElection.await]
     * once to elect a connected transport, then send SessionEstablishment only on
     * the returned transport. No CBOR message is sent by the factory or election.
     */
    fun start(context: Context, engagement: MdocEngagement): MdocBleTransportElection {
        val ble = requireNotNull(engagement.ble) { "The engagement does not offer BLE retrieval" }
        require(ble.supportsPeripheralServerMode || ble.supportsCentralClientMode) {
            "The BLE retrieval method offers neither mdoc BLE role"
        }
        val appContext = context.applicationContext ?: context
        val election = MdocBleTransportElection()
        val candidates = mutableListOf<MdocBleCandidate>()

        if (ble.supportsPeripheralServerMode) {
            val serviceUuid = requireNotNull(ble.peripheralServerModeUuid) {
                "Peripheral-server mode is offered without its engagement UUID"
            }
            candidates += BleGattClientTransport(
                context = appContext,
                serviceUuid = serviceUuid,
                onReady = election::candidateReady,
                onFailure = election::candidateFailed,
            )
        }
        if (ble.supportsCentralClientMode) {
            val serviceUuid = requireNotNull(ble.centralClientModeUuid) {
                "Central-client mode is offered without its engagement UUID"
            }
            candidates += BleGattServerTransport(
                context = appContext,
                serviceUuid = serviceUuid,
                eDeviceKeyBytes = engagement.eDeviceKeyBytes,
                onReady = election::candidateReady,
                onFailure = election::candidateFailed,
            )
        }
        election.start(candidates)
        return election
    }
}

/**
 * One-shot, thread-safe election across the offered BLE roles.
 *
 * The first fully connected and STATE_START-ready candidate wins. Every loser is
 * closed before [await] returns. Repeated [await] calls return that same transport;
 * election itself never sends an establishment, preventing duplicate radio sends.
 * Cancelling a coroutine waiting in [await] closes all candidates. Call [close]
 * when the host ViewModel is cleared if no elected transport remains in use.
 */
class MdocBleTransportElection internal constructor() {
    private val result = CompletableDeferred<MdocMessageTransport>()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO.limitedParallelism(1))
    private val mutex = Mutex()
    private val pending = linkedSetOf<MdocBleCandidate>()
    private val failures = mutableListOf<Pair<String, Throwable>>()

    private var started = false
    private var registrationFinished = false
    private var closed = false
    private var elected: MdocBleCandidate? = null

    /** Suspends until one role is ready, or until every offered role has failed. */
    suspend fun await(): MdocMessageTransport = try {
        result.await()
    } catch (e: CancellationException) {
        withContext(NonCancellable) { close() }
        throw e
    }

    /** Deterministically closes pending candidates and any previously elected transport. */
    suspend fun close() {
        val transports = mutex.withLock {
            if (closed) return
            closed = true
            val all = buildList {
                elected?.let(::add)
                addAll(pending)
            }.distinct()
            pending.clear()
            all
        }
        result.cancel(CancellationException("BLE transport election was closed"))
        closeAll(transports)
        scope.cancel()
    }

    internal fun start(candidates: List<MdocBleCandidate>) {
        check(!started) { "BLE candidates have already been started" }
        require(candidates.isNotEmpty()) { "At least one BLE candidate is required" }
        started = true
        pending += candidates
        scope.launch { finishRegistration() }
        for (candidate in candidates) {
            try {
                candidate.start()
            } catch (e: Exception) {
                candidateFailed(candidate, e)
            }
        }
    }

    internal fun candidateReady(candidate: MdocBleCandidate) {
        scope.launch {
            var won = false
            val toClose = mutableListOf<MdocBleCandidate>()
            mutex.withLock {
                if (closed || elected != null || result.isCompleted || candidate !in pending) {
                    // A late/duplicate ready callback for an already-retired loser
                    // must not close it a second time. If it is still pending, the
                    // terminal state won the race and owns its single cleanup here.
                    if (pending.remove(candidate)) toClose += candidate
                } else {
                    pending.remove(candidate)
                    elected = candidate
                    won = true
                    toClose += pending
                    pending.clear()
                }
            }
            closeAll(toClose)
            if (won) result.complete(candidate)
        }
    }

    internal fun candidateFailed(candidate: MdocBleCandidate, error: Throwable) {
        scope.launch {
            var terminalFailure: MdocBleTransportException? = null
            mutex.withLock {
                if (!closed && elected == null && !result.isCompleted && pending.remove(candidate)) {
                    failures += candidate.role to error
                    if (registrationFinished && pending.isEmpty()) {
                        val detail = failures.joinToString("; ") { (role, cause) ->
                            "$role: ${cause.message ?: cause.javaClass.simpleName}"
                        }
                        terminalFailure = MdocBleTransportException(
                            "No offered BLE role became ready: $detail",
                            failures.last().second,
                        )
                    }
                }
            }
            terminalFailure?.let { result.completeExceptionally(it) }
        }
    }

    private suspend fun finishRegistration() {
        var terminalFailure: MdocBleTransportException? = null
        mutex.withLock {
            registrationFinished = true
            if (!closed && elected == null && pending.isEmpty()) {
                val detail = failures.joinToString("; ") { (role, cause) ->
                    "$role: ${cause.message ?: cause.javaClass.simpleName}"
                }
                terminalFailure = MdocBleTransportException(
                    "No offered BLE role became ready: $detail",
                    failures.lastOrNull()?.second,
                )
            }
        }
        terminalFailure?.let { result.completeExceptionally(it) }
    }

    private suspend fun closeAll(transports: List<MdocBleCandidate>) {
        for (transport in transports.distinct()) {
            try {
                transport.close()
            } catch (_: Exception) {
                // A failed loser must not prevent the winner from being returned.
            }
        }
    }
}
