// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import kotlinx.coroutines.sync.Mutex
import timber.log.Timber

/**
 * At most one loaded prover in the process at a time, released when the
 * host says so.
 *
 * A decompressed Longfellow circuit is ~110 MB and a Vega prover key
 * ~140-160 MB, held as native memory outside the Java heap. Each proof
 * system used to keep every prover it had ever loaded in a map for the life
 * of the process, so two proof systems and two attribute counts could pin
 * half a gigabyte - and a 157 MB key has already caused one out-of-memory
 * crash on a real device, in a process that also hosts a WebView. This
 * replaces those maps: one slot, keyed by whatever the proof system needs to
 * tell provers apart, reloaded on a miss and destroyed on a switch.
 *
 * [release] is for the host to call when the app leaves the foreground
 * (`onTrimMemory(TRIM_MEMORY_UI_HIDDEN)` on Android, which is what
 * `SirosWallet` wires up); a proof in progress finishes first and the
 * release happens when it ends.
 *
 * One residency is shared by every proof system in a
 * [ZkMdocPresentation], so the bound really is one prover, not one per
 * system. Proving is serialized on it as a consequence: two concurrent
 * proofs would otherwise each need a resident prover, and a wallet never
 * has two presentations in flight at once anyway.
 */
class ZkProverResidency {

    private class Resident(val key: String, val prover: AutoCloseable)

    private val mutex = Mutex()

    /**
     * Guards the retirement protocol: the decision of [release]/[releaseCircuit] (idle now, or deferred) and the end-of-use cleanup of
     * [use] (including the unlock of [mutex]) happen under it, so a request registered while a use is in flight is always seen by that
     * use's cleanup, and a request that finds the residency idle destroys the prover itself. Never held across a suspension.
     */
    private val stateLock = Any()

    @Volatile private var resident: Resident? = null
    @Volatile private var releaseWhenIdle = false

    /** The key being loaded by a [use] that has the mutex but has not yet stored its [Resident]; null when none. */
    @Volatile private var loadingKey: String? = null

    /** Test hook: runs inside the retirement decision, after a deferral was decided and before it is recorded. */
    @Volatile internal var onRetirementDeferred: (() -> Unit)? = null

    /** The key of the prover currently loaded, or null. For diagnostics and tests. */
    val residentKey: String? get() = resident?.key

    /**
     * Runs [block] with the prover for [key], loading it with [load] if it is
     * not the one resident (and destroying whatever was). Holds the residency
     * for the duration, so [load] and [block] never overlap with another
     * caller's.
     */
    suspend fun <T : AutoCloseable, R> use(key: String, load: suspend () -> T, block: suspend (T) -> R): R {
        mutex.lock()
        try {
            // A release requested between a previous proof's end and this
            // call is moot: the host is proving again, so the resident
            // prover is wanted, not memory to be reclaimed.
            synchronized(stateLock) { releaseWhenIdle = false }
            val current = resident
            val prover: T = if (current != null && current.key == key) {
                @Suppress("UNCHECKED_CAST")
                current.prover as T
            } else {
                if (current != null) {
                    Timber.i("Releasing resident ZK prover '${current.key}' to load '$key'")
                    destroyQuietly(current)
                    synchronized(stateLock) { resident = null }
                }
                // A retirement arriving while this loads must not be lost: it sees [loadingKey] and defers to the end of the use.
                synchronized(stateLock) { loadingKey = key }
                val loaded = try {
                    load()
                } catch (t: Throwable) {
                    synchronized(stateLock) { loadingKey = null }
                    throw t
                }
                synchronized(stateLock) {
                    resident = Resident(key, loaded)
                    loadingKey = null
                }
                loaded
            }
            return block(prover)
        } finally {
            // The cleanup and the unlock are one step under [stateLock]: a retirement that found the mutex held registered its
            // request under the same lock, so it is either seen here or happens after the unlock and finds the residency idle.
            synchronized(stateLock) {
                if (releaseWhenIdle) {
                    releaseWhenIdle = false
                    resident?.let { destroyQuietly(it) }
                    resident = null
                }
                mutex.unlock()
            }
        }
    }

    /**
     * Destroys the resident prover, or arranges for that as soon as the proof
     * using it completes. Safe to call at any time, from any thread; a no-op
     * with nothing resident.
     */
    fun release() {
        // Never blocks on a proof: this is called from lifecycle callbacks on the main thread while a proof may be holding the
        // mutex for seconds. Under [stateLock] (held only briefly): acquiring the mutex means nothing is using the prover and it
        // can go now; failing to means a proof is running, and its cleanup applies the deferred release under the same lock.
        synchronized(stateLock) {
            if (mutex.tryLock()) {
                try {
                    resident?.let {
                        Timber.i("Releasing resident ZK prover '${it.key}'")
                        destroyQuietly(it)
                    }
                    resident = null
                } finally {
                    mutex.unlock()
                }
            } else {
                releaseWhenIdle = true
            }
        }
    }

    /**
     * Drops the resident prover if it belongs to the circuit [circuitId] (a retired one): the key holds the circuit
     * id as a run of whole `:`-separated segments (`longfellow-libzk-v1:<id>:<n>`, `vega-mc-p256-v1:<id>`,
     * `<system>:<id>:<hash>`), and the id itself may contain colons (`urn:circuits:longfellow:nym_auth:v1`), so the id is
     * looked for as a whole run, not as one segment. Like [release]: at once when idle, else when the proof using it ends,
     * which includes a prover that is still loading.
     */
    fun releaseCircuit(circuitId: String) {
        synchronized(stateLock) {
            if (mutex.tryLock()) {
                try {
                    resident?.takeIf { keyHasCircuit(it.key, circuitId) }?.let {
                        Timber.i("Releasing resident ZK prover '${it.key}': its circuit was retired")
                        destroyQuietly(it)
                        resident = null
                    }
                } finally {
                    mutex.unlock()
                }
            } else if (loadingKey?.let { keyHasCircuit(it, circuitId) } == true || resident?.key?.let { keyHasCircuit(it, circuitId) } == true) {
                onRetirementDeferred?.invoke()
                releaseWhenIdle = true
            }
        }
    }

    /** Whether [circuitId] occurs in [key] as a whole run of `:`-separated segments (never as a part of one). */
    private fun keyHasCircuit(key: String, circuitId: String): Boolean = ":$key:".contains(":$circuitId:")

    private fun destroyQuietly(r: Resident) {
        try {
            r.prover.close()
        } catch (e: Exception) {
            Timber.w(e, "Destroying resident ZK prover '${r.key}' threw")
        }
    }
}
