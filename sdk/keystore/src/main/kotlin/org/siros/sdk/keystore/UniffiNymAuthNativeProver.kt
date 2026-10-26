// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import timber.log.Timber

/**
 * One native implementation of a nymauth proof system, as [UniffiNymAuthNativeProver] drives it: build the resident
 * state of a circuit once, then prove with it. The SDK ships [ZkCredVegaNymAuthBinding] (zk-cred-vega) and
 * [ZkCredLongfellowNymAuthBinding] (zk-cred-longfellow); a host plugs in another implementation of the same system (the
 * same circuits, the same [NymAuthProveRequest]) by passing its own binding to [UniffiNymAuthNativeProver].
 *
 * The contract every binding keeps: it proves exactly the circuit the request names and refuses one it does not
 * support ([NymAuthNativeErrorKind.UNSUPPORTED_CIRCUIT]); it checks that its own derivation of `e2` from
 * `transcriptSeed` equals `challengeDigest`; it zeroes its copies of `secretSeed`; and every failure is a
 * [NymAuthNativeException] that carries nothing the native side said (no digest, rule or value).
 */
interface NymAuthBinding {
    /** The catalog `system` this binding proves (for example [NymAuthCircuitZkAdapter.LONGFELLOW_SYSTEM]). */
    val system: String

    /**
     * Which implementation this is, for logs, diagnostics and benchmark records (for example `zk-cred-longfellow`).
     * Not sent to verifiers: a proof states its circuit, not the code that made it.
     */
    val implementation: String

    /**
     * Builds the resident state of the circuit [request] names from its verified, decompressed bytes
     * (`request.circuit`): Vega runs key setup from the shapes (about a second, 100+ MB), Longfellow loads the two
     * circuits. Throws a [NymAuthNativeException] for the binding's own errors. The handle is closed to release it.
     */
    fun load(request: NymAuthProveRequest): AutoCloseable

    /** Proves with a [handle] this binding built. Throws a [NymAuthNativeException] for the binding's own errors. */
    fun prove(handle: AutoCloseable, request: NymAuthProveRequest): NymAuthProveResponse
}

/**
 * The real [NymAuthNativeProver]: dispatches by catalog `system` to the [NymAuthBinding] the host chose for it (by
 * default [DEFAULT_BINDINGS]: zk-cred-vega for `vega-nymauth`, zk-cred-longfellow for `longfellow-nymauth`), keeps
 * ONE built circuit resident (keyed by system, circuit id and artifact hash, so a changed artifact is never proved
 * with a stale state), and drops it on [release] (memory pressure) or when its circuit is retired. A different
 * circuit evicts the resident one first: the process holds one native prover at a time. The binding's errors are
 * already [NymAuthNativeException]s (the adapter maps each deliberately); a system no binding is registered for is
 * an unsupported circuit. Proving runs off the caller's dispatcher.
 */
class UniffiNymAuthNativeProver(
    private val bindings: List<NymAuthBinding>,
) : ResidentNymAuthNativeProver {

    init {
        require(bindings.isNotEmpty()) { "A nymauth prover needs at least one binding" }
        val twice = bindings.groupBy { it.system }.filterValues { it.size > 1 }.keys
        require(twice.isEmpty()) { "More than one binding for $twice: a system has exactly one implementation" }
    }

    /** The standard prover: [DEFAULT_BINDINGS]. */
    constructor() : this(DEFAULT_BINDINGS)

    /** The systems this prover serves. */
    val systems: Set<String> get() = bindings.mapTo(LinkedHashSet()) { it.system }

    /** The implementation serving [system] ([NymAuthBinding.implementation]), or null when none does. */
    fun implementationFor(system: String): String? = bindings.firstOrNull { it.system == system }?.implementation

    private class Resident(val key: String, val circuitId: String, val binding: NymAuthBinding, val handle: AutoCloseable)

    private val mutex = Mutex()
    private var resident: Resident? = null
    @Volatile private var releaseWhenIdle = false

    /** The key of the resident circuit, or null. For diagnostics and tests. */
    val residentKey: String? get() = resident?.key

    override suspend fun prove(request: NymAuthProveRequest): NymAuthProveResponse {
        val binding = bindings.firstOrNull { it.system == request.system }
            ?: throw NymAuthNativeException(NymAuthNativeErrorKind.UNSUPPORTED_CIRCUIT)
        val key = "${request.system}:${request.circuitId}:${request.artifactHash}"
        return mutex.withLock {
            releaseWhenIdle = false
            try {
                withContext(Dispatchers.Default) {
                    val current = resident
                    val handle = if (current != null && current.key == key) {
                        current.handle
                    } else {
                        if (current != null) {
                            Timber.i("Releasing resident nymauth circuit '${current.key}' to load '$key'")
                            close(current)
                            resident = null
                        }
                        Timber.i("Loading nymauth circuit '$key' with ${binding.implementation}")
                        binding.load(request).also { resident = Resident(key, request.circuitId, binding, it) }
                    }
                    binding.prove(handle, request)
                }
            } finally {
                if (releaseWhenIdle) {
                    releaseWhenIdle = false
                    resident?.let { close(it) }
                    resident = null
                }
            }
        }
    }

    override fun release() {
        if (mutex.tryLock()) {
            try {
                resident?.let { close(it) }
                resident = null
            } finally {
                mutex.unlock()
            }
        } else {
            // A proof is running: it finishes first, and the release happens when it ends.
            releaseWhenIdle = true
        }
    }

    override fun releaseCircuit(circuitId: String) {
        if (mutex.tryLock()) {
            try {
                resident?.takeIf { it.circuitId == circuitId }?.let {
                    close(it)
                    resident = null
                }
            } finally {
                mutex.unlock()
            }
        } else if (resident?.circuitId == circuitId) {
            releaseWhenIdle = true
        }
    }

    private fun close(r: Resident) {
        try {
            r.handle.close()
        } catch (e: Exception) {
            Timber.w("Closing the resident nymauth circuit failed (${e.javaClass.simpleName})")
        }
    }

    companion object {
        /** The SDK's own implementations: zk-cred-vega for `vega-nymauth`, zk-cred-longfellow for `longfellow-nymauth`. */
        val DEFAULT_BINDINGS: List<NymAuthBinding> get() = listOf(ZkCredVegaNymAuthBinding, ZkCredLongfellowNymAuthBinding)

        /**
         * [DEFAULT_BINDINGS] with each of [replacements] taking over its system (a system no default serves is added): the
         * usual way to swap one implementation and keep the others.
         */
        fun withBindings(vararg replacements: NymAuthBinding): UniffiNymAuthNativeProver {
            val chosen = LinkedHashMap<String, NymAuthBinding>()
            DEFAULT_BINDINGS.forEach { chosen[it.system] = it }
            val twice = replacements.groupBy { it.system }.filterValues { it.size > 1 }.keys
            require(twice.isEmpty()) { "More than one replacement for $twice" }
            replacements.forEach { chosen[it.system] = it }
            return UniffiNymAuthNativeProver(chosen.values.toList())
        }
    }
}
