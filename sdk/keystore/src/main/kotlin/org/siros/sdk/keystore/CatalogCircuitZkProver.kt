// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import java.nio.ByteBuffer
import java.time.Clock
import org.siros.sdk.credentials.CircuitZkCircuit
import org.siros.sdk.credentials.CircuitZkPlan
import org.siros.sdk.credentials.ZkCircuitClient
import org.siros.sdk.credentials.ZkCircuitDescriptor
import timber.log.Timber

/**
 * The real [CircuitZkProver]: proves a `circuit_zk` request with the circuit of the go-zk-circuits catalog it
 * names, through the [CircuitZkSystemAdapter] registered for that circuit's (system, systemVersion).
 *
 * The dispatcher itself only does what is common to every system, refusing (an [CircuitZkError.AccessDenied],
 * never a fallback to the fake prover, never a default adapter) at the first thing that fails:
 * 1. the catalog descriptor is fetched and must be the circuit the presenter chose, published, `active` and
 *    not deprecated;
 * 2. its (system, systemVersion) must be claimed by an adapter in [registry]: an unknown system, or a known
 *    one at a version nobody has vetted, is refused;
 * 3. the adapter proves; see [NymAuthCircuitZkAdapter] (the `nymauth-*` circuits, behind the native seam) and
 *    [LegacyZkCircuitZkAdapter] (Longfellow and Vega-mc, through the shared proof systems).
 *
 * [admits] lets the presenter choose among circuits only those an adapter can serve for the plan.
 */
class CatalogCircuitZkProver(
    private val circuitClient: ZkCircuitClient,
    private val registry: CircuitZkSystemRegistry,
) : CircuitZkProver {

    private var registeredHandlers: List<CircuitZkFunctionHandler>? = null

    /** The registered profiles, used by the wallet for function/witness/consent handling. */
    constructor(
        circuitClient: ZkCircuitClient,
        registry: CircuitZkSystemRegistry,
        profiles: List<CircuitZkProfile>,
    ) : this(circuitClient, registry) {
        registeredHandlers = CircuitZkProfile.handlers(profiles)
    }

    /** The handlers of the registered profiles, or the built-in set for a manually assembled registry. */
    val handlers: List<CircuitZkFunctionHandler>
        get() = registeredHandlers ?: DEFAULT_CIRCUIT_ZK_HANDLERS

    /** The nymauth adapter alone, with [native] as its seam; the legacy systems are not reachable. */
    constructor(
        circuitClient: ZkCircuitClient,
        native: NymAuthNativeProver?,
        residency: ZkProverResidency = ZkProverResidency(),
        clock: Clock = Clock.systemUTC(),
        decompress: (ByteArray, ZkCircuitDescriptor) -> ByteBuffer = ::decompressZkCircuitArtifact,
    ) : this(
        circuitClient,
        CircuitZkSystemRegistry(listOf(NymAuthCircuitZkAdapter(circuitClient, native, residency, clock, decompress))),
    )

    /**
     * The circuits of a catalog manifest as this prover can serve them: legacy entries that declare no
     * functions get the ones their adapter claims (everything else is offered for no plan).
     */
    fun circuitsOf(manifest: org.siros.sdk.credentials.ZkManifest): List<CircuitZkCircuit> =
        org.siros.sdk.credentials.CircuitZkCircuitSource.fromManifest(manifest, registry::declaredFunctions)

    /** What a catalog-backed circuit table should declare for [descriptor]: the functions its adapter claims it for (null: none). */
    fun declaredFunctions(descriptor: ZkCircuitDescriptor): Set<String>? = registry.declaredFunctions(descriptor)

    /** Whether some adapter can produce a proof; false means every request is refused. */
    val canProve: Boolean get() = registry.canProve

    /** A catalog refresh retired [descriptor]'s circuit: drop what is resident for it (see [ZkCircuitCatalogRefresher]). */
    suspend fun onCircuitRetired(descriptor: ZkCircuitDescriptor) {
        registry.retire(descriptor)
    }

    /** Drops every adapter's resident prover memory. */
    fun releaseProvers() {
        registry.release()
    }

    override fun admits(circuit: CircuitZkCircuit, plan: CircuitZkPlan): Boolean = registry.admits(circuit, plan)

    override suspend fun prove(input: CircuitZkProveInput): CircuitZkProveOutput {
        try {
            return proveInternal(input)
        } catch (e: CircuitZkError) {
            throw e
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Throwable) {
            // Throwable, not Exception: an OutOfMemoryError from a hostile artifact or an UnsatisfiedLinkError from a
            // missing native library is a refusal, not a crash of the host.
            Timber.w("circuit_zk: proving failed (${e.javaClass.simpleName}); refusing")
            throw CircuitZkError.AccessDenied(CircuitZkStep.PROVE)
        }
    }

    private suspend fun proveInternal(input: CircuitZkProveInput): CircuitZkProveOutput {
        val circuit = input.circuit
        // NOTE: the proof time is the wallet's clock and is not bounded here; the verifier enforces the tolerance it
        // accepts on proof_time. A wallet-side sanity window (or a trusted time source) is deferred.
        val descriptor = circuitClient.fetchCircuit(circuit.circuitId) ?: run {
            Timber.w("circuit_zk: no catalog descriptor for the chosen circuit; refusing")
            throw CircuitZkError.AccessDenied(CircuitZkStep.PROVE)
        }
        val current = descriptor.id == circuit.circuitId && descriptor.system == circuit.system &&
            (circuit.systemVersion == null || circuit.systemVersion == descriptor.systemVersion) &&
            descriptor.published && descriptor.deprecatedAt == null && descriptor.status == "active"
        val adapter = if (current) registry.adapterFor(descriptor.system, descriptor.systemVersion) else null
        if (adapter == null) {
            Timber.w("circuit_zk: no adapter for the chosen circuit's system or it is not an active circuit; refusing")
            throw CircuitZkError.AccessDenied(CircuitZkStep.PROVE)
        }
        return adapter.prove(descriptor, input)
    }

    companion object {
        /**
         * The standard registry: the nymauth circuits behind [native] and the legacy Longfellow and Vega-mc
         * circuits through [presentation], all sharing [presentation]'s residency when it has one.
         */
        fun standard(
            circuitClient: ZkCircuitClient,
            presentation: ZkMdocPresentation,
            native: NymAuthNativeProver? = null,
            clock: Clock = Clock.systemUTC(),
        ): CatalogCircuitZkProver = standard(circuitClient, presentation, native, clock, emptyList())

        /**
         * The standard registry plus additional credential/circuit [profiles]. The built-in nym_auth
         * and legacy Longfellow/Vega adapters stay registered; a duplicate catalog key or function id
         * is rejected instead of replacing either one.
         */
        fun standard(
            circuitClient: ZkCircuitClient,
            presentation: ZkMdocPresentation,
            native: NymAuthNativeProver? = null,
            clock: Clock = Clock.systemUTC(),
            profiles: List<CircuitZkProfile>,
            predicates: org.siros.sdk.credentials.PredicateFunctions = org.siros.sdk.credentials.PredicateFunctions.DEFAULT,
        ): CatalogCircuitZkProver {
            val registered = standardProfiles(circuitClient, presentation, native, clock, profiles, predicates)
            CircuitZkProfile.handlers(registered) // Validate shared function ids at construction too.
            return CatalogCircuitZkProver(
                circuitClient,
                CircuitZkSystemRegistry(registered.map { it.adapter }),
                registered,
            )
        }

        /**
         * The built-in profile registrations plus [additional]. nym_auth is the first profile, not a
         * separate code path; the legacy mdoc profile and caller-supplied profiles use the same shape.
         */
        fun standardProfiles(
            circuitClient: ZkCircuitClient,
            presentation: ZkMdocPresentation,
            native: NymAuthNativeProver? = null,
            clock: Clock = Clock.systemUTC(),
            additional: List<CircuitZkProfile>,
            predicates: org.siros.sdk.credentials.PredicateFunctions = org.siros.sdk.credentials.PredicateFunctions.DEFAULT,
        ): List<CircuitZkProfile> = listOf(
            NymAuthCircuitZkAdapter.profile(circuitClient, native, presentation.proverResidency ?: ZkProverResidency(), clock, predicates = predicates),
            LegacyZkCircuitZkAdapter.profile(presentation),
        ) + additional
    }
}
