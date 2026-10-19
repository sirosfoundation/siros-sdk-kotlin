// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import java.nio.ByteBuffer
import java.time.Clock
import kotlinx.serialization.json.JsonObject
import org.siros.sdk.credentials.CircuitZkCircuit
import org.siros.sdk.credentials.CircuitZkPlan
import org.siros.sdk.credentials.ZkCircuitClient
import org.siros.sdk.credentials.ZkCircuitDescriptor
import timber.log.Timber

/**
 * The proving ABI of the `nymauth-*` circuits, as the circuit authors define it (`SPEC.md` of their
 * `nym-auth-circuits` archive: §3 and §L3-L6 for Longfellow, §V3-V5 for Vega): one narrow call that takes
 * the verified circuit bytes and the already-assembled inputs and returns the proof and the pseudonym.
 *
 * This is the seam where native code is needed and none is shipped yet: the vendored `zk_cred_longfellow`
 * and `zk_cred_vega` bindings expose the generic mdoc/age circuits only, with no entry point that builds the
 * nymauth witnesses (Longfellow's hash-circuit semantic bits and signature-circuit ECDSA trace, Vega's table
 * and core witness) or runs the two-circuit / multi-circuit proof. The circuit authors' reference
 * implementations (`longfellow/reference`, `vega/reference`) are Rust. Until a binding implements this
 * interface the [NymAuthCircuitZkAdapter] refuses every request; it never substitutes another proof.
 *
 * An implementation must not log or retain any argument: [NymAuthProveRequest.secretSeed] is the issuer-delivered
 * seed and the circuit input is private.
 */
fun interface NymAuthNativeProver {
    /** Proves [request]; any failure is an exception, which [CatalogCircuitZkProver] turns into a refusal. */
    suspend fun prove(request: NymAuthProveRequest): NymAuthProveResponse
}

/**
 * What [NymAuthNativeProver.prove] receives. Everything here is derived by the SDK from the stored
 * credential, the verifier's request and the device signer; the native side does not parse the request.
 *
 * @property system The catalog `system` of the circuit: [NymAuthCircuitZkAdapter.LONGFELLOW_SYSTEM] or
 *   [NymAuthCircuitZkAdapter.VEGA_SYSTEM].
 * @property circuitParams The catalog descriptor's `params` (Longfellow: `block_enc_hash`, `block_enc_sig`,
 *   `hash_circuit_id`, `sig_circuit_id`), verbatim.
 * @property circuit The decompressed circuit artifact, its hash verified against the catalog (Longfellow:
 *   the two LFC2 circuits, signature then hash; Vega: the bincode `(STEP, CORE)` shapes, from which the native
 *   side derives its keys). Read-only; do not retain it past the call.
 * @property issuerSigned The credential's `IssuerSigned` structure as CBOR.
 * @property secretSeed The 16-byte issuer-delivered `secret_seed`, already checked against `ssc`.
 * @property issuerKeyX Big-endian x of the issuer key Q (the `x5chain` leaf), 32 bytes.
 * @property time `T`: `YYYY-MM-DDThh:mm:ssZ`, 20 ASCII characters.
 * @property earliest `E`: `YYYY-MM-DD`, `0000-00-00` for no lower bound.
 * @property cutoff `C`: `YYYY-MM-DD`, `9999-12-31` for no upper bound.
 * @property challengeDigest `e2`: SHA-256 of the COSE `Signature1` message the device key signed.
 * @property deviceSignature The device key's ES256 signature on that message, `r || s`, 64 bytes.
 * @property verifierInput `SHA-256(verifier_id)`, 32 bytes.
 * @property transcriptSeed The SessionTranscript the proof is bound to (Longfellow's Fiat-Shamir seed).
 */
class NymAuthProveRequest(
    val system: String,
    val circuitId: String,
    val circuitParams: JsonObject,
    val circuit: ByteBuffer,
    val issuerSigned: ByteArray,
    val secretSeed: ByteArray,
    val issuerKeyX: ByteArray,
    val issuerKeyY: ByteArray,
    val time: String,
    val earliest: String,
    val cutoff: String,
    val challengeDigest: ByteArray,
    val deviceSignature: ByteArray,
    val verifierInput: ByteArray,
    val transcriptSeed: ByteArray,
) {
    override fun toString() = "NymAuthProveRequest(redacted)"
}

/** What [NymAuthNativeProver.prove] returns: the proof bytes as the circuit's own verifier reads them, and the pseudonym it reports. */
class NymAuthProveResponse(val proof: ByteArray, val pseudonym: ByteArray) {
    override fun toString() = "NymAuthProveResponse(redacted)"
}


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

    /** Whether some adapter can produce a proof; false means every request is refused. */
    val canProve: Boolean get() = registry.canProve

    /** Drops every adapter's resident prover memory. */
    fun releaseProvers() {
        registry.release()
    }

    override fun admits(circuit: CircuitZkCircuit, plan: CircuitZkPlan): Boolean = registry.admits(circuit, plan)

    override suspend fun prove(input: CircuitZkProveInput): CircuitZkProveOutput {
        val circuit = input.circuit
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
        ): CatalogCircuitZkProver = CatalogCircuitZkProver(
            circuitClient,
            CircuitZkSystemRegistry(
                listOf(
                    NymAuthCircuitZkAdapter(circuitClient, native, presentation.proverResidency ?: ZkProverResidency(), clock),
                    LegacyZkCircuitZkAdapter(presentation),
                ),
            ),
        )
    }
}
