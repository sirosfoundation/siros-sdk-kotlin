// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import com.github.luben.zstd.Zstd
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.siros.sdk.credentials.DefaultZkPseudonymDeriver
import org.siros.sdk.credentials.VerifierIdentity
import org.siros.sdk.credentials.ZkCircuitClient
import org.siros.sdk.credentials.ZkCircuitDescriptor
import org.siros.sdk.credentials.ZkProofResult
import org.siros.sdk.credentials.ZkProofSystem
import org.siros.sdk.credentials.ZkPseudonymDeriver
import org.siros.sdk.credentials.ZkSystemSpec
import org.siros.sdk.credentials.PseudonymOutcome
import org.siros.sdk.credentials.mdoc.MdocCbor
import timber.log.Timber
import uniffi.zk_cred_longfellow.CircuitVersion
import uniffi.zk_cred_longfellow.MdocZkProver
import uniffi.zk_cred_longfellow.initializeProver
import uniffi.zk_cred_longfellow.prove
import uniffi.zk_cred_longfellow.proveWithPpid
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.time.Instant

/**
 * [ZkProofSystem] implementation wrapping the `zk-cred-longfellow` native
 * crate (V8 circuit + PPID support - see
 * `~/.claude/plans/silver-drifting-heron.md` for the full design/provenance
 * history). Fetches circuits on demand from [zkCircuitClient] (Phase 1),
 * caches initialized [MdocZkProver] instances per (circuit id, attribute
 * count) since circuit loading is expensive, and derives pseudonyms via
 * [pseudonymDeriver] (defaults to the real spec-faithful formula).
 *
 * **How the witness DeviceResponse is built** (confirmed 2026-08-14 via
 * `wallet-frontend`'s `feat/longfellow-zk` reference implementation
 * (`MdocProverService.ts`) and the crate's own `parse_device_response`):
 * the native prover needs a REAL, fully-signed DeviceResponse - the ZK proof
 * proves knowledge of a valid device signature, it doesn't replace the
 * signing mechanism. This is built locally via [MdocDeviceResponseBuilder]
 * (the exact same builder every non-ZK presentation already uses) with
 * `disclosedClaims = null` (full disclosure) since these bytes are a
 * private witness never transmitted to the verifier - the circuit itself
 * selects which claims [ZkProofSystem.generateProof]'s `requestedClaims`
 * actually reveals in the proof.
 */
class LongfellowZkProofSystem(
    private val zkCircuitClient: ZkCircuitClient,
    private val pseudonymDeriver: ZkPseudonymDeriver = DefaultZkPseudonymDeriver,
) : ZkProofSystem {

    companion object {
        /**
         * Included in `requestedClaims` (and thus asserted/disclosed by the
         * proof) whenever a pseudonym is requested - confirmed via the
         * `feat/longfellow-zk` reference implementation, which always lists
         * it alongside real disclosed claims (e.g. `["age_over_18",
         * "pairwise_pseudonym"]`), not as a separate side-channel-only
         * concept the circuit is unaware of.
         */
        const val PSEUDONYM_CLAIM = "pairwise_pseudonym"
    }

    override val systemId: String = "longfellow-libzk-v1"

    override val supportedDocTypes: Set<String> = setOf(
        "org.iso.18013.5.1.mDL",
        "eu.europa.ec.eudi.pid.1",
    )

    /**
     * Cache key: (circuit id, attribute count) - a circuit is compiled for a
     * FIXED number of attributes (e.g. `..._8_2_...` proves exactly 2), so
     * two requests against the same circuit id but different claim counts
     * are genuinely different prover instances, not a cache hit.
     */
    private val proverCache = mutableMapOf<Pair<String, Int>, MdocZkProver>()
    private val cacheMutex = Mutex()

    /**
     * Matches any requested spec declaring `system == "longfellow"` -
     * mirrors [org.siros.sdk.wallet.WscdSelectionPolicy]'s "nominal
     * capability" convention (a static declaration, not a live probe):
     * whether the specific circuit [ZkSystemSpec.id] names is actually
     * fetchable is only verified lazily, in [generateProof] - `matchingSpec`
     * itself can't do network I/O (it's a plain, synchronous function, used
     * during request-vs-capability matching before any proof generation is
     * committed to).
     */
    override fun matchingSpec(requestedSpecs: List<ZkSystemSpec>): ZkSystemSpec? =
        requestedSpecs.firstOrNull { it.system == "longfellow" }

    override suspend fun generateProof(
        spec: ZkSystemSpec,
        credentialBytes: ByteArray,
        sessionTranscript: ByteArray,
        requestedClaims: List<String>,
        verifierIdentity: VerifierIdentity?,
        signer: suspend (ByteArray) -> ByteArray,
        priorState: ByteArray?,
    ): ZkProofResult {
        val effectiveClaims = if (verifierIdentity != null && PSEUDONYM_CLAIM !in requestedClaims) {
            requestedClaims + PSEUDONYM_CLAIM
        } else {
            requestedClaims
        }

        val document = MdocCbor.parseStoredCredential(credentialBytes)
        val namespace = document.issuerSigned.nameSpaces.keys.firstOrNull()
            ?: error("mdoc credential '${document.docType}' has no disclosed namespaces")

        val prover = getOrInitProver(spec, effectiveClaims.size)

        // Private witness only - see this class's doc comment for why this
        // must be a REAL, fully-signed DeviceResponse, and why it's built
        // with full disclosure rather than pre-filtered to requestedClaims.
        // buildForProximity is transport-agnostic despite its name: it just
        // takes a pre-computed session transcript directly, which is exactly
        // what's needed here regardless of which real transport the caller
        // is presenting over.
        val witnessDeviceResponse = MdocDeviceResponseBuilder(credentialBytes)
            .buildForProximity(sessionTranscript, disclosedClaims = null, signer = signer)

        val time = Instant.now().toString()

        if (verifierIdentity == null) {
            val proofBytes = prove(
                prover = prover,
                deviceResponse = ByteBuffer.wrap(witnessDeviceResponse),
                namespace = namespace,
                requestedClaims = effectiveClaims,
                sessionTranscript = ByteBuffer.wrap(sessionTranscript),
                time = time,
            )
            return ZkProofResult(proofBytes = proofBytes)
        }

        val verifierContext = pseudonymDeriver.deriveVerifierContext(verifierIdentity)
        val proofBytes = proveWithPpid(
            prover = prover,
            deviceResponse = ByteBuffer.wrap(witnessDeviceResponse),
            namespace = namespace,
            requestedClaims = effectiveClaims,
            sessionTranscript = ByteBuffer.wrap(sessionTranscript),
            time = time,
            verifierContext = ByteBuffer.wrap(verifierContext),
        )

        // The native API returns only proof bytes - the pseudonym itself
        // (SHA256(pseudonym_seed || verifier_context), the same formula the
        // circuit itself asserts) is computed locally so the caller can
        // display/track it, mirroring the feat/longfellow-zk reference's own
        // separate computePPID() step.
        val seedItem = document.issuerSigned.nameSpaces[namespace]
            ?.firstOrNull { it.item.elementIdentifier == PSEUDONYM_CLAIM }
        val pseudonym = seedItem?.let { sha256(it.item.elementValue.GetByteString() + verifierContext) }

        return ZkProofResult(
            proofBytes = proofBytes,
            pseudonym = pseudonym,
            pseudonymOutcome = if (pseudonym != null) PseudonymOutcome.PROVIDED else PseudonymOutcome.NOT_SUPPORTED_BY_SYSTEM,
        )
    }

    private suspend fun getOrInitProver(spec: ZkSystemSpec, numAttributes: Int): MdocZkProver {
        val cacheKey = spec.id to numAttributes
        cacheMutex.withLock {
            proverCache[cacheKey]?.let { return it }
        }

        val descriptor = zkCircuitClient.fetchCircuit(spec.id)
            ?: error("Longfellow circuit '${spec.id}' not found in any configured zk-circuits source")
        val compressedBytes = zkCircuitClient.downloadArtifact(descriptor)
        val circuitBytes = decompress(compressedBytes, descriptor)
        val circuitVersion = circuitVersionOf(descriptor)

        val prover = initializeProver(
            circuit = ByteBuffer.wrap(circuitBytes),
            circuitVersion = circuitVersion,
            numAttributes = numAttributes.toUByte(),
        )

        cacheMutex.withLock {
            // Another concurrent call may have raced us - keep whichever
            // instance won, don't leak the loser (a loaded circuit is
            // multi-hundred-MB).
            val existing = proverCache[cacheKey]
            if (existing != null) return existing
            proverCache[cacheKey] = prover
            return prover
        }
    }

    /**
     * Decompresses [compressedBytes] to the exact size recorded in
     * [ZkCircuitDescriptor.artifact]'s `uncompressed.size` when known (zstd
     * needs the output buffer size up front for a single-pass decompress);
     * falls back to a generous fixed size if that metadata is missing.
     */
    private fun decompress(compressedBytes: ByteArray, descriptor: ZkCircuitDescriptor): ByteArray {
        val uncompressedSize = descriptor.artifact?.uncompressed?.size
        val outputSize = if (uncompressedSize != null && uncompressedSize > 0) {
            uncompressedSize
        } else {
            Timber.w("Circuit '${descriptor.id}' artifact has no uncompressed size recorded; guessing buffer size")
            compressedBytes.size.toLong() * 20
        }
        return Zstd.decompress(compressedBytes, outputSize.toInt())
    }

    private fun circuitVersionOf(descriptor: ZkCircuitDescriptor): CircuitVersion =
        when (descriptor.systemVersion) {
            "6" -> CircuitVersion.V6
            "7" -> CircuitVersion.V7
            "8" -> CircuitVersion.V8
            else -> error("Longfellow circuit '${descriptor.id}' has unsupported systemVersion '${descriptor.systemVersion}'")
        }

    private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
}
