// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.siros.sdk.credentials.PseudonymOutcome
import org.siros.sdk.credentials.VerifierIdentity
import org.siros.sdk.credentials.ZkCircuitClient
import org.siros.sdk.credentials.ZkProofResult
import org.siros.sdk.credentials.ZkProofSystem
import org.siros.sdk.credentials.ZkSystemSpec
import org.siros.sdk.credentials.mdoc.MdocCbor
import uniffi.zk_cred_vega.FfiClaim
import uniffi.zk_cred_vega.FfiEcdsaWitness
import uniffi.zk_cred_vega.FfiMsoBodyWitness
import uniffi.zk_cred_vega.VegaProverKey
import uniffi.zk_cred_vega.prepProve
import uniffi.zk_cred_vega.prove
import java.nio.ByteBuffer

/**
 * [ZkProofSystem] implementation wrapping the `zk-cred-vega` native crate -
 * see `~/.claude/plans/zk-cred-vega-sdk-handoff.md` for the full
 * design/provenance history and current crate status.
 *
 * **Do not wire this into production** (i.e. into whatever constructs the
 * real [org.siros.sdk.credentials.ZkProofSystemRegistry] a wallet actually
 * uses) yet. Per that handoff doc's own explicit gating, three things need
 * to happen first: (a) the crate's `sha256_var` gadget needs an independent
 * security review (novel, soundness-critical circuit code, unreviewed as of
 * this writing); (b) the digestID-binding and ECDSA range-check findings
 * need triage; (c) `zk-cred-vega` needs at least a real version tag/release
 * to depend on (right now it's a private, unreleased repo - this class's own
 * Gradle dependency only resolves from a local `mavenLocal()` publish, which
 * is why it isn't committed to this SDK's own `main` branch). This class
 * exists to let the SDK-side interface work be sketched/tested in parallel,
 * per that doc's own explicit suggestion, not to ship a Vega-backed
 * presentation to a real relying party.
 *
 * **[buildWitness] is deliberately unimplemented** - see its own doc comment.
 * Everything else here (the `prep_prove`/`prove` FFI wiring, fold-and-reuse
 * state threading, pseudonym handling) is real and mirrors
 * [LongfellowZkProofSystem]'s own shape.
 */
class VegaProofSystem(
    private val zkCircuitClient: ZkCircuitClient,
) : ZkProofSystem {

    companion object {
        /**
         * The circuit's fixed claim-slot count (`MAX_CLAIMS_V1` in the Rust
         * crate) - VEGA's v1 circuit is compiled for exactly this many claim
         * slots, unlike Longfellow's own per-attribute-count circuit
         * variants. A request for more claims than this can't be satisfied
         * by this system at all.
         */
        const val MAX_CLAIMS_V1 = 4
    }

    override val systemId: String = "vega-mc-p256-v1"

    /**
     * VEGA's v1 circuit only handles one docType/namespace pair (see the
     * handoff doc's "Known scope limits" section) - unlike
     * [LongfellowZkProofSystem], which already supports two.
     */
    override val supportedDocTypes: Set<String> = setOf("org.iso.18013.5.1.mDL")

    /** Cache key: circuit/spec id - a single prover key handle is reusable across presentations. */
    private val proverKeyCache = mutableMapOf<String, VegaProverKey>()
    private val cacheMutex = Mutex()

    /**
     * Matches any requested spec declaring `system == systemId` for a proof
     * over AT MOST [MAX_CLAIMS_V1] claims - unlike Longfellow's exact-match
     * requirement (a circuit compiled per attribute count), VEGA's circuit
     * is fixed-shape at [MAX_CLAIMS_V1] slots regardless of how many claims
     * a given presentation actually discloses (unused slots are filled from
     * the credential's own other elements, not left blank - see
     * [buildWitness]'s doc comment for why that's still an open question).
     */
    override fun matchingSpec(requestedSpecs: List<ZkSystemSpec>, numAttributes: Int): ZkSystemSpec? {
        if (numAttributes > MAX_CLAIMS_V1) return null
        return requestedSpecs.firstOrNull { it.system == systemId }
    }

    override suspend fun generateProof(
        spec: ZkSystemSpec,
        credentialBytes: ByteArray,
        sessionTranscript: ByteArray,
        requestedClaims: List<String>,
        verifierIdentity: VerifierIdentity?,
        signer: suspend (ByteArray) -> ByteArray,
        priorState: ByteArray?,
    ): ZkProofResult {
        val document = MdocCbor.parseStoredCredential(credentialBytes)
        val proverKey = getOrInitProverKey(spec)
        val (claims, ecdsaWitness, msoBody) = buildWitness(document, requestedClaims)

        // Fold-and-reuse: prep_prove only runs once per credential, ever -
        // every subsequent presentation reuses the previous prove() call's
        // own nextState instead. See ZkProofResult.nextState's doc comment.
        val state = priorState ?: prepProve(proverKey, claims, ecdsaWitness, msoBody)
        val result = prove(proverKey, claims, ecdsaWitness, msoBody, state)

        return ZkProofResult(
            proofBytes = result.proofBytes,
            nextState = result.nextState,
            // VEGA has no pseudonym-derivation concept at all (confirmed in
            // the handoff doc's own design research) - always report this,
            // regardless of whether verifierIdentity was supplied, rather
            // than silently dropping a pseudonym request.
            pseudonymOutcome = PseudonymOutcome.NOT_SUPPORTED_BY_SYSTEM,
        )
    }

    /**
     * Builds this presentation's witness data from a real, stored mdoc
     * credential - **deliberately unimplemented**. Three genuinely open
     * questions need real answers (not guesses) before this can be written
     * correctly, none of which this class should paper over:
     *
     * 1. **ECDSA witness extraction**: `FfiEcdsaWitness.r`/`s` come from
     *    `issuerAuth`'s COSE_Sign1 signature bytes (first/second half), but
     *    `sInv` (the modular inverse of `s` mod the P-256 curve order `n`)
     *    needs a real `BigInteger.modInverse` computation this class
     *    doesn't have yet - get this wrong and proofs fail to verify with
     *    no clear error (same class of mistake `zk-cred-vega`'s own
     *    ecdsa.rs module doc warns about for the *circuit* side of this same
     *    computation). `qx`/`qy` (the issuer's public key) come from
     *    `issuerAuth`'s x5chain - see [org.siros.sdk.wallet.SirosWallet]'s
     *    own VICAL/RICAL work for the established x5chain-extraction
     *    pattern this should reuse, not reinvent.
     * 2. **MSO body witness extraction**: `FfiMsoBodyWitness` needs the
     *    MSO's `deviceKeyInfo.deviceKey.{x,y}` and
     *    `validityInfo.{signed,validFrom,validUntil}` (each a 20-byte ASCII
     *    RFC 3339 timestamp, `mso::TIMESTAMP_LEN`) - [MdocCbor] deliberately
     *    doesn't parse the MSO at all today (see its own file doc: "not MSO
     *    digest verification... those live in the issuer/verifier"), since
     *    no wallet-side use case needed it before this one.
     * 3. **Fixed-slot-count claim selection**: the circuit has EXACTLY
     *    [MAX_CLAIMS_V1] claim slots, each checked against the MSO's real
     *    `valueDigests` (i.e. every slot must be a genuine credential
     *    element, not padding) - what happens when a credential has fewer
     *    than [MAX_CLAIMS_V1] elements in its disclosed namespace, or more
     *    than [MAX_CLAIMS_V1] and the caller wants to disclose a subset
     *    that doesn't fill all the remaining slots from the *same*
     *    elements every time (which would affect [ZkProofResult.nextState]
     *    reuse across presentations disclosing different claim subsets),
     *    is genuinely unresolved in the handoff doc and needs a real answer
     *    before this can be written, not a guess baked into this SDK.
     *
     * @throws NotImplementedError always - see this function's doc comment.
     */
    @Suppress("UNUSED_PARAMETER")
    private fun buildWitness(
        document: org.siros.sdk.credentials.mdoc.DocumentMdoc,
        requestedClaims: List<String>,
    ): Triple<List<FfiClaim>, FfiEcdsaWitness, FfiMsoBodyWitness> {
        throw NotImplementedError(
            "VegaProofSystem.buildWitness: real witness extraction from a live mdoc credential " +
                "is not implemented yet - see this function's doc comment for the three open " +
                "questions that need resolving first (ECDSA witness extraction, MSO body parsing, " +
                "fixed-slot-count claim selection policy).",
        )
    }

    private suspend fun getOrInitProverKey(spec: ZkSystemSpec): VegaProverKey {
        cacheMutex.withLock {
            proverKeyCache[spec.id]?.let { return it }
        }

        val descriptor = zkCircuitClient.fetchCircuit(spec.id)
            ?: error(
                "Vega prover key '${spec.id}' not found in any configured zk-circuits source - " +
                    "expected until the vega-mc catalog entries are published (see handoff doc " +
                    "'What's NOT ready yet' #2)",
            )
        val keyBytes = zkCircuitClient.downloadArtifact(descriptor)
        val proverKey = uniffi.zk_cred_vega.deserializeProverKey(directByteBuffer(keyBytes))

        cacheMutex.withLock {
            val existing = proverKeyCache[spec.id]
            if (existing != null) return existing
            proverKeyCache[spec.id] = proverKey
            return proverKey
        }
    }

    /**
     * The vendored UniFFI bindings' `&[u8]` parameters need a DIRECT
     * `ByteBuffer` - same requirement as [LongfellowZkProofSystem]'s own
     * `directByteBuffer` (see its doc comment for why).
     */
    private fun directByteBuffer(bytes: ByteArray): ByteBuffer =
        ByteBuffer.allocateDirect(bytes.size).put(bytes).apply { flip() }
}
