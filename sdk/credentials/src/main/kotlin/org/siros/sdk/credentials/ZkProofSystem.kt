// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import java.security.MessageDigest

/**
 * A verifier's request for one ZK proof system, mirroring multipaz's own
 * `ZkSystemSpec`/`ZkSystemRepository` design: a generic id/system/params bag
 * rather than a fixed typed shape, so each proof system (Longfellow today,
 * Vega/BBS later) defines its own matching semantics without forcing every
 * implementation to understand every other system's parameters.
 *
 * [id] and [system] mirror `ZkCircuitDescriptor.id`/`.system` (this SDK's own
 * circuit catalog, see [ZkCircuitClient]) closely enough that a
 * [ZkProofSystem.matchingSpec] implementation can usually resolve a request
 * straight to a catalog entry, but this type is wire-shaped (what a verifier
 * asked for), not catalog-shaped (what we have available) - the two only
 * coincide when the requested system is one we actually support.
 */
data class ZkSystemSpec(
    val id: String,
    val system: String,
    val params: Map<String, String> = emptyMap(),
) {
    fun getParam(key: String): String? = params[key]
}

/**
 * Identifies who a pseudonym is being bound to, and any secondary
 * verifier-supplied binding context - the two inputs to the real wire-format
 * pseudonym derivation (see [ZkPseudonymDeriver]). Named for its role at the
 * SDK boundary (verifier's presentation request); doubles as the "pseudonym
 * requested at all" signal in [ZkProofSystem.generateProof] (a `null` value
 * there means no pseudonym was requested).
 *
 * @param clientId the verifier's OpenID4VP `client_id` (e.g.
 *   `x509_san_dns:verifier.example.com`) - fed into `verifier_id`'s
 *   derivation.
 * @param ppidContext the DCQL credential query's `meta.ppid_context` string,
 *   if the verifier supplied one - a second, independent binding value a
 *   verifier can use to further scope pseudonyms (e.g. per-session, not just
 *   per-verifier). `null` when absent, which is a normal, common case.
 */
data class VerifierIdentity(
    val clientId: String,
    val ppidContext: String? = null,
)

/**
 * Whether a proof system honored a pseudonym request. Not every ZK system
 * has a pseudonym concept (Vega, researched 2026-08-14, has none at all) - a
 * system that can't produce one must say so explicitly rather than silently
 * dropping the request or fabricating a value that isn't actually bound to
 * anything.
 */
enum class PseudonymOutcome { PROVIDED, NOT_SUPPORTED_BY_SYSTEM }

/**
 * The result of [ZkProofSystem.generateProof].
 *
 * @param proofBytes the opaque proof, in whatever encoding the issuing
 *   system uses - never interpreted outside that system's own verifier.
 * @param nextState updated [ZkProofSystem.generateProof] `priorState` to
 *   feed the next call for this same credential+system, for systems that
 *   support a rerandomizable-witness reuse path (e.g. Vega's `prep_prove`
 *   cache - see plan §2.4.1 item 3). `null` for systems (Longfellow today)
 *   that don't have or need this.
 * @param pseudonym the derived pseudonym bytes, present only when
 *   [pseudonymOutcome] is [PseudonymOutcome.PROVIDED].
 * @param publicValues whatever output values this system's verify-equivalent
 *   asserts (not assumed to be a fixed "success/claims" shape - some systems,
 *   e.g. Vega, recompute and return public values rather than taking
 *   expected ones as input).
 */
data class ZkProofResult(
    val proofBytes: ByteArray,
    val nextState: ByteArray? = null,
    val pseudonym: ByteArray? = null,
    val pseudonymOutcome: PseudonymOutcome = PseudonymOutcome.NOT_SUPPORTED_BY_SYSTEM,
    val publicValues: Map<String, Any> = emptyMap(),
)

/**
 * One pluggable zero-knowledge proof system, backing a specific credential
 * presentation mode (selective disclosure + optional pseudonym, today;
 * whatever a future BBS/Vega implementation supports). Mirrors this org's
 * existing WSCD plugin framework (`siros-wscd-manager`'s plugin
 * architecture, `WscdSelectionPolicy`) - same shape of problem (multiple
 * interchangeable backends behind one wallet-facing API, selected per
 * declared capability), same organization already has the pattern working
 * end-to-end.
 *
 * Each new proof system is a new implementation of this interface plus its
 * own Rust/native crate - never a change to wallet-facing code. See
 * `~/.claude/plans/silver-drifting-heron.md` §3 for the full design
 * rationale (including why `priorState`/`nextState` and the pseudonym
 * outcome exist - both are Vega-driven additions, backward-compatible
 * no-ops for Longfellow's own implementation).
 */
interface ZkProofSystem {
    /** This system's identifier, e.g. `"longfellow-libzk-v1_8_2_4307_2945"`. */
    val systemId: String

    /** mdoc doctypes this system can generate a ZK proof over, e.g. `{"org.iso.18013.5.1.mDL"}`. */
    val supportedDocTypes: Set<String>

    /**
     * Returns whichever of [requestedSpecs] (a verifier's own list, in
     * priority order) this system can satisfy, or `null` if none match -
     * the extension point [ZkProofSystemRegistry] uses to resolve "does any
     * registered system satisfy this verifier's ZK request."
     */
    fun matchingSpec(requestedSpecs: List<ZkSystemSpec>): ZkSystemSpec?

    /**
     * Generate a ZK proof of possession (and, if [verifierIdentity] is
     * non-null, a pseudonym bound to it) over the credential in
     * [credentialBytes].
     *
     * **Why this takes raw credential bytes + a signer, not a pre-assembled
     * DeviceResponse**: confirmed 2026-08-14 by reading
     * `wallet-frontend`'s `feat/longfellow-zk` branch (`MdocProverService.ts`,
     * by the same author as `zk-cred-longfellow`'s V8/PPID work) plus the
     * Rust crate's own `parse_device_response` - the native prover's
     * `device_response` parameter is "the mdoc's DeviceResponse, as CBOR
     * data" **including a real, normally-computed device signature** over
     * `sessionTranscript` (via the exact same `DeviceAuthentication`/
     * `deviceSigned` construction any non-ZK mdoc presentation already uses -
     * `parse_device_response` requires `device_signed.device_auth.device_signature`
     * to be present and errors otherwise). The ZK proof does not replace the
     * device signature; it proves knowledge of a *valid* one (among other
     * things) without revealing it. This locally-assembled DeviceResponse
     * bytes are a private witness fed only to the local prover - unlike a
     * normal presentation's output, they are never sent to the verifier
     * (only [ZkProofResult.proofBytes] is) - so it should be built with full
     * disclosure (no claim filtering): the circuit itself, not this SDK,
     * selects which claims [requestedClaims] actually reveals.
     *
     * @param spec the specific [ZkSystemSpec] to prove against - normally
     *   whatever [matchingSpec] just returned for this same request.
     * @param credentialBytes the credential's raw stored bytes (a full
     *   DeviceResponse-shaped envelope, matching
     *   `MdocDeviceResponseBuilder`'s own constructor input in `sdk/keystore`).
     * @param sessionTranscript the OpenID4VP/DC-API/proximity session
     *   transcript this proof must be bound to (mirrors every non-ZK mdoc
     *   presentation's own session-transcript binding) - already computed by
     *   the caller for whichever transport is in play; this call is
     *   transport-agnostic.
     * @param requestedClaims element identifiers the verifier asked to have
     *   selectively disclosed within the proof.
     * @param verifierIdentity non-null to also derive and include a
     *   pseudonym bound to this verifier; `null` for a plain proof of
     *   possession with no pseudonym.
     * @param signer signs raw bytes with the device key for the (private,
     *   never-transmitted) witness DeviceResponse's own device signature;
     *   must return a raw (not DER) signature - same contract as
     *   `MdocDeviceResponseBuilder`'s own `signer` parameter.
     * @param priorState opaque prover-side cache from a previous call to
     *   this same credential+system (see [ZkProofResult.nextState]) -
     *   systems without a reuse path (Longfellow) ignore it.
     */
    suspend fun generateProof(
        spec: ZkSystemSpec,
        credentialBytes: ByteArray,
        sessionTranscript: ByteArray,
        requestedClaims: List<String>,
        verifierIdentity: VerifierIdentity?,
        signer: suspend (ByteArray) -> ByteArray,
        priorState: ByteArray? = null,
    ): ZkProofResult
}

/**
 * Derives the wire-format `verifier_context` a [ZkProofSystem] pseudonym
 * derivation binds to a specific verifier - a policy decision independent
 * of which proof system produced the pseudonym, so it's pluggable
 * separately from [ZkProofSystem] itself.
 *
 * **This is the real wire-format formula**, confirmed 2026-08-14 by reading
 * `balfanz/multipaz`'s `ppid` branch (`verifier.kt`) directly - NOT a naive
 * single hash of one combined value:
 *
 * ```
 * pairwise_pseudonym = SHA256(pseudonym_seed || SHA256(SHA256(verifier_id) || SHA256(ppid_context)))
 * ```
 *
 * i.e. `verifier_id` and `ppid_context` are each independently SHA-256'd
 * first, concatenated, and SHA-256'd again to produce the 32-byte value fed
 * to the underlying proof system as its own `verifier_context` parameter
 * (see e.g. `zk-cred-longfellow`'s `prove_with_ppid`) - that system's own
 * `SHA256(pseudonym_seed || verifier_context)` is the OUTER hash in the
 * formula above, not a separate/different formula. Getting this derivation
 * wrong produces pseudonyms that silently fail to match any real verifier's
 * expectation, even though proof generation itself succeeds.
 */
interface ZkPseudonymDeriver {
    fun deriveVerifierContext(verifierIdentity: VerifierIdentity): ByteArray
}

/**
 * The default, spec-faithful [ZkPseudonymDeriver] - implements the formula
 * documented on that interface exactly. Stateless; safe to share/reuse
 * across proof systems and requests.
 */
object DefaultZkPseudonymDeriver : ZkPseudonymDeriver {
    override fun deriveVerifierContext(verifierIdentity: VerifierIdentity): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        val verifierIdHash = digest.digest(verifierIdentity.clientId.toByteArray(Charsets.UTF_8))
        digest.reset()
        val ppidContextHash = digest.digest((verifierIdentity.ppidContext ?: "").toByteArray(Charsets.UTF_8))
        digest.reset()
        digest.update(verifierIdHash)
        digest.update(ppidContextHash)
        return digest.digest()
    }
}

/**
 * Holds every [ZkProofSystem] compiled into this wallet and resolves "does
 * any registered system satisfy this verifier's ZK request" - mirrors
 * [org.siros.sdk.wallet.WscdSelectionPolicy]'s registry role: matching
 * declared capabilities (doc type + system spec) against the request, not a
 * hardcoded single-system assumption, even though Longfellow is the only
 * real implementation on day one.
 */
class ZkProofSystemRegistry(private val systems: List<ZkProofSystem>) {
    /**
     * The first registered system (in registration order) that supports
     * [docType] and can satisfy one of [requestedSpecs], paired with the
     * matched spec - or `null` if none qualify.
     */
    fun resolve(docType: String, requestedSpecs: List<ZkSystemSpec>): Pair<ZkProofSystem, ZkSystemSpec>? {
        for (system in systems) {
            if (docType !in system.supportedDocTypes) continue
            val matched = system.matchingSpec(requestedSpecs) ?: continue
            return system to matched
        }
        return null
    }

    /** Every registered system's [ZkProofSystem.systemId], for diagnostics/settings UI. */
    val registeredSystemIds: List<String> get() = systems.map { it.systemId }
}
