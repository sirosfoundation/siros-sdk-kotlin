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
 *   `x509_san_dns:verifier.example.com`) - used as a fallback `verifier_id`
 *   derivation input only when [sessionId] is unavailable (see that
 *   param's doc comment for why it's the real, preferred input).
 * @param ppidContext the DCQL credential query's `meta.ppid_context` string,
 *   if the verifier supplied one - a second, independent binding value a
 *   verifier can use to further scope pseudonyms (e.g. per-session, not just
 *   per-verifier). `null` when absent, which is a normal, common case.
 * @param sessionId the verifier's own session id for this specific
 *   presentation (e.g. the `sessionId` query param on the `request_uri` a
 *   redirect-flow request was fetched from) - the REAL `verifier_id`
 *   derivation input, confirmed 2026-08-17 via direct report from
 *   zk-cred-longfellow's V8/PPID author: a real reference implementation
 *   binds a pseudonym's `verifier_context` to the presentation SESSION, not
 *   the verifier's static identity, specifically so a captured proof can't
 *   be replayed/cached against a different session. `null` for transports
 *   that don't carry one (e.g. DC API has no server-assigned session id at
 *   all) - [clientId] is used as a fallback in that case, though this means
 *   pseudonyms derived over DC API won't match a verifier that itself
 *   expects session-id binding.
 */
data class VerifierIdentity(
    val clientId: String,
    val ppidContext: String? = null,
    val sessionId: String? = null,
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
    /**
     * The exact RFC 3339 timestamp string this proof was generated against
     * (the same value passed as the native prover's own `time` parameter).
     * A verifier-facing wrapper (e.g.
     * [org.siros.sdk.keystore.MdocDeviceResponseBuilder.buildZkDeviceResponse]'s
     * `timestamp` field) must reuse this exact string rather than computing
     * its own - the proof and the wrapper need to agree on it byte-for-byte.
     */
    val timestamp: String = "",
)

/**
 * What a credential *is*: a format plus the type identifier that format
 * uses - an mdoc's doctype, an SD-JWT VC's `vct`.
 *
 * Reuses [CredentialFormat], the enum the credential store already keys
 * on, rather than introducing a second notion of "format" alongside it.
 *
 * Replaces the bare doctype string this interface used to match on. That
 * only worked while every proof system was mdoc-only: a doctype alone
 * cannot distinguish an mdoc mDL from an SD-JWT VC one, so a request for
 * the latter would have been silently routed to an mdoc-only
 * implementation and failed somewhere deep inside a native prover.
 */
data class CredentialTypeRef(
    val format: CredentialFormat,
    val typeId: String,
)

/**
 * A credential's stored bytes, tagged with how to read them.
 *
 * Deliberately still bytes rather than a parsed model. The bytes are a
 * private witness fed to a local prover and never sent to the verifier
 * (see [ZkProofSystem.generateProof]), and each proof system's native
 * crate parses them itself - so a shared parsed representation here would
 * be a translation layer that every implementation immediately undoes.
 */
sealed class CredentialDocument {
    abstract val bytes: ByteArray

    /**
     * A DeviceResponse-shaped CBOR envelope, matching
     * `MdocDeviceResponseBuilder`'s own constructor input.
     */
    data class Mdoc(override val bytes: ByteArray) : CredentialDocument() {
        override fun equals(other: Any?): Boolean =
            this === other || (other is Mdoc && bytes.contentEquals(other.bytes))

        override fun hashCode(): Int = bytes.contentHashCode()
    }

    /** A `~`-delimited SD-JWT VC, as issued. */
    data class SdJwtVc(override val bytes: ByteArray) : CredentialDocument() {
        override fun equals(other: Any?): Boolean =
            this === other || (other is SdJwtVc && bytes.contentEquals(other.bytes))

        override fun hashCode(): Int = bytes.contentHashCode()
    }

    /**
     * A JWP in Compact Serialization, issued form - the UTF-8 bytes of the
     * three dot-separated parts.
     *
     * Kept as bytes for consistency with the other variants even though
     * this one is always ASCII; [compact] is the form the native crate
     * actually takes.
     */
    data class Jwp(override val bytes: ByteArray) : CredentialDocument() {
        constructor(compact: String) : this(compact.toByteArray(Charsets.UTF_8))

        val compact: String get() = bytes.toString(Charsets.UTF_8)

        override fun equals(other: Any?): Boolean =
            this === other || (other is Jwp && bytes.contentEquals(other.bytes))

        override fun hashCode(): Int = bytes.contentHashCode()
    }
}

/**
 * Signs raw bytes with a credential's device key, mid-proof-generation.
 *
 * Replaces the bare `suspend (ByteArray) -> ByteArray` this interface used
 * to take. The reason is [algorithm]: Longfellow needs an ES256 signature
 * over a witness DeviceResponse, while a BBS key binding key signs with
 * Schnorr over BLS12-381 G1 - a different key, on a different curve, that
 * only some authenticators can produce at all. A bare lambda cannot say
 * which it wants, so the wallet had to guess, and guessing wrong yields a
 * signature that fails verification with nothing to point at.
 *
 * Implementations must return a raw (not DER) signature - the same
 * contract `MdocDeviceResponseBuilder`'s own `signer` parameter has.
 */
fun interface ZkWitnessSigner {
    /**
     * @param algorithm the signature algorithm required, as a COSE
     *   identifier (e.g. `-7` for ES256). A signer that cannot produce it
     *   must throw rather than substitute another - a wallet that quietly
     *   signs with the wrong key produces a credential that cannot be
     *   presented.
     */
    suspend fun sign(algorithm: Long, data: ByteArray): ByteArray
}

/** COSE algorithm identifier for ES256 (RFC 8152 §8.1). */
const val COSE_ALG_ES256: Long = -7

/**
 * A ZK system that must take part in ISSUANCE, not only presentation.
 *
 * Longfellow and Vega are post-issuance transforms: they prove things about
 * a credential someone else already signed, so a wallet holding one can
 * start proving without ever having said anything to the issuer. Blind BBS
 * is not like that. The wallet commits to messages the issuer never sees,
 * and to the public key of a device-held key binding key, and the issuer
 * signs that commitment - so a credential that was not issued this way can
 * never be presented this way, and an issuer cannot bolt it on afterwards.
 *
 * That makes this a real seam rather than a speculative one, but it is
 * deliberately narrow. Only the parts every system would share are here:
 * what goes into the credential request, and the fact that something must
 * happen at all. Everything a specific system needs afterwards - BBS has to
 * validate the issued credential against the exact messages it committed to
 * - belongs on that system's own preparation type, where it can be typed
 * properly instead of passed around as an opaque blob.
 *
 * See [ZkProofSystem.issuanceParticipant] for how a wallet finds one
 * without naming a system.
 */
interface ZkIssuanceParticipant {
    /** The owning [ZkProofSystem.systemId], for diagnostics. */
    val systemId: String

    /**
     * Do whatever this system requires before a credential can be
     * requested, and return what the request must carry.
     *
     * @param holderClaimsJson a JSON object of claims the holder
     *   contributes and the issuer never sees. Systems that have no such
     *   concept ignore it.
     * @param keybindPublicKeys device-held key binding public keys to bind
     *   the credential to, in whatever encoding the system defines. Empty
     *   for an unbound credential.
     * @param signer signs whatever challenge the system produces - for BBS
     *   the authenticator signs a commit challenge, which is why this is
     *   suspending and why it carries an algorithm (see [ZkWitnessSigner]).
     */
    suspend fun prepare(
        holderClaimsJson: String,
        keybindPublicKeys: List<ByteArray>,
        signer: ZkWitnessSigner,
    ): ZkIssuancePreparation
}

/**
 * The wallet-facing half of what [ZkIssuanceParticipant.prepare] produced.
 *
 * Implementations carry their own follow-up alongside this - see
 * [BbsIssuancePreparation.accept], which validates the issued credential
 * and yields the state to store next to it.
 */
interface ZkIssuancePreparation {
    /**
     * Members to merge into the OID4VCI credential request object, as
     * already-encoded JSON values keyed by member name.
     *
     * Pre-encoded rather than typed because this crosses into whatever
     * JSON library the request builder uses, and re-encoding a value that
     * a signature covers is how the two ends stop agreeing.
     */
    val credentialRequestFields: Map<String, String>
}

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

    /**
     * The credential types this system can prove over, e.g.
     * `{CredentialTypeRef(MDOC, "org.iso.18013.5.1.mDL")}`.
     *
     * Was `supportedDocTypes: Set<String>`. Carrying the format means a
     * request for an SD-JWT VC or JWP credential finds no match today
     * rather than being routed to an mdoc-only implementation on a
     * doctype-string collision.
     */
    val supportedCredentialTypes: Set<CredentialTypeRef>

    /**
     * Returns whichever of [requestedSpecs] (a verifier's own list, in
     * priority order) this system can satisfy for a proof over exactly
     * [numAttributes] claims, or `null` if none match - the extension point
     * [ZkProofSystemRegistry] uses to resolve "does any registered system
     * satisfy this verifier's ZK request."
     *
     * **Why [numAttributes] is required, not optional**: a real ZK circuit
     * is compiled for a FIXED attribute count (confirmed via a real
     * `go-zk-circuits` catalog entry - e.g.
     * `longfellow-libzk-v1_8_1_4259_2945` has `params.num_attributes: 1`), so
     * a verifier's `zk_system_type` array normally offers several circuit
     * variants (one per attribute count) precisely so the wallet can pick
     * the one matching how many claims it's about to disclose. Ignoring
     * this and picking, say, the first entry with a matching [ZkSystemSpec.system]
     * silently selects a circuit compiled for the wrong attribute count -
     * proof generation still "succeeds" (the native prover doesn't reject
     * it), but the resulting proof is structurally invalid for the circuit
     * that was actually loaded, and a real verifier rejects it during
     * deserialization (confirmed live: multipaz's native verifier surfaces
     * this as `MDOC_VERIFIER_HASH_PARSING_FAILURE`, its own "hash proof
     * could not be parsed" case - not an attribute-content or signature
     * problem, but a wire-format mismatch from proving against a
     * differently-shaped circuit than the one being verified against).
     */
    fun matchingSpec(requestedSpecs: List<ZkSystemSpec>, numAttributes: Int): ZkSystemSpec?

    /**
     * How this system takes part in issuance, or `null` if it does not.
     *
     * Defaulted to `null` because that is the honest answer for every
     * post-issuance system - Longfellow and Vega prove things about a
     * credential someone else already signed - and because defaulting it
     * means adding this seam changed neither of their implementations.
     */
    val issuanceParticipant: ZkIssuanceParticipant? get() = null

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
     * @param document the credential's raw stored bytes, tagged with its
     *   format. A system must reject a [CredentialDocument] variant it does
     *   not handle rather than assuming one - [supportedCredentialTypes]
     *   makes mis-routing unlikely, but not impossible for a caller that
     *   bypasses the registry.
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
     *   never-transmitted) witness DeviceResponse's own device signature.
     *   See [ZkWitnessSigner] for why this carries an algorithm rather than
     *   being a bare lambda.
     * @param priorState opaque prover-side cache from a previous call to
     *   this same credential+system (see [ZkProofResult.nextState]) -
     *   systems without a reuse path (Longfellow) ignore it.
     */
    suspend fun generateProof(
        spec: ZkSystemSpec,
        document: CredentialDocument,
        sessionTranscript: ByteArray,
        requestedClaims: List<String>,
        verifierIdentity: VerifierIdentity?,
        signer: ZkWitnessSigner,
        priorState: ByteArray? = null,
    ): ZkProofResult
}

/**
 * Derives the wire-format `verifier_context` a [ZkProofSystem] pseudonym
 * derivation binds to a specific verifier - a policy decision independent
 * of which proof system produced the pseudonym, so it's pluggable
 * separately from [ZkProofSystem] itself.
 *
 * **This is the real wire-format formula**, confirmed 2026-08-17 against a
 * real, self-hosted multipaz verifier
 * (`multipaz-longfellow/.../LongfellowZkSystem.kt`'s `verifyProof`) - a
 * SINGLE hash of each input, not a double hash:
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
 * formula above, not a separate/different formula.
 *
 * An EARLIER version of this doc comment (and of the real verifier's own
 * `verifyProof`) mistakenly double-hashed `verifier_id`/`ppid_context`: the
 * verifier's wire param for each is ALREADY that value's SHA-256 (hex
 * encoded, added once by the verifier's own request-building code), so
 * hashing it again there produced `SHA256(SHA256(verifier_id))` instead of
 * `SHA256(verifier_id)`. Fixed here 2026-08-17 alongside the matching fix in
 * `LongfellowZkSystem.kt`'s `verifyProof` - not yet independently re-tested
 * against a real device proof at the time of this comment, so treat as a
 * strong, evidence-backed candidate fix rather than a fully closed loop
 * until confirmed live. Getting this derivation wrong produces pseudonyms
 * that silently fail to match any real verifier's expectation, even though
 * proof generation itself succeeds.
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
        // The verifier_id input is the presentation SESSION's id, not the
        // verifier's static client_id (see VerifierIdentity.sessionId's doc
        // comment) - clientId is only a fallback for transports that never
        // carry a session id (e.g. DC API).
        val verifierIdSource = verifierIdentity.sessionId ?: verifierIdentity.clientId
        val verifierIdHash = digest.digest(verifierIdSource.toByteArray(Charsets.UTF_8))
        digest.reset()
        // A real verifier (multipaz's own LongfellowZkSystem.verifyProof,
        // confirmed via its actual reconstruction logic) falls back to 32
        // ZERO bytes when no ppid_context was supplied - NOT
        // SHA256("") - since it never adds a "ppid_context" wire param at
        // all in that case, and its own fallback is a raw zero-filled
        // array, never hashed. Matching that exactly here (rather than
        // hashing an empty string) was required for a real device proof to
        // verify when ppidContext is absent - hashing "" produces a
        // different 32 bytes than an unhashed zero array.
        val ppidContextHash = verifierIdentity.ppidContext?.let { digest.digest(it.toByteArray(Charsets.UTF_8)) }
            ?: ByteArray(32)
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
     * [credentialType] and can satisfy one of [requestedSpecs] for a proof over
     * exactly [numAttributes] claims, paired with the matched spec - or
     * `null` if none qualify. See [ZkProofSystem.matchingSpec]'s doc comment
     * for why [numAttributes] must be the caller's real disclosed-claim
     * count, not a value ignorable/defaultable to "whichever circuit is
     * offered first".
     */
    fun resolve(
        credentialType: CredentialTypeRef,
        requestedSpecs: List<ZkSystemSpec>,
        numAttributes: Int,
    ): Pair<ZkProofSystem, ZkSystemSpec>? {
        for (system in systems) {
            if (credentialType !in system.supportedCredentialTypes) continue
            val matched = system.matchingSpec(requestedSpecs, numAttributes) ?: continue
            return system to matched
        }
        return null
    }

    /**
     * The first registered system that both supports [credentialType] and
     * needs the wallet to contribute something at issuance, or `null` if
     * none do.
     *
     * The point of routing this through the registry rather than letting
     * an issuance flow construct a BBS participant directly is that the
     * flow then never names a proof system. Today exactly one system
     * answers; a flow written against this keeps working when that stops
     * being true, and more immediately, keeps working for the credential
     * types where the answer is `null` - which is most of them.
     */
    fun issuanceParticipant(credentialType: CredentialTypeRef): ZkIssuanceParticipant? {
        for (system in systems) {
            if (credentialType !in system.supportedCredentialTypes) continue
            system.issuanceParticipant?.let { return it }
        }
        return null
    }

    /** Every registered system's [ZkProofSystem.systemId], for diagnostics/settings UI. */
    val registeredSystemIds: List<String> get() = systems.map { it.systemId }
}
