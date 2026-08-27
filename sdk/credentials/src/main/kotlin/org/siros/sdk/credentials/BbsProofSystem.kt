// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import java.security.MessageDigest
import java.util.Base64
import uniffi.zk_cred_bbs.BbsSuiteId
import uniffi.zk_cred_bbs.jwpBuildPresentationHeader
import uniffi.zk_cred_bbs.jwpInspect
import uniffi.zk_cred_bbs.jwpPresentFinalize
import uniffi.zk_cred_bbs.jwpPresentInit

/**
 * COSE algorithm identifier for Schnorr over BLS12-381 G1, the signature a
 * BBS key binding key produces.
 *
 * **A placeholder.** `-65609` is what the YubiKey 5.8 prototype firmware
 * reports for `EcsdsaBls12_381_BP1_Sha256_SEC1`; the construction is
 * pre-standardisation and this identifier is expected to change when it
 * reaches a registry. It is named here rather than inlined so that when it
 * does, there is one place to change.
 */
const val COSE_ALG_BLS12381G1_SCHNORR: Long = -65609

/**
 * The holder-side state a BBS credential needs that its container does not
 * carry.
 *
 * A JWP holds the issuer's claims and the signature. It deliberately does
 * not hold the holder's own committed values, the blinding factor tying
 * them to the signature, or which device key the credential is bound to -
 * publishing those would undo the point of blind issuance. So they live
 * beside the credential, and every presentation needs them.
 *
 * [secretProverBlind] in particular is long-lived: it is generated once at
 * issuance and required for every presentation for the life of the
 * credential. Losing it makes the credential unusable, and it must never
 * leave the wallet.
 */
data class BbsHolderState(
    /** The issuer's BBS public key, as a compressed G2 point. */
    val issuerPublicKey: ByteArray,
    /** The blinding factor from issuance. See the class doc. */
    val secretProverBlind: ByteArray,
    /**
     * The holder's own messages, in the order the credential's header maps
     * them - they occupy the tail of the message vector, after the
     * issuer's.
     */
    val committedMessages: List<ByteArray>,
    /**
     * The key binding public keys this credential is bound to. Empty for a
     * credential with no device binding.
     */
    val keybindPublicKeys: List<ByteArray>,
) {
    override fun equals(other: Any?): Boolean =
        this === other ||
            (
                other is BbsHolderState &&
                    issuerPublicKey.contentEquals(other.issuerPublicKey) &&
                    secretProverBlind.contentEquals(other.secretProverBlind) &&
                    committedMessages.size == other.committedMessages.size &&
                    committedMessages.zip(other.committedMessages).all { (a, b) -> a.contentEquals(b) } &&
                    keybindPublicKeys.size == other.keybindPublicKeys.size &&
                    keybindPublicKeys.zip(other.keybindPublicKeys).all { (a, b) -> a.contentEquals(b) }
            )

    override fun hashCode(): Int = issuerPublicKey.contentHashCode() * 31 + secretProverBlind.contentHashCode()
}

/**
 * Where [BbsProofSystem] looks up a credential's [BbsHolderState].
 *
 * An interface rather than a field on the stored credential because that
 * belongs to the issuance path, and to a format shared with other wallet
 * clients: the state has to reach the encrypted `privatedata` container,
 * and what that container carries is not this class's decision to make.
 * See the SDK's own issuance work for the wiring.
 */
fun interface BbsHolderStateStore {
    /**
     * @param issuedJwp the credential in Compact Serialization, exactly as
     *   stored.
     * @return its holder state, or `null` if this store has none - which a
     *   caller must treat as "cannot present", not as "present without
     *   binding".
     */
    suspend fun stateFor(issuedJwp: String): BbsHolderState?
}

/**
 * Blind BBS presentation, backed by the `zk-cred-bbs` native crate.
 *
 * # How this differs from the other proof systems
 *
 * Longfellow and Vega prove a statement *about* a credential to a circuit
 * compiled in advance. BBS is not a circuit at all: the signature scheme
 * itself supports revealing a chosen subset of the signed messages, and
 * the "proof" is a re-randomised signature. Three consequences show up in
 * this class, each noted where it lands:
 *
 * - [matchingSpec] ignores `numAttributes`, because there is no fixed
 *   attribute count to match.
 * - [ZkProofResult.pseudonymOutcome] is always
 *   [PseudonymOutcome.NOT_SUPPORTED_BY_SYSTEM] - BBS has a pseudonym
 *   construction (`draft-irtf-cfrg-bbs-per-verifier-linkability`) but it is
 *   not implemented, and needs a reserved message slot decided at issuance.
 * - There is no `nextState`: nothing is cached between presentations, and
 *   caching would be the wrong thing anyway, since re-randomising afresh
 *   each time is what keeps presentations unlinkable.
 *
 * # What the verifier receives
 *
 * [ZkProofResult.proofBytes] is the UTF-8 of a presented JWP - four
 * dot-separated parts, self-contained. Unlike the other systems' opaque
 * proof blobs it carries the disclosed claims and both headers, so a
 * verifier needs nothing from this SDK but the issuer's public key.
 *
 * @param holderState where to find the secrets that are not in the
 *   container.
 * @param supportedVcts the credential types this wallet actually holds BBS
 *   credentials for. Unlike a circuit-based system, BBS constrains no type
 *   whatsoever - the honest answer to "what can you prove over" is
 *   "anything issued this way", which the registry's fixed-set matching
 *   cannot express, so the wallet supplies the set it has.
 * @param suiteId which key binding construction these credentials use.
 *   Must match what they were issued under; it selects the domain
 *   separation, and a mismatch verifies against nothing.
 */
class BbsProofSystem(
    private val holderState: BbsHolderStateStore,
    private val supportedVcts: Set<String>,
    private val suiteId: BbsSuiteId = BbsSuiteId.SCHNORR,
) : ZkProofSystem {

    override val systemId: String = SYSTEM_ID

    override val supportedCredentialTypes: Set<CredentialTypeRef> =
        supportedVcts.map { CredentialTypeRef(CredentialFormat.JWP, it) }.toSet()

    /**
     * Matches on the system identifier alone.
     *
     * **`numAttributes` is deliberately ignored**, which is the opposite of
     * what [ZkProofSystem.matchingSpec] requires of a circuit-based system,
     * so it is worth being explicit about why. That requirement exists
     * because a real ZK circuit is compiled for a fixed attribute count and
     * proving against the wrong one yields a structurally invalid proof. A
     * BBS presentation has no circuit and no compiled-in count: the
     * generator list is derived from the credential's own message count at
     * proving time, and the disclosed subset is chosen per presentation.
     * Filtering on an attribute count here would reject specs that this
     * system can satisfy perfectly well.
     */
    override fun matchingSpec(requestedSpecs: List<ZkSystemSpec>, numAttributes: Int): ZkSystemSpec? =
        requestedSpecs.firstOrNull { it.system == SYSTEM_ID }

    override suspend fun generateProof(
        spec: ZkSystemSpec,
        document: CredentialDocument,
        sessionTranscript: ByteArray,
        requestedClaims: List<String>,
        verifierIdentity: VerifierIdentity?,
        signer: ZkWitnessSigner,
        priorState: ByteArray?,
    ): ZkProofResult {
        // A caller that bypassed the registry could hand over any variant.
        val jwp = when (document) {
            is CredentialDocument.Jwp -> document.compact
            else -> throw IllegalArgumentException(
                "BbsProofSystem needs a JWP credential, got ${document::class.simpleName}",
            )
        }

        val state = holderState.stateFor(jwp)
            ?: throw IllegalStateException(
                "no holder state stored for this credential; it cannot be presented without the blinding factor from issuance",
            )

        // Fail before touching the authenticator if the credential cannot
        // answer the request anyway - a user prompt that leads nowhere is
        // worse than an error.
        val info = jwpInspect(jwp)
        val unknown = requestedClaims.filterNot { it in info.pointers }
        require(unknown.isEmpty()) {
            "credential ${info.vct} has no claim at ${unknown.joinToString()}; it maps ${info.pointers.joinToString()}"
        }

        val presentationHeader = jwpBuildPresentationHeader(
            nonce = nonceFor(spec, sessionTranscript),
            aud = audienceFor(spec, verifierIdentity),
            // Binds the transport's own session transcript, which the JWP
            // drafts have no parameter for. Without it this proof would be
            // bound only to a nonce, and every other presentation path in
            // this SDK binds the full transcript.
            extraJson = """{"$SESSION_TRANSCRIPT_PARAM":"${base64Url(sha256(sessionTranscript))}"}""",
        )

        val init = jwpPresentInit(
            suiteId = suiteId,
            issuedJwp = jwp,
            issuerPublicKey = state.issuerPublicKey,
            presentationHeader = presentationHeader,
            requestedPointers = requestedClaims,
            committedMessages = state.committedMessages,
            keybindPublicKeys = state.keybindPublicKeys,
            secretProverBlind = state.secretProverBlind,
        )

        // One authenticator signature per key binding key. Each challenge
        // is already prehashed to 32 octets by the crate, because the
        // prototype firmware caps its signing input - see the crate's
        // PROFILE.md, DELTA 3.
        val signatures = init.keybindChallenges.map { challenge ->
            signer.sign(COSE_ALG_BLS12381G1_SCHNORR, challenge)
        }

        val presented = jwpPresentFinalize(suiteId, init.state, signatures)

        return ZkProofResult(
            proofBytes = presented.toByteArray(Charsets.UTF_8),
            // No reuse path: re-randomising afresh is what keeps
            // presentations unlinkable.
            nextState = null,
            pseudonym = null,
            pseudonymOutcome = PseudonymOutcome.NOT_SUPPORTED_BY_SYSTEM,
            publicValues = mapOf("vct" to info.vct),
        )
    }

    /**
     * The verifier's nonce, which a presentation is replay-bound to.
     *
     * Taken from the spec's params when the verifier supplied one, as
     * OpenID4VP always does. Falling back to the session transcript's hash
     * rather than erroring keeps transports that carry no separate nonce
     * usable, and it is still unique per session.
     */
    private fun nonceFor(spec: ZkSystemSpec, sessionTranscript: ByteArray): String =
        spec.getParam(NONCE_PARAM) ?: base64Url(sha256(sessionTranscript))

    /**
     * Who the presentation is for.
     *
     * `aud` is required by the JWP draft, so there is no "omit it" option.
     * The verifier's own `client_id` is the right value and is what a
     * verifier checks against itself.
     */
    private fun audienceFor(spec: ZkSystemSpec, verifierIdentity: VerifierIdentity?): String =
        spec.getParam(AUDIENCE_PARAM)
            ?: verifierIdentity?.clientId
            ?: throw IllegalArgumentException(
                "a BBS presentation needs an audience: supply '$AUDIENCE_PARAM' in the spec params or a VerifierIdentity",
            )

    private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    private fun base64Url(data: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(data)

    companion object {
        /**
         * This system's identifier in a verifier's `zk_system_type` list.
         *
         * Names the cipher suite rather than a version, because unlike a
         * circuit there is no artifact to version - two wallets agreeing on
         * this string agree on everything that matters.
         */
        const val SYSTEM_ID: String = "bbs-mod-bls12381-schnorr-kb-v0"

        /** Spec param carrying the verifier's nonce. */
        const val NONCE_PARAM: String = "nonce"

        /** Spec param carrying the intended audience. */
        const val AUDIENCE_PARAM: String = "aud"

        /**
         * Presentation-header parameter carrying the session transcript's
         * SHA-256. Private to this profile - the JWP drafts have no
         * parameter for a transport session binding.
         */
        const val SESSION_TRANSCRIPT_PARAM: String = "sth"
    }
}
