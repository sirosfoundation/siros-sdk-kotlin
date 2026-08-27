// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import java.util.Base64
import uniffi.zk_cred_bbs.BbsSuiteId
import uniffi.zk_cred_bbs.commitFinalize
import uniffi.zk_cred_bbs.commitInit
import uniffi.zk_cred_bbs.jwpAccept
import uniffi.zk_cred_bbs.jwpCommittedMessages

/**
 * The wallet's side of blind BBS issuance.
 *
 * # Why the wallet has to be here at all
 *
 * Every other credential this SDK handles is signed by an issuer and handed
 * over; the wallet's first involvement is storing it. Blind BBS is not like
 * that. The holder commits to messages the issuer never sees, and to the
 * public key of a device-held key binding key, and the issuer signs *that
 * commitment*. So a BBS credential cannot be issued without the wallet
 * having spoken first, and cannot be retrofitted onto one that was.
 *
 * # It is still one round trip
 *
 * The commit challenge is pure wallet-local Fiat-Shamir - it is derived
 * from the commitment itself, with no issuer nonce and no server input. So
 * `commitInit` -> the authenticator signs -> `commitFinalize` all happen
 * inside the wallet, before the credential request is sent, and the
 * commitment rides along in that one request.
 *
 * Freshness still comes from the existing `c_nonce`-bound key proof. The
 * commitment's own proof is a proof of *knowledge*, not of freshness, and
 * asking it to carry freshness would be a mistake.
 *
 * # Order of operations
 *
 * The wallet commits before it knows anything about the issuer's own
 * claims - it cannot know how many there will be. That works because the
 * committed message octets are just the claim values; the *indices* live in
 * the credential header's map, which the issuer builds. [prepare] and
 * [BbsIssuancePreparation.accept] are the two halves either side of that
 * gap.
 *
 * @param suiteId which key binding construction to issue under. Must match
 *   what the issuer will sign with; it selects the domain separation, and a
 *   mismatch produces a credential that verifies against nothing.
 */
class BbsIssuanceParticipant(
    override val systemId: String = BbsProofSystem.SYSTEM_ID,
    private val suiteId: BbsSuiteId = BbsSuiteId.SCHNORR,
) : ZkIssuanceParticipant {

    override suspend fun prepare(
        holderClaimsJson: String,
        keybindPublicKeys: List<ByteArray>,
        signer: ZkWitnessSigner,
    ): BbsIssuancePreparation {
        // The issuer will index these by sorted pointer, so the wallet has
        // to commit in that order too - which is why this is a native call
        // and not a `sortedBy` here. Same code the issuer runs.
        val derived = jwpCommittedMessages(holderClaimsJson)

        val commit = commitInit(suiteId, derived.messages, keybindPublicKeys)

        // One authenticator signature per key binding key, each over the
        // SAME commit challenge - the device proving it holds the key the
        // credential is about to be bound to. An issuer that could not
        // check this would be binding credentials to keys nobody controls.
        //
        // An unbound credential has no keys and so no signatures, and the
        // loop below correctly does nothing.
        val signatures = keybindPublicKeys.map {
            signer.sign(COSE_ALG_BLS12381G1_SCHNORR, commit.challenge)
        }

        val commitment = commitFinalize(suiteId, commit.state, signatures)

        return BbsIssuancePreparation(
            suiteId = suiteId,
            commitmentWithProof = commitment,
            holderPointers = derived.pointers,
            committedMessages = derived.messages,
            secretProverBlind = commit.secretProverBlind,
            keybindPublicKeys = keybindPublicKeys,
        )
    }

    companion object {
        /**
         * Credential-request member carrying the holder's commitment,
         * base64url-encoded.
         *
         * Structurally analogous to `proofs` in an OID4VCI credential
         * request: the wallet-local device signature over the commit
         * challenge plays the same role for the key binding key that a
         * `proof.jwt` plays for the proof-of-possession key.
         */
        const val COMMITMENT_FIELD: String = "bbs_commitment"

        /**
         * Credential-request member naming the committed claims, as a JSON
         * array of RFC 6901 pointers.
         *
         * The issuer needs these: it must place the holder's messages in
         * the credential's map, and it never sees their values so it cannot
         * name them itself. It checks the count against the commitment
         * rather than taking the wallet's word for it.
         */
        const val POINTERS_FIELD: String = "bbs_committed_claims"
    }
}

/**
 * Everything the wallet must send, and everything it must remember, between
 * committing and receiving the credential.
 *
 * **[secretProverBlind] is long-lived.** It is generated here and required
 * for every presentation for the life of the credential. Losing it makes
 * the credential unusable; leaking it undoes the blinding. It must reach
 * client-side encrypted storage and never a backend.
 */
class BbsIssuancePreparation internal constructor(
    private val suiteId: BbsSuiteId,
    /** The `commitment_with_proof` blob the issuer verifies and signs. */
    val commitmentWithProof: ByteArray,
    /** RFC 6901 pointers naming the committed claims, in message order. */
    val holderPointers: List<String>,
    /** The committed message octets, in the same order. */
    val committedMessages: List<ByteArray>,
    /** See the class doc: long-lived, secret, client-side only. */
    val secretProverBlind: ByteArray,
    /** The key binding public keys the credential is being bound to. */
    val keybindPublicKeys: List<ByteArray>,
) : ZkIssuancePreparation {

    override val credentialRequestFields: Map<String, String>
        get() = mapOf(
            BbsIssuanceParticipant.COMMITMENT_FIELD to jsonString(base64Url(commitmentWithProof)),
            BbsIssuanceParticipant.POINTERS_FIELD to holderPointers.joinToString(
                prefix = "[",
                postfix = "]",
                transform = ::jsonString,
            ),
        )

    /**
     * Check what the issuer returned, and produce the state to store beside
     * it.
     *
     * **Not optional.** This is the wallet's only chance to find out that
     * the issuer signed something other than what was asked for, or that
     * the credential is not actually bound to the key that was committed.
     * Both otherwise surface much later, as a presentation that will not
     * verify with nothing pointing at the cause.
     *
     * @param issuedJwp the credential as issued, in JWP Compact
     *   Serialization.
     * @param issuerPublicKey the issuer's BBS public key, from its
     *   published metadata.
     * @return the state [BbsProofSystem] needs to present this credential,
     *   which the caller must persist alongside it.
     * @throws uniffi.zk_cred_bbs.BbsFfiException if the credential does not
     *   validate against what was committed.
     */
    fun accept(issuedJwp: String, issuerPublicKey: ByteArray): BbsHolderState {
        jwpAccept(
            suiteId,
            issuedJwp,
            issuerPublicKey,
            committedMessages,
            keybindPublicKeys,
            secretProverBlind,
        )
        return BbsHolderState(
            issuerPublicKey = issuerPublicKey,
            secretProverBlind = secretProverBlind,
            committedMessages = committedMessages,
            keybindPublicKeys = keybindPublicKeys,
        )
    }

    private fun base64Url(data: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(data)

    /**
     * Minimal JSON string encoding.
     *
     * These values are base64url and RFC 6901 pointers, so the escapes that
     * can arise are `"`, `\` and `/`-adjacent control characters from a
     * hostile claim name. Escaping them here rather than pulling in a JSON
     * library keeps this module's dependency surface where it was.
     */
    private fun jsonString(value: String): String = buildString {
        append('"')
        for (c in value) {
            when {
                c == '"' -> append("\\\"")
                c == '\\' -> append("\\\\")
                c == '\n' -> append("\\n")
                c == '\r' -> append("\\r")
                c == '\t' -> append("\\t")
                c < ' ' -> append("\\u%04x".format(c.code))
                else -> append(c)
            }
        }
        append('"')
    }
}
