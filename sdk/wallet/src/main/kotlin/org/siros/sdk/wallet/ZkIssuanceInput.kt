// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.siros.sdk.credentials.ZkWitnessSigner

/**
 * What the holder contributes to an issuance the issuer cannot complete
 * alone.
 *
 * Every other credential this SDK handles is signed by an issuer and handed
 * over. A blind BBS credential is not: the holder commits to messages the
 * issuer never sees, and the issuer signs that commitment. So the wallet has
 * to speak first, with values only the host app can supply, and it cannot be
 * retrofitted onto a credential that was already issued.
 *
 * Pass one to [SirosWallet.startIssuance] or
 * [SirosWallet.startIssuanceByOffer]. Omitting it — the default — means the
 * flow carries no holder contribution, which is correct for every credential
 * type that has no issuance participant registered.
 *
 * @param holderClaimsJson a JSON object of the claims the holder
 *   contributes and the issuer never learns the values of. The issuer does
 *   learn which claims were committed: their RFC 6901 pointers travel in the
 *   credential request, because the issuer has to place them in the
 *   credential's claim map and cannot name what it cannot see.
 * @param keybindPublicKeys device-held key binding public keys to bind the
 *   credential to. Empty — the default — issues an unbound credential.
 *   For BBS these are BLS12-381 G1 points, not the P-256 keys the rest of
 *   the wallet uses: the key binding proof is a Schnorr proof in the same
 *   group as the signature, so a platform secure element cannot hold one.
 * @param signer signs the commit challenge once per key in
 *   [keybindPublicKeys] — the device proving it holds the key the credential
 *   is about to be bound to. Required when [keybindPublicKeys] is non-empty
 *   and unused when it is empty.
 * @param issuerPublicKey the issuer's BBS public key, needed to check what
 *   the issuer actually signed once the credential comes back. Supplied by
 *   the caller because there is nowhere yet to fetch it from: OpenID4VCI
 *   issuer metadata has no member for a BBS key, and the issuer side has not
 *   defined one either. When that publication mechanism exists this becomes
 *   optional and the wallet resolves it; until then a caller that cannot
 *   provide it cannot complete a BBS issuance, and finding that out here —
 *   before anything is committed — is better than after.
 */
class ZkIssuanceInput(
    val holderClaimsJson: String,
    val keybindPublicKeys: List<ByteArray> = emptyList(),
    val signer: ZkWitnessSigner? = null,
    val issuerPublicKey: ByteArray? = null,
) {
    init {
        require(keybindPublicKeys.isEmpty() || signer != null) {
            "a key binding key needs a signer: the issuer will not bind a credential to a key " +
                "nobody proved they hold"
        }
    }
}
