// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import com.nimbusds.jose.jwk.JWK
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import org.siros.sdk.credentials.diip.createDidJwk
import org.siros.sdk.credentials.diip.didJwkKeyId
import timber.log.Timber

/**
 * How a holder key pair is turned into a DID and a local key id.
 *
 * The value is shared with wallet-frontend's `DID_KEY_VERSION` config, and it
 * has to be: both clients read the same encrypted `privatedata` container, so
 * a key written by one is looked up by the other under whatever id it was
 * stored with.
 */
enum class DidKeyVersion(val value: String) {
    /**
     * `did:jwk`, with the key id being the DID's only verification method,
     * `<did>#0`. What DIIP requires of a Holder, and the default.
     */
    JWK("jwk"),

    /**
     * `did:key` with the P-256 multicodec, key id being the JWK thumbprint.
     * Predates DIIP; kept so a wallet already holding credentials bound to
     * one keeps working.
     */
    P256_PUB("p256-pub"),

    /**
     * `did:key` with a JCS-canonicalized JWK, key id being the JWK
     * thumbprint. wallet-frontend's other legacy option.
     */
    JWK_JCS_PUB("jwk_jcs-pub"),
    ;

    /**
     * Whether keys of this version are named by a DID URL rather than by a
     * JWK thumbprint. This is the branch that matters at every call site:
     * a DID URL can be resolved by a relying party, a thumbprint cannot.
     */
    val namesKeysByDidUrl: Boolean get() = this == JWK

    companion object {
        /**
         * Parse the value as written in configuration. Unknown or absent
         * values fall back to [JWK], so a wallet is DIIP-compliant out of
         * the box rather than silently dropping to a legacy identifier.
         */
        fun fromValue(value: String?): DidKeyVersion {
            val match = entries.firstOrNull { it.value.equals(value?.trim(), ignoreCase = true) }
            if (match == null && !value.isNullOrBlank()) {
                Timber.w("Unknown did_key_version '$value'; using ${JWK.value}")
            }
            return match ?: JWK
        }
    }
}

/** A key pair's DID and the local id it is addressed by. */
data class KeypairIdentity(val did: String, val kid: String)

/**
 * Derive a key pair's identity from its public key.
 *
 * For [DidKeyVersion.JWK] the key id is a DID URL - DIIP binds the Holder
 * with a `cnf.kid` naming a verification method of their DID document, and
 * `#0` is the only one a `did:jwk` document has. The legacy versions keep
 * the JWK thumbprint they have always used.
 *
 * The `did:key` computation for the legacy versions stays where it was, in
 * [JweKeystore], since it needs the EC point rather than the JWK; this
 * function takes the DID as an argument for those.
 */
fun deriveKeypairIdentity(
    publicJwk: JsonObject,
    version: DidKeyVersion,
    legacyDid: () -> String,
    thumbprint: () -> String,
): KeypairIdentity = when (version) {
    DidKeyVersion.JWK -> {
        val did = createDidJwk(publicJwk)
        KeypairIdentity(did = did, kid = didJwkKeyId(did))
    }
    DidKeyVersion.P256_PUB, DidKeyVersion.JWK_JCS_PUB ->
        KeypairIdentity(did = legacyDid(), kid = thumbprint())
}

/**
 * Whether a stored key pair is the one a credential means by [kid].
 *
 * A key pair's id depends on [DidKeyVersion]: a DID URL for `did:jwk`, a JWK
 * thumbprint for the `did:key` versions. Some credentials can only ever name
 * the holder key by value, and so can only produce a thumbprint - an mdoc's
 * `deviceKeyInfo.deviceKey`, and an SD-JWT `cnf.jwk`. Without the fallback, a
 * wallet configured for `did:jwk` could not present the mdoc credentials it
 * already holds, which is exactly the regression this guards.
 */
fun keypairMatchesKid(storedKid: String, publicJwkJson: String, kid: String): Boolean {
    if (storedKid == kid) return true
    return runCatching { JWK.parse(publicJwkJson).computeThumbprint().toString() }
        .getOrNull() == kid
}

/** [keypairMatchesKid] for a key already parsed into a Nimbus [JWK]. */
fun keypairMatchesKid(storedKid: String, publicKey: JWK, kid: String): Boolean {
    if (storedKid == kid) return true
    return runCatching { publicKey.toPublicJWK().computeThumbprint().toString() }.getOrNull() == kid
}

/**
 * The `kid` a credential's `cnf` claim binds it to.
 *
 * DIIP binds the Holder with `cnf.kid`, a DID URL into their `authentication`
 * relationship. Credentials issued before that carry `cnf.jwk` instead and
 * are addressed by JWK thumbprint - this SDK's own legacy key id. Returns
 * null when the credential has no holder binding at all.
 */
fun resolveCnfKid(cnf: JsonObject?): String? =
    org.siros.sdk.credentials.diip.resolveCnfKid(cnf) { jwk ->
        JWK.parse(jwk.toString()).computeThumbprint().toString()
    }

/** [resolveCnfKid] over a credential payload, which may or may not carry a `cnf`. */
fun resolveCnfKidFromPayload(payload: JsonObject?): String? =
    resolveCnfKid(payload?.get("cnf") as? JsonObject)

internal val keypairIdentityJson = Json { ignoreUnknownKeys = true }
