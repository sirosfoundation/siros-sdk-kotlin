// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

package org.siros.sdk.transport.wmp.openid4x

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

//
// siros-wallet-core's typed asks — the child flows the Rust engine starts on
// the wallet (engine-ports' `Host` vocabulary, bridged by the server's
// `RemoteHost` as `<parent>::<type>::<seq>` child flows). Field-for-field
// mirrors of the serde structs in siros-wallet-core's
// crates/engine-ports/src/lib.rs: the same member names, the same null vs
// absent shapes, so a profile answers them without a translation layer.
//
// These are a SECOND ask dialect beside go-wmp's (the `sign` sub-flow with
// its `action` member, and `match`): the LEGACY_WS mode speaks go-wmp's
// dialect against the Go engine, and the HTTP_SSE / LOCAL modes speak these
// against siros-wallet-core. The profile distinguishes them by shape, not by
// configuration: go-wmp always sends a `sign` ask carrying `action` (and a
// `match` ask carrying `parent_flow_id`), and the Rust engine never does —
// its sign-family asks are one flow type each, so no ask of one dialect can
// be mistaken for the other's.
//

/**
 * The bare `sign` ask (engine-ports `SignParams`): one raw signature over
 * the bytes the engine could not sign itself — an OID4VCI JWT proof's
 * `header.payload`, an RFC 7523 client assertion, or an engine-held DPoP
 * proof's htu/htm body. The engine built the bytes; the KEY never left the
 * wallet ([keyId] names it, the wallet resolves it).
 *
 * [toSign] is `Vec<u8>` on the wire: a JSON array of byte values.
 */
@Serializable
data class EngineSignParams(
    /** The PARENT flow's id (the ask rides a `<parent>::sign::<n>` child). */
    @SerialName("flow_id") val flowId: String? = null,
    /** The raw to-be-signed bytes. */
    @SerialName("to_sign") val toSign: List<Int> = emptyList(),
    /** The wallet key to sign with (the renewal's reissuance kid, or the client key); null = the default proof key. */
    @SerialName("key_id") val keyId: String? = null,
    /** The JWS algorithm the engine wants ("ES256" today). */
    val algorithm: String? = null,
) {
    /** [toSign] as bytes. */
    val toSignBytes: ByteArray get() = ByteArray(toSign.size) { toSign[it].toByte() }
}

/**
 * The `signing_key` ask (engine-ports `SigningKeyParams`): the PUBLIC JWK of
 * a named wallet key, so the engine can build a proof header (or an RFC 7523
 * assertion) that names it. Answered with `{"jwk": …}`; an empty answer
 * means "no such key" and the engine proceeds with a bare header.
 */
@Serializable
data class EngineSigningKeyParams(
    @SerialName("flow_id") val flowId: String? = null,
    /** The key to publish; null = the wallet's default proof key. */
    @SerialName("key_id") val keyId: String? = null,
)

/** The answer to an [EngineSigningKeyParams]: the public JWK, or null for "no key". */
data class EngineSigningKeyResult(
    val jwk: JsonObject? = null,
)

/**
 * The `consent` ask (engine-ports `ConsentParams`): the engine asks the
 * wallet's USER whether this presentation may proceed — the OID4VP
 * consent-check, with the purpose (scope) and the claims the query would
 * disclose. Answered with `{"consented": true|false}`; `false` is the decline
 * path (the verifier is told `access_denied`), never a flow error.
 */
@Serializable
data class EngineConsentParams(
    @SerialName("flow_id") val flowId: String? = null,
    /** The scope the verifier asked for. */
    val purpose: String? = null,
    /** The claims the query would disclose. */
    @SerialName("requested_claims") val requestedClaims: List<String> = emptyList(),
    /** The raw base64url transaction_data entries the presentation would bind. */
    @SerialName("transaction_data") val transactionData: List<String> = emptyList(),
)

/**
 * The `authorization` ask (ports' `open_authorization`): the engine has built
 * an OAuth authorization URL; the wallet opens the browser (or however the
 * app hands the user over) and answers the ask with ANY result — the engine
 * ignores it, it only waits for the hand-over. The authorization's own answer
 * comes back later as an `authorize` flow action on the PARENT flow, after
 * the redirect.
 */
@Serializable
data class EngineAuthorizationParams(
    @SerialName("flow_id") val flowId: String? = null,
    /** The URL to hand the user to. */
    val url: String? = null,
)

/** One credential the wallet selected to present (engine-ports `VpSelection`). */
@Serializable
data class EngineVpSelection(
    /** The DCQL query id this selection answers; "" when the request was scope-based. */
    @SerialName("credential_query_id") val credentialQueryId: String? = null,
    /** The wallet's own credential id. */
    @SerialName("credential_id") val credentialId: String,
    /** The claim names to disclose; absent = the whole credential. */
    @SerialName("disclosed_claims") val disclosedClaims: List<String>? = null,
)

/**
 * The `presentation` ask (engine-ports `VpParams`): build and sign the
 * VP token for the selections the wallet itself reported in its `match`
 * answer. Answered with [EngineVpResult]: the `vp_token` (newline-separated
 * tokens), or a structured refusal — `SIGN_REFUSED` (the user declined at the
 * sign stage) or `UNSUPPORTED_TRANSACTION_DATA` — which the engine relays to
 * the verifier as `access_denied` / `invalid_transaction_data`. Never a flow
 * error: the engine reads any `wmp.flow.error` on an ask as a generic
 * refusal, and the verifier must learn WHICH it was.
 */
@Serializable
data class EngineVpParams(
    @SerialName("flow_id") val flowId: String? = null,
    /** The verifier's client_id (redirect_uri fallback). */
    val audience: String? = null,
    /** The request's nonce. */
    val nonce: String? = null,
    /** The wallet's own `match` answer, relayed back. */
    val selections: List<EngineVpSelection> = emptyList(),
    /** The verifier's response_uri (the mdoc session transcript input). */
    @SerialName("response_uri") val responseUri: String? = null,
    /** The direct_post.jwt handover thumbprint; "" when the request was plain. */
    @SerialName("verifier_jwk_thumbprint") val verifierJwkThumbprint: String? = null,
    /** The verifier's own session id (ZK/PPID context). */
    @SerialName("verifier_session_id") val verifierSessionId: String? = null,
    /** Raw base64url transaction_data entries, hashed into the KB-JWT. */
    @SerialName("transaction_data") val transactionData: List<String> = emptyList(),
    /** The match answer's opaque handle, passed through untouched. */
    @SerialName("selection_handle") val selectionHandle: String? = null,
)

/**
 * The answer to an [EngineVpParams]: the signed `vp_token` (newline-separated
 * tokens, or a pre-formed JSON object which passes through unchanged), or a
 * structured [refusalCode] which the engine relays as the verifier-facing
 * error. Exactly one of the two.
 */
data class EngineVpResult(
    val vpToken: String? = null,
    /** `SIGN_REFUSED` or `UNSUPPORTED_TRANSACTION_DATA`. */
    val refusalCode: String? = null,
) {
    init {
        require((vpToken == null) != (refusalCode == null)) {
            "A presentation answer carries exactly one of vp_token or a refusal"
        }
    }

    companion object {
        /** The user declined at the sign stage: the verifier is answered `access_denied`. */
        const val SIGN_REFUSED = "SIGN_REFUSED"

        /** The transaction_data entries are not supported: the verifier is answered `invalid_transaction_data`. */
        const val UNSUPPORTED_TRANSACTION_DATA = "UNSUPPORTED_TRANSACTION_DATA"
    }
}

/**
 * The `dpop_proof` ask (engine-ports `DpopProofParams`): a DPoP proof for a
 * request the engine is about to send, signed by the CLIENT-held key
 * ([keyId]). Answered with the `dpop+jwt` proof; an EMPTY answer is a legal
 * "no client-held key" and the engine falls back to its own ephemeral key.
 */
@Serializable
data class EngineDpopProofParams(
    @SerialName("flow_id") val flowId: String? = null,
    /** The client-held DPoP key to sign with; null = the wallet's default DPoP key. */
    @SerialName("key_id") val keyId: String? = null,
    /** The HTTP method of the request the proof covers. */
    val htm: String? = null,
    /** The URI of the request the proof covers. */
    val htu: String? = null,
    /** The access token the `ath` claim hashes; "" when the request carries none. */
    @SerialName("access_token") val accessToken: String? = null,
    /** A server-issued DPoP nonce; "" when the server sent none. */
    val nonce: String? = null,
)

/** The answer to an [EngineDpopProofParams]: the proof, or null for "unavailable" (the engine falls back). */
data class EngineDpopProofResult(
    val proof: String? = null,
)

/**
 * The `attestation` ask (engine-ports `AttestationParams`): the OAuth client
 * attestation (a WIA and its PoP) for the authorization server [audience].
 * Answered with both JWTs; an empty answer is a legal "no attestation" and
 * the flow proceeds without one.
 */
@Serializable
data class EngineAttestationParams(
    @SerialName("flow_id") val flowId: String? = null,
    /** The AS the attestation is presented to (its token endpoint). */
    val audience: String? = null,
    /** The WIA's `sub` / the PoP's `iss` (the flow's client_id). */
    @SerialName("client_id") val clientId: String? = null,
    /** The AS's attestation challenge when it advertised one; "" otherwise. */
    val challenge: String? = null,
)

/** The answer to an [EngineAttestationParams]: the WIA and PoP JWTs; nulls = "no attestation". */
data class EngineAttestationResult(
    val wia: String? = null,
    val pop: String? = null,
)

/** The refusal codes a tx_code ask refusal may carry (a generic refusal on the wire; local logging only). */
object EngineAskRefusal {
    const val SIGN_REFUSED = EngineVpResult.SIGN_REFUSED
    const val UNSUPPORTED_TRANSACTION_DATA = EngineVpResult.UNSUPPORTED_TRANSACTION_DATA
}
