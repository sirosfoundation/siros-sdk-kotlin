// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore.mdoc

import com.upokecenter.cbor.CBORObject

/**
 * Minimal COSE_Sign1 construction (RFC 8152 §4.2), scoped to what a wallet
 * (holder) needs to produce a `DeviceAuth.deviceSignature` for an ISO
 * 18013-5 DeviceResponse - signing only, no verification (that's a
 * verifier-side concern). Mirrors `sirosfoundation/vc/pkg/mdoc/cose.go`'s
 * `Sign1Detached` for the algorithm/header/Sig_structure shape.
 *
 * Note: unlike the Go reference, no ECDSA DER->raw signature conversion is
 * needed here - this SDK's [Signer] abstraction (WSCD/UniFFI-backed) already
 * returns raw r||s signatures, confirmed by the existing JWS signing paths
 * (`generateProof`/`signPresentation` in `WscdKeystoreAdapter`) which embed
 * the same signer output directly as a JWS signature with no conversion.
 */
object MdocCose {

    /** COSE algorithm identifiers per RFC 8152 §8.1/§8.2, relevant subset. */
    private const val ALG_ES256 = -7L
    private const val ALG_ES384 = -35L
    private const val ALG_ES512 = -36L
    private const val ALG_EDDSA = -8L

    private const val HEADER_ALGORITHM = 1L

    private fun algorithmValue(algorithm: String): Long = when (algorithm.uppercase()) {
        "ES256" -> ALG_ES256
        "ES384" -> ALG_ES384
        "ES512" -> ALG_ES512
        "EDDSA", "ED25519" -> ALG_EDDSA
        else -> ALG_ES256
    }

    /**
     * Build a detached COSE_Sign1 over [payload] with [externalAad] as the
     * Sig_structure's `external_aad` (the ISO 18013-5 DeviceAuthentication
     * bytes, for a DeviceResponse device signature). Returns the CBOR-encoded
     * tag-18 4-element array `[protected, unprotected, null, signature]`.
     *
     * @param signer signs raw bytes with the device key; must return a raw
     *   (not DER) signature for ECDSA algorithms.
     */
    suspend fun sign1Detached(
        algorithm: String,
        externalAad: ByteArray,
        signer: suspend (ByteArray) -> ByteArray,
    ): CBORObject {
        val algValue = algorithmValue(algorithm)

        val protectedHeaders = CBORObject.NewMap()
        protectedHeaders[CBORObject.FromObject(HEADER_ALGORITHM)] = CBORObject.FromObject(algValue)
        val protectedBytes = protectedHeaders.EncodeToBytes()

        // Sig_structure = ["Signature1", protected, external_aad, payload]
        // Detached: payload is an empty byte string.
        val sigStructure = CBORObject.NewArray()
        sigStructure.Add(CBORObject.FromObject("Signature1"))
        sigStructure.Add(CBORObject.FromObject(protectedBytes))
        sigStructure.Add(CBORObject.FromObject(externalAad))
        sigStructure.Add(CBORObject.FromObject(ByteArray(0)))
        val toBeSigned = sigStructure.EncodeToBytes()

        val signature = signer(toBeSigned)

        val coseSign1 = CBORObject.NewArray()
        coseSign1.Add(CBORObject.FromObject(protectedBytes))
        coseSign1.Add(CBORObject.NewMap()) // empty unprotected headers
        coseSign1.Add(CBORObject.Null) // detached payload
        coseSign1.Add(CBORObject.FromObject(signature))

        return CBORObject.FromObjectAndTag(coseSign1, 18)
    }
}
