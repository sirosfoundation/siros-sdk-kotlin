// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore.mdoc

import com.upokecenter.cbor.CBORObject
import java.math.BigInteger
import java.security.PublicKey
import java.security.Signature

/**
 * Minimal COSE_Sign1 construction/verification (RFC 8152 §4.2/§4.4), scoped
 * to an mdoc wallet's needs: signing a `DeviceAuth.deviceSignature` for an
 * ISO 18013-5 DeviceResponse, and - new for RICAL reader-authentication
 * support (Annex F) - verifying an INCOMING COSE_Sign1 (a reader's
 * `readerAuth`). This is a deliberate, first-time departure from this SDK's
 * prior convention of treating incoming COSE_Sign1 structures (issuerAuth)
 * as opaque and never verifying them locally - see
 * [org.siros.sdk.credentials.mdoc.MdocModel]'s own doc comment. Mirrors
 * `sirosfoundation/vc/pkg/mdoc/cose.go`'s `Sign1Detached`/`Verify1` for the
 * algorithm/header/Sig_structure shape.
 *
 * Note: unlike the Go reference, no ECDSA DER->raw signature conversion is
 * needed for SIGNING - this SDK's [Signer] abstraction (WSCD/UniFFI-backed)
 * already returns raw r||s signatures, confirmed by the existing JWS
 * signing paths (`generateProof`/`signPresentation` in
 * `WscdKeystoreAdapter`) which embed the same signer output directly as a
 * JWS signature with no conversion. VERIFYING an incoming signature is the
 * opposite direction: the JDK's [Signature] API only accepts DER-encoded
 * ECDSA signatures, so [verify1] converts the raw r||s COSE signature to
 * DER before calling it.
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
        // `algorithm` here is a signing key's own reported algorithm (e.g.
        // WscdKeystoreAdapter's `key.algorithm`), not a fixed compile-time
        // enum - silently defaulting an unrecognized value to ES256 would
        // put the WRONG COSE alg identifier in the protected header while
        // the signature itself was produced with a different algorithm,
        // breaking verification in a way that looks like a signature
        // mismatch rather than the actual root cause.
        else -> throw IllegalArgumentException("Unsupported mdoc COSE signing algorithm: $algorithm")
    }

    /**
     * Build a detached COSE_Sign1 over [payload] (the ISO 18013-5
     * DeviceAuthentication bytes, for a DeviceResponse device signature).
     * Returns the CBOR-encoded tag-18 4-element array `[protected,
     * unprotected, null, signature]`.
     *
     * "Detached" describes the OUTPUT wire format only (the 3rd element of
     * the returned array is CBOR null, since the verifier reconstructs
     * DeviceAuthentication itself from context rather than needing it
     * embedded) - the signature is still computed over the real [payload]
     * bytes in the Sig_structure's `payload` position, with `external_aad`
     * left empty (`h''`). This was previously inverted (payload hardcoded
     * empty, [payload]'s content passed as external_aad instead) - a real
     * bug matching Google's own reference wallet's construction
     * (https://github.com/digitalcredentialsdev/CMWallet's
     * `generateDeviceResponse()`), confirmed by that reference's exact
     * `sigStructure = ["Signature1", protected, byteArrayOf(),
     * deviceAuthenticationBytes]` shape.
     *
     * @param signer signs raw bytes with the device key; must return a raw
     *   (not DER) signature for ECDSA algorithms.
     */
    suspend fun sign1Detached(
        algorithm: String,
        payload: ByteArray,
        signer: suspend (ByteArray) -> ByteArray,
    ): CBORObject {
        val algValue = algorithmValue(algorithm)

        val protectedHeaders = CBORObject.NewMap()
        protectedHeaders[CBORObject.FromObject(HEADER_ALGORITHM)] = CBORObject.FromObject(algValue)
        val protectedBytes = protectedHeaders.EncodeToBytes()

        // Sig_structure = ["Signature1", protected, external_aad, payload]
        val sigStructure = CBORObject.NewArray()
        sigStructure.Add(CBORObject.FromObject("Signature1"))
        sigStructure.Add(CBORObject.FromObject(protectedBytes))
        sigStructure.Add(CBORObject.FromObject(ByteArray(0)))
        sigStructure.Add(CBORObject.FromObject(payload))
        val toBeSigned = sigStructure.EncodeToBytes()

        val signature = signer(toBeSigned)

        // Bare 4-element array, NOT wrapped in COSE tag 18 - the mdoc
        // convention (matching this SDK's own issuer,
        // sirosfoundation/vc/pkg/mdoc/issuer.go's issuerAuthArray, and
        // Google's reference wallet's generateDeviceResponse()) embeds
        // COSE_Sign1 structures as untagged arrays; a tagged value here
        // previously made Google's own https://digital-credentials.dev/ demo
        // reject deviceSignature with "object of type 'cbor2.CBORTag' has no
        // len()" trying to treat it as a plain 4-element array.
        val coseSign1 = CBORObject.NewArray()
        coseSign1.Add(CBORObject.FromObject(protectedBytes))
        coseSign1.Add(CBORObject.NewMap()) // empty unprotected headers
        coseSign1.Add(CBORObject.Null) // detached payload
        coseSign1.Add(CBORObject.FromObject(signature))

        return coseSign1
    }

    /** Java Security algorithm names per COSE alg identifier, ECDSA subset. */
    private fun jcaAlgorithmFor(coseAlg: Long): String = when (coseAlg) {
        ALG_ES256 -> "SHA256withECDSA"
        ALG_ES384 -> "SHA384withECDSA"
        ALG_ES512 -> "SHA512withECDSA"
        else -> throw IllegalArgumentException("Unsupported COSE algorithm for verification: $coseAlg")
    }

    /** Raw signature byte length (r and s each this many bytes) per COSE alg. */
    private fun rawSignatureLength(coseAlg: Long): Int = when (coseAlg) {
        ALG_ES256 -> 32
        ALG_ES384 -> 48
        ALG_ES512 -> 66
        else -> throw IllegalArgumentException("Unsupported COSE algorithm for verification: $coseAlg")
    }

    /**
     * Converts a raw fixed-length r||s ECDSA signature (the COSE/JOSE wire
     * format, RFC 8152 §8.1) to the ASN.1 DER `SEQUENCE { INTEGER r,
     * INTEGER s }` encoding [java.security.Signature.verify] requires -
     * the opposite direction of `der_signature_to_raw` in
     * `siros-wscd-manager`'s `preview_sign_protocol.rs` (confirmed there via
     * real YubiKey hardware testing), which converts a real authenticator's
     * DER signature back to raw for the WSCD-signing path.
     */
    private fun rawEcdsaSignatureToDer(raw: ByteArray, componentLength: Int): ByteArray {
        require(raw.size == componentLength * 2) {
            "Raw ECDSA signature length ${raw.size} does not match expected ${componentLength * 2}"
        }
        val r = BigInteger(1, raw.copyOfRange(0, componentLength))
        val s = BigInteger(1, raw.copyOfRange(componentLength, raw.size))

        fun encodeInteger(value: BigInteger): ByteArray {
            var bytes = value.toByteArray()
            // BigInteger.toByteArray() already two's-complement-encodes (and
            // left-pads with a 0x00 sign byte when the raw component's high
            // bit would otherwise read as negative) - ASN.1 INTEGER uses the
            // same encoding, so no further adjustment is needed beyond the
            // standard TLV wrapper.
            return byteArrayOf(0x02, bytes.size.toByte()) + bytes
        }

        val rEncoded = encodeInteger(r)
        val sEncoded = encodeInteger(s)
        val sequenceBody = rEncoded + sEncoded
        return byteArrayOf(0x30, sequenceBody.size.toByte()) + sequenceBody
    }

    /**
     * Verifies an incoming COSE_Sign1's signature over [payload] (used for
     * the detached case, e.g. a `readerAuth` whose payload is reconstructed
     * from context rather than embedded - the same detachment convention
     * [sign1Detached] produces) against [publicKey]. Reads the signing
     * algorithm from [sign1]'s protected header (COSE label 1); the RICAL
     * annex (F.3.2) restricts this to ES256/ES384/ES512/EdDSA, but EdDSA
     * verification isn't implemented here yet since no current caller needs
     * it - added if/when one does, rather than guessing at untested code.
     *
     * @param sign1 the 4-element COSE_Sign1 array: `[protected, unprotected,
     *   payload-or-null, signature]`.
     * @param payload the actual signed payload bytes (required even when
     *   `sign1`'s own payload slot is CBOR null, i.e. detached).
     */
    fun verify1(sign1: CBORObject, payload: ByteArray, publicKey: PublicKey): Boolean {
        require(sign1.type == com.upokecenter.cbor.CBORType.Array && sign1.size() == 4) {
            "sign1 is not a 4-element COSE_Sign1 array"
        }
        val protectedBytes = sign1[0].GetByteString()
        val signature = sign1[3].GetByteString()

        val protectedHeaders = CBORObject.DecodeFromBytes(protectedBytes)
        val algValue = protectedHeaders[CBORObject.FromObject(HEADER_ALGORITHM)]
            ?: throw IllegalArgumentException("COSE_Sign1 protected header missing algorithm")
        val coseAlg = algValue.AsInt64Value()

        val sigStructure = CBORObject.NewArray()
        sigStructure.Add(CBORObject.FromObject("Signature1"))
        sigStructure.Add(CBORObject.FromObject(protectedBytes))
        sigStructure.Add(CBORObject.FromObject(ByteArray(0)))
        sigStructure.Add(CBORObject.FromObject(payload))
        val toBeSigned = sigStructure.EncodeToBytes()

        val derSignature = rawEcdsaSignatureToDer(signature, rawSignatureLength(coseAlg))

        val verifier = Signature.getInstance(jcaAlgorithmFor(coseAlg))
        verifier.initVerify(publicKey)
        verifier.update(toBeSigned)
        return verifier.verify(derSignature)
    }

    /**
     * Extracts the x5chain (COSE header label 33) from a COSE_Sign1's
     * unprotected header (index 1 of the 4-element array) - the standard
     * mdoc issuerAuth/deviceAuth/readerAuth convention (confirmed against
     * ISO 18013-5:2021's own worked readerAuth example, §9.1.4: the
     * diagnostic-notation x5chain sits in the second, unprotected map, not
     * the first/protected one - unlike the second-edition RICAL/VICAL
     * trust-list documents' own signatures, which place it differently; see
     * go-trust's `mdocrical`/`vical` registries for that distinction).
     * Returns DER-encoded certificate bytes, leaf first.
     */
    fun extractX5Chain(sign1: CBORObject): List<ByteArray> {
        if (sign1.type != com.upokecenter.cbor.CBORType.Array || sign1.size() < 2) return emptyList()
        val unprotected = sign1[1]
        if (unprotected.type != com.upokecenter.cbor.CBORType.Map) return emptyList()
        val x5chain = unprotected[CBORObject.FromObject(33)] ?: return emptyList()
        return when (x5chain.type) {
            com.upokecenter.cbor.CBORType.ByteString -> listOf(x5chain.GetByteString())
            com.upokecenter.cbor.CBORType.Array -> (0 until x5chain.size()).map { x5chain[it].GetByteString() }
            else -> emptyList()
        }
    }

    /**
     * Builds `ReaderAuthenticationBytes` per ISO 18013-5:2021 §9.1.4 -
     * `#6.24(bstr .cbor ["ReaderAuthentication", SessionTranscript,
     * ItemsRequestBytes])` - the detached content a reader's `readerAuth`
     * COSE_Sign1 actually signs (its own payload slot is CBOR null).
     *
     * @param sessionTranscript the bare (untagged) `SessionTranscript` array
     *   bytes, the same shape [ProximitySessionCrypto] takes.
     * @param itemsRequestTaggedBytes the exact tag-24-wrapped `itemsRequest`
     *   CBOR bytes as they appeared in the `DocRequest` - the identical
     *   bytes, not a re-encoding, per the spec's "Same as in mdoc request".
     */
    fun buildReaderAuthenticationBytes(sessionTranscript: ByteArray, itemsRequestTaggedBytes: ByteArray): ByteArray {
        val readerAuthentication = CBORObject.NewArray()
        readerAuthentication.Add(CBORObject.FromObject("ReaderAuthentication"))
        readerAuthentication.Add(CBORObject.DecodeFromBytes(sessionTranscript))
        readerAuthentication.Add(CBORObject.DecodeFromBytes(itemsRequestTaggedBytes))
        return CBORObject.FromObjectAndTag(CBORObject.FromObject(readerAuthentication.EncodeToBytes()), 24).EncodeToBytes()
    }
}
