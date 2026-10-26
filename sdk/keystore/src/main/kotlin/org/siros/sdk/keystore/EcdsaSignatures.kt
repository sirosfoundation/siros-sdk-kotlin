// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import java.math.BigInteger
import java.security.interfaces.ECPublicKey
import java.util.Base64
import org.siros.sdk.credentials.KeystoreException

/**
 * P-256 ECDSA signature encodings: the DER `ECDSA-Sig-Value` that `java.security.Signature` and the
 * Android Keystore produce, and the raw `r || s` (32 + 32 bytes) that JWS (RFC 7518 §3.4) and COSE
 * (RFC 9053 §2.1) carry and that [Signer.sign] returns.
 */
internal object EcdsaSignatures {

    /** The order n of the P-256 group. */
    val P256_ORDER: BigInteger =
        BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

    private val HALF_ORDER: BigInteger = P256_ORDER.shiftRight(1)

    private const val SCALAR_BYTES = 32

    /**
     * The raw `r || s` of a DER P-256 signature, with `s` in the lower half of the group order
     * (`s' = n - s` when `s > n/2`). Both forms verify; the low one is the canonical form some
     * verifiers and circuits insist on, so this signer never hands out the other.
     *
     * @throws KeystoreException when [der] is not a well-formed P-256 `ECDSA-Sig-Value`.
     */
    fun derToRawLowS(der: ByteArray): ByteArray {
        val (r, s) = parseDer(der)
        val sLow = if (s > HALF_ORDER) P256_ORDER - s else s
        return fixed(r) + fixed(sLow)
    }

    /** The DER `ECDSA-Sig-Value` of a raw 64-byte `r || s` (for verifying with `java.security`). */
    fun rawToDer(raw: ByteArray): ByteArray {
        require(raw.size == 2 * SCALAR_BYTES) { "A P-256 signature is 64 bytes, not ${raw.size}" }
        val r = derInteger(BigInteger(1, raw.copyOfRange(0, SCALAR_BYTES)))
        val s = derInteger(BigInteger(1, raw.copyOfRange(SCALAR_BYTES, 2 * SCALAR_BYTES)))
        val body = r + s
        return byteArrayOf(0x30, body.size.toByte()) + body
    }

    /** The public JWK (RFC 7518 §6.2.1) of a P-256 key: `kty`, `crv`, `x`, `y`, coordinates 32 bytes each. */
    fun publicJwk(key: ECPublicKey): String {
        val enc = Base64.getUrlEncoder().withoutPadding()
        val x = enc.encodeToString(fixed(key.w.affineX))
        val y = enc.encodeToString(fixed(key.w.affineY))
        return """{"kty":"EC","crv":"P-256","x":"$x","y":"$y"}"""
    }

    /** [value] as exactly 32 big-endian bytes. */
    private fun fixed(value: BigInteger): ByteArray {
        val bytes = value.toByteArray()
        return when {
            bytes.size == SCALAR_BYTES -> bytes
            bytes.size == SCALAR_BYTES + 1 && bytes[0] == 0.toByte() -> bytes.copyOfRange(1, bytes.size)
            bytes.size < SCALAR_BYTES -> ByteArray(SCALAR_BYTES - bytes.size) + bytes
            else -> throw KeystoreException("A P-256 scalar does not fit in 32 bytes", errorCode = "invalid_signature")
        }
    }

    private fun derInteger(value: BigInteger): ByteArray {
        val bytes = value.toByteArray() // minimal two's complement: a leading 0x00 keeps it positive
        return byteArrayOf(0x02, bytes.size.toByte()) + bytes
    }

    /** `SEQUENCE { INTEGER r, INTEGER s }`, short-form lengths only (a P-256 signature is at most 72 bytes). */
    private fun parseDer(der: ByteArray): Pair<BigInteger, BigInteger> {
        fun bad(): Nothing = throw KeystoreException("Not a DER P-256 ECDSA signature", errorCode = "invalid_signature")
        if (der.size < 8 || der[0] != 0x30.toByte()) bad()
        val seqLen = der[1].toInt() and 0xFF
        if (seqLen >= 0x80 || seqLen != der.size - 2) bad()
        var pos = 2
        fun integer(): BigInteger {
            if (pos + 2 > der.size || der[pos] != 0x02.toByte()) bad()
            val len = der[pos + 1].toInt() and 0xFF
            if (len == 0 || len > SCALAR_BYTES + 1 || pos + 2 + len > der.size) bad()
            val bytes = der.copyOfRange(pos + 2, pos + 2 + len)
            if (bytes[0].toInt() and 0x80 != 0) bad() // negative
            pos += 2 + len
            return BigInteger(1, bytes)
        }
        val r = integer()
        val s = integer()
        if (pos != der.size) bad()
        if (r.signum() == 0 || s.signum() == 0 || r >= P256_ORDER || s >= P256_ORDER) bad()
        return r to s
    }
}
