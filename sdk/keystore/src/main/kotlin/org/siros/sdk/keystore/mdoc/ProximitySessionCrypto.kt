// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore.mdoc

import com.upokecenter.cbor.CBORObject
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * ISO 18013-5 §9.1.1/§12.2.5 session encryption: ECKA-DH key agreement
 * between `EDeviceKey`/`EReaderKey`, HKDF-SHA256 deriving `SKDevice`/
 * `SKReader`, and AES-256-GCM encryption/decryption of `SessionEstablishment`/
 * `SessionData` payloads with the spec's deterministic IV.
 *
 * Verified against the real ISO/IEC 18013-5 Annex D.5.1 worked example - see
 * `ProximitySessionCryptoTest.kt`, which reproduces the exact `EDeviceKey`/
 * `EReaderKey` values, decrypts the vector's own `SessionEstablishment`/
 * `SessionData` ciphertexts, and confirms the plaintexts are the exact
 * Annex D.4.1.1/D.4.1.2 mdoc request/response CBOR (independently
 * re-derived and cross-checked with a standalone Python script during
 * implementation - see [[reference_iso18013_5_local_pdf]] memory).
 */
object ProximitySessionCrypto {

    /** Fixed 8-byte IV identifier the mdoc reader uses, per §12.2.5. */
    private val READER_IDENTIFIER = ByteArray(8)

    /** Fixed 8-byte IV identifier the mdoc uses, per §12.2.5. */
    private val MDOC_IDENTIFIER = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 1)

    private const val GCM_TAG_BITS = 128

    data class SessionKeys(val skReader: ByteArray, val skDevice: ByteArray)

    /**
     * Derive `SKReader`/`SKDevice` per §12.2.5: ECKA-DH between
     * [eDeviceKeyPrivate] and [eReaderKeyPublic] produces `ZAB`; HKDF-SHA256
     * with `salt = SHA-256(SessionTranscriptBytes)` (the tag-24-WRAPPED
     * form - computed internally here, distinct from the bare array bytes
     * [ProximitySessionTranscript.build] returns) and `info = "SKReader"`/
     * `"SKDevice"` derives both 32-byte keys.
     *
     * @param sessionTranscript the bare (untagged) `SessionTranscript` array
     *   bytes from [ProximitySessionTranscript.build].
     */
    fun deriveSessionKeys(
        eDeviceKeyPrivate: ECPrivateKey,
        eReaderKeyPublic: ECPublicKey,
        sessionTranscript: ByteArray,
    ): SessionKeys {
        val zab = ecdh(eDeviceKeyPrivate, eReaderKeyPublic)
        val sessionTranscriptBytes = CBORObject.FromObjectAndTag(sessionTranscript, 24).EncodeToBytes()
        val salt = sha256(sessionTranscriptBytes)
        return SessionKeys(
            skReader = hkdfSha256(ikm = zab, salt = salt, info = "SKReader".toByteArray(Charsets.US_ASCII), length = 32),
            skDevice = hkdfSha256(ikm = zab, salt = salt, info = "SKDevice".toByteArray(Charsets.US_ASCII), length = 32),
        )
    }

    /** Encryptor/decryptor for one session key, tracking its own monotonic message counter (never reused). */
    class SessionCipher(private val key: ByteArray, private val identifier: ByteArray) {
        private var counter = 1

        /** AES-256-GCM encrypt with the next IV for this key; empty AAD, per §12.2.5. */
        fun encrypt(plaintext: ByteArray): ByteArray {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nextIv()))
            return cipher.doFinal(plaintext)
        }

        /** AES-256-GCM decrypt with the next IV for this key; empty AAD, per §12.2.5. */
        fun decrypt(ciphertext: ByteArray): ByteArray {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nextIv()))
            return cipher.doFinal(ciphertext)
        }

        private fun nextIv(): ByteArray {
            val counterBytes = byteArrayOf(
                (counter ushr 24).toByte(), (counter ushr 16).toByte(), (counter ushr 8).toByte(), counter.toByte(),
            )
            counter++
            return identifier + counterBytes
        }
    }

    /** Cipher for messages the mdoc READER encrypts (mdoc requests) - used by the mdoc to decrypt them. */
    fun readerCipher(skReader: ByteArray): SessionCipher = SessionCipher(skReader, READER_IDENTIFIER)

    /** Cipher for messages the MDOC encrypts (mdoc responses). */
    fun deviceCipher(skDevice: ByteArray): SessionCipher = SessionCipher(skDevice, MDOC_IDENTIFIER)

    /** Parse a `SessionEstablishment.eReaderKey` field (`#6.24`-tagged `COSE_Key`) into an [ECPublicKey]. */
    fun parseEReaderKeyPublic(eReaderKeyBytes: ByteArray): ECPublicKey {
        val tagged = CBORObject.DecodeFromBytes(eReaderKeyBytes)
        val coseKey = CBORObject.DecodeFromBytes(tagged.UntagOne().GetByteString())
        val x = coseKey[CBORObject.FromObject(-2L)].GetByteString()
        val y = coseKey[CBORObject.FromObject(-3L)].GetByteString()
        val params = p256Params()
        val point = ECPoint(BigInteger(1, x), BigInteger(1, y))
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, params)) as ECPublicKey
    }

    /**
     * §11.1.3.1 `Ident` characteristic value: `HKDF-SHA256(IKM=EDeviceKeyBytes,
     * salt=<none>, info="BLEIdent", L=16)`. In "mdoc central client mode",
     * the mdoc reads this from the reader's GATT service and MUST terminate
     * the connection if it doesn't match - it's the only defense against
     * connecting to the wrong (or an impersonating) reader.
     *
     * RFC 5869 §2.2: when no salt is provided, HKDF-Extract uses a salt of
     * `HashLen` zero bytes (32, for SHA-256) - NOT a zero-length byte array.
     * `HMAC-SHA256` with a truly empty key is a different (and, on some JCE
     * providers, outright rejected) computation from one with a 32-byte
     * all-zero key.
     */
    fun computeIdent(eDeviceKeyBytes: ByteArray): ByteArray =
        hkdfSha256(ikm = eDeviceKeyBytes, salt = ByteArray(32), info = "BLEIdent".toByteArray(Charsets.US_ASCII), length = 16)

    private fun p256Params(): ECParameterSpec {
        val params = AlgorithmParameters.getInstance("EC")
        params.init(ECGenParameterSpec("secp256r1"))
        return params.getParameterSpec(ECParameterSpec::class.java)
    }

    private fun ecdh(priv: ECPrivateKey, pub: ECPublicKey): ByteArray {
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(priv)
        ka.doPhase(pub, true)
        return ka.generateSecret()
    }

    private fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val prk = hmacSha256(salt, ikm)
        val okm = java.io.ByteArrayOutputStream()
        var t = ByteArray(0)
        var counter = 1
        while (okm.size() < length) {
            t = hmacSha256(prk, t + info + byteArrayOf(counter.toByte()))
            okm.write(t)
            counter++
        }
        return okm.toByteArray().copyOf(length)
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
}
