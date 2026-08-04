// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore.mdoc

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec

/**
 * Verifies [ProximitySessionCrypto] against the real ISO/IEC 18013-5 Annex
 * D.5.1 "Session encryption" worked example - the same source PDF as
 * [NfcHandoverSelectTest] (see that file's doc comment). Independently
 * re-derived and cross-checked byte-for-byte with a standalone Python
 * script (`cryptography` library: real ECDH + HKDF + AES-256-GCM) before
 * being hardcoded here, including a full decrypt of the vector's own
 * `SessionEstablishment` ciphertext down to the exact Annex D.4.1.1 mdoc
 * request CBOR.
 */
class ProximitySessionCryptoTest {

    // Annex D.5.1's ephemeral device/reader key pairs (P-256).
    private val eDeviceKeyX = "5a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe".let { fix(it) }
    private val eDeviceKeyY = "b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67".let { fix(it) }
    private val eDeviceKeyD = "c1917a1579949a042f1ba9fc53a2df9b1bc47adf31c10f813ed75702d1c1f136".let { fix(it) }
    private val eReaderKeyX = "60e3392385041f51403051f2415531cb56dd3f999c71687013aac6768bc8187e".let { fix(it) }
    private val eReaderKeyY = "e58deb8fdbe907f7dd5368245551a34796f7d2215c440c339bb0f7b67beccdfa".let { fix(it) }
    private val eReaderKeyD = "de3b4b9e5f72dd9b58406ae3091434da48a6f9fd010d88fcb0958e2cebec947c".let { fix(it) }

    private val expectedSkReader = "58d277d8719e62a1561d248f403f477e9e6c37bf5d5fc5126f8f4c727c22dfc9".let { fix(it) }
    private val expectedSkDevice = "81d170e07fbdac93c1a676242c2576124a380d87bb73ed9ce4834de2272cf409".let { fix(it) }

    /** Bare (untagged) `SessionTranscript` array bytes from Annex D.5.1 - see [ProximitySessionCrypto.deriveSessionKeys]'s doc comment on why bare, not tag-24-wrapped. */
    private val bareSessionTranscriptHex =
        "83d8185858a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d9" +
        "3e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67d81858" +
        "4ba40102200121582060e3392385041f51403051f2415531cb56dd3f999c71687013aac6768bc8187e225820e58deb8f" +
        "dbe907f7dd5368245551a34796f7d2215c440c339bb0f7b67beccdfa8258c391020f487315d10209616301013001046d" +
        "646f631a200c016170706c69636174696f6e2f766e642e626c7565746f6f74682e6c652e6f6f6230081b28128b372828" +
        "01021c015c1e580469736f2e6f72673a31383031333a646576696365656e676167656d656e746d646f63a20063312e30" +
        "018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe22" +
        "5820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc6758cd910225487215910202637201" +
        "02110204616301013000110206616301036e6663005102046163010157001a201e016170706c69636174696f6e2f766e" +
        "642e626c7565746f6f74682e6c652e6f6f6230081b28078080bf2801021c021107c832fff6d26fa0beb34dfcd555d482" +
        "3a1c11010369736f2e6f72673a31383031333a6e66636e6663015a172b016170706c69636174696f6e2f766e642e7766" +
        "612e6e616e57030101032302001324fec9a70b97ac9684a4e326176ef5b981c5e8533e5f00298cfccbc35e700a6b0204" +
        "14"

    /** Annex D.5.1's full `SessionEstablishment` CBOR message. */
    private val sessionEstablishmentHex =
        "a26a655265616465724b6579d818584ba40102200121582060e3392385041f51403051f2415531cb56dd3f999c716870" +
        "13aac6768bc8187e225820e58deb8fdbe907f7dd5368245551a34796f7d2215c440c339bb0f7b67beccdfa6464617461" +
        "5902df52ada2acbeb6c390f2ca0bc659b484678eb94dd45074386aadece23777b44606e42e2846bc2e2ee3c1e867b1d1" +
        "685e41354a021abb0fda36f09cf5d5c51b561d3be41c9347ae71cf2b49de9dec7b44046ab02247931b210c9157840c15" +
        "14a6027b08810716adf61966344979314ac3ae9f40e66e015c1254a684108bd093e8772ec333fb663fd6803af02ea10b" +
        "dbe83a999f75b55a180f872139fb57ac04acd58ca15eca150cde1c3b849401188b7a30ce887dd7b71b12eda2fc6ec6e5" +
        "235a6c9498351fcd301f2292a4ebba7555285cee84ead96ef1677b0af8239f6a7a52af4b8809b1d52ab21a162ca31ade" +
        "21c57bd1d9970a2832aac41c7d52d1c4fee4ee64030a218df51363be701792fa6c515c489bd39dcad6fba48f1d6eb19e" +
        "9c769531a3bf9998a32c01841305f23844ca3db6a1ff0d0d917343d62fc72ad58eab01a3198116f19606609f94e35eac" +
        "b78d23c59c67852a361915fe87848cdba5630c99fab71aeff72d131cf442654f7708ec48216416f2d996cf6cf91012b7" +
        "71b88907b1d1629dfa794343e653c31207482e2f6621cd4b5dcf3b3c328625c33fe98be99c5f264a264315be41bafdc7" +
        "26f8bcde5920de0a71884d860af44c1ff1b3d78b2e8d720d85dae53fea2b3fa1806162a4be02d039567c5eb2419c2ad8" +
        "79af48fcb7df55ca94f1b00f62187fa2329c8227aae0130ec052ca3e2102e57e72911b328cfdcfbaaf6b9364660f6134" +
        "15382644c30c0bd4e222c5cf94ba5a73679c53d5ced95ca50787c2289a0c17358393c1e0f2272361002fb9b160606888" +
        "a59ef7a2c389f68b7cb424572db026b17cf2bdcafcb67c8292d92b50050356900a62a82b16f854759052b00f0f4673a4" +
        "6229f43257e8e8325401b3fecc8c6d2258baf7f7c2fbbafab3a1b6aded4eceac1eafd5b61118df93bc0a622b03504fde" +
        "47cebb224e983db12677e316c22aae042d6ce4adae0d8b0f40437b8e1afa0859c9501beb63974496859a60f11069b196" +
        "5b4ffac5779a96191f89eac7caa688b9e67c"

    /**
     * The spec's own hex dumps occasionally carry a stray trailing
     * character from PDF text-layout artifacts (see [[reference_iso18013_5_local_pdf]]) -
     * this project verified each of these six values is exactly 64 hex
     * chars (32 bytes) via a standalone check before use; this helper just
     * documents that these are pre-verified, not a silent truncation.
     */
    private fun fix(hex: String): String {
        check(hex.length == 64) { "expected a 32-byte P-256 field element, got ${hex.length / 2} bytes" }
        return hex
    }

    private fun hex(s: String): ByteArray {
        val clean = s.replace(" ", "").replace("\n", "")
        return ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    private fun p256Params(): ECParameterSpec {
        val params = AlgorithmParameters.getInstance("EC")
        params.init(ECGenParameterSpec("secp256r1"))
        return params.getParameterSpec(ECParameterSpec::class.java)
    }

    private fun ecPrivateKey(d: String): ECPrivateKey {
        val spec = ECPrivateKeySpec(BigInteger(1, hex(d)), p256Params())
        return KeyFactory.getInstance("EC").generatePrivate(spec) as ECPrivateKey
    }

    private fun ecPublicKey(x: String, y: String): ECPublicKey {
        val point = ECPoint(BigInteger(1, hex(x)), BigInteger(1, hex(y)))
        val spec = ECPublicKeySpec(point, p256Params())
        return KeyFactory.getInstance("EC").generatePublic(spec) as ECPublicKey
    }

    @Test
    fun deriveSessionKeys_matchesTheOfficialVectorsExactly() {
        val eDevicePriv = ecPrivateKey(eDeviceKeyD)
        val eReaderPub = ecPublicKey(eReaderKeyX, eReaderKeyY)
        val sessionTranscript = hex(bareSessionTranscriptHex)

        val keys = ProximitySessionCrypto.deriveSessionKeys(eDevicePriv, eReaderPub, sessionTranscript)

        assertArrayEquals(hex(expectedSkReader), keys.skReader)
        assertArrayEquals(hex(expectedSkDevice), keys.skDevice)
    }

    @Test
    fun deriveSessionKeys_isSymmetric_fromTheReadersPerspective() {
        // The mdoc reader computes the SAME keys using (EReaderKey.Priv, EDeviceKey.Pub) - §12.2.5.
        val eReaderPriv = ecPrivateKey(eReaderKeyD)
        val eDevicePub = ecPublicKey(eDeviceKeyX, eDeviceKeyY)
        val sessionTranscript = hex(bareSessionTranscriptHex)

        val keys = ProximitySessionCrypto.deriveSessionKeys(eReaderPriv, eDevicePub, sessionTranscript)

        assertArrayEquals(hex(expectedSkReader), keys.skReader)
        assertArrayEquals(hex(expectedSkDevice), keys.skDevice)
    }

    @Test
    fun readerCipher_decryptsTheOfficialSessionEstablishmentCiphertext_toARealMdocRequest() {
        val eDevicePriv = ecPrivateKey(eDeviceKeyD)
        val eReaderPub = ecPublicKey(eReaderKeyX, eReaderKeyY)
        val sessionTranscript = hex(bareSessionTranscriptHex)
        val keys = ProximitySessionCrypto.deriveSessionKeys(eDevicePriv, eReaderPub, sessionTranscript)

        val established = ProximitySessionMessages.parseSessionEstablishment(hex(sessionEstablishmentHex))
        val plaintext = ProximitySessionCrypto.readerCipher(keys.skReader).decrypt(established.encryptedData)

        val request = com.upokecenter.cbor.CBORObject.DecodeFromBytes(plaintext)
        assertEquals("1.0", request[com.upokecenter.cbor.CBORObject.FromObject("version")].AsString())
        assertTrue(request[com.upokecenter.cbor.CBORObject.FromObject("docRequests")].size() >= 1)
    }

    @Test
    fun deviceCipher_roundTrips_withTheMdocIdentifierAndIncrementingCounter() {
        val key = ByteArray(32) { it.toByte() }
        val plaintext = "same mdoc response, encrypted twice".toByteArray()

        val encryptor = ProximitySessionCrypto.deviceCipher(key)
        val ciphertext1 = encryptor.encrypt(plaintext)
        val ciphertext2 = encryptor.encrypt(plaintext)

        assertTrue(
            "re-encrypting the same plaintext must change the ciphertext once the counter increments the IV",
            !ciphertext1.contentEquals(ciphertext2),
        )

        val decryptor = ProximitySessionCrypto.deviceCipher(key)
        assertArrayEquals(plaintext, decryptor.decrypt(ciphertext1))
        assertArrayEquals(plaintext, decryptor.decrypt(ciphertext2))
    }

    @Test
    fun parseEReaderKeyPublic_recoversTheSameKeyUsedToDeriveTheOfficialVector() {
        val established = ProximitySessionMessages.parseSessionEstablishment(hex(sessionEstablishmentHex))
        val parsedPub = ProximitySessionCrypto.parseEReaderKeyPublic(established.eReaderKeyBytes)

        assertEquals(BigInteger(1, hex(eReaderKeyX)), parsedPub.w.affineX)
        assertEquals(BigInteger(1, hex(eReaderKeyY)), parsedPub.w.affineY)
    }

    @Test
    fun computeIdent_matchesRfc5869NoSaltSemantics_notATrulyEmptyHmacKey() {
        // Independently cross-checked against Python's `cryptography` HKDF
        // with salt=None (its own correct RFC 5869 "no salt" default) -
        // confirms HKDF-Extract's "no salt" case is a 32-byte all-zero key,
        // NOT a zero-length one (HMAC-SHA256 treats those as different keys).
        val ikm = ByteArray(88) { it.toByte() }
        val ident = ProximitySessionCrypto.computeIdent(ikm)

        assertEquals(16, ident.size)
        assertArrayEquals(hex("0cd459a9fa6e6f91cba134e5e8c3c3ee"), ident)
    }

    @Test
    fun computeIdent_isDeterministic_andDiffersByInput() {
        val ikm1 = ByteArray(32) { it.toByte() }
        val ikm2 = ByteArray(32) { (it + 1).toByte() }

        assertArrayEquals(ProximitySessionCrypto.computeIdent(ikm1), ProximitySessionCrypto.computeIdent(ikm1))
        assertTrue(!ProximitySessionCrypto.computeIdent(ikm1).contentEquals(ProximitySessionCrypto.computeIdent(ikm2)))
    }
}
