// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore.mdoc

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Verifies [DeviceRequestParser] against a real ISO/IEC 18013-5 mdoc
 * request: the plaintext recovered by [ProximitySessionCryptoTest]'s own
 * decrypt of the Annex D.5.1 `SessionEstablishment` ciphertext (which is,
 * per the spec's own text, exactly the Annex D.4.1.1 request) - reusing that
 * already-verified plaintext instead of re-transcribing D.4.1.1's raw hex
 * separately (its own dump includes a long `readerAuth` X.509 chain across
 * a page break, which isn't needed to test parsing).
 */
class DeviceRequestParserTest {

    private val realDeviceRequestHex =
        "a26776657273696f6e63312e306b646f63526571756573747381a26c6974656d7352657175657374d8185893a267646f" +
        "6354797065756f72672e69736f2e31383031332e352e312e6d444c6a6e616d65537061636573a1716f72672e69736f2e" +
        "31383031332e352e31a66b66616d696c795f6e616d65f56f646f63756d656e745f6e756d626572f57264726976696e67" +
        "5f70726976696c65676573f56a69737375655f64617465f56b6578706972795f64617465f568706f727472616974f46a" +
        "726561646572417574688443a10126a118215901b7308201b330820158a00302010202147552715f6add323d4934a1ba" +
        "175dc945755d8b50300a06082a8648ce3d04030230163114301206035504030c0b72656164657220726f6f74301e170d" +
        "3230313030313030303030305a170d3233313233313030303030305a3011310f300d06035504030c0672656164657230" +
        "59301306072a8648ce3d020106082a8648ce3d03010703420004f8912ee0f912b6be683ba2fa0121b2630e601b2b628d" +
        "ff3b44f6394eaa9abdbcc2149d29d6ff1a3e091135177e5c3d9c57f3bf839761eed02c64dd82ae1d3bbfa38188308185" +
        "301c0603551d1f041530133011a00fa00d820b6578616d706c652e636f6d301d0603551d0e04160414f2dfc4acafc5f3" +
        "0b464fada20bfcd533af5e07f5301f0603551d23041830168014cfb7a881baea5f32b6fb91cc29590c50dfac416e300e" +
        "0603551d0f0101ff04040302078030150603551d250101ff040b3009060728818c5d050106300a06082a8648ce3d0403" +
        "020349003046022100fb9ea3b686fd7ea2f0234858ff8328b4efef6a1ef71ec4aae4e307206f9214930221009b94f0d7" +
        "39dfa84cca29efed529dd4838acfd8b6bee212dc6320c46feb839a35f658401f3400069063c189138bdcd2f631427c58" +
        "9424113fc9ec26cebcacacfcdb9695d28e99953becabc4e30ab4efacc839a81f9159933d192527ee91b449bb7f80bf"

    private fun hex(s: String): ByteArray {
        val clean = s.replace(" ", "").replace("\n", "")
        return ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    @Test
    fun parse_realMdlRequest_extractsDocTypeAndRequestedElements() {
        val docRequests = DeviceRequestParser.parse(hex(realDeviceRequestHex))

        assertEquals(1, docRequests.size)
        val doc = docRequests[0]
        assertEquals("org.iso.18013.5.1.mDL", doc.docType)
        assertTrue(doc.requestedItems.containsKey("org.iso.18013.5.1"))

        val elements = doc.requestedItems.getValue("org.iso.18013.5.1")
        assertEquals(
            setOf("family_name", "document_number", "driving_privileges", "issue_date", "expiry_date", "portrait"),
            elements.toSet(),
        )
    }

    @Test
    fun disclosedClaims_flattensAcrossNamespaces() {
        val docRequests = DeviceRequestParser.parse(hex(realDeviceRequestHex))

        assertEquals(6, docRequests[0].disclosedClaims().size)
    }

    @Test
    fun parse_missingDocRequests_throws() {
        val bytes = com.upokecenter.cbor.CBORObject.NewMap().apply {
            this[com.upokecenter.cbor.CBORObject.FromObject("version")] = com.upokecenter.cbor.CBORObject.FromObject("1.0")
        }.EncodeToBytes()

        try {
            DeviceRequestParser.parse(bytes)
            throw AssertionError("expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }
}
