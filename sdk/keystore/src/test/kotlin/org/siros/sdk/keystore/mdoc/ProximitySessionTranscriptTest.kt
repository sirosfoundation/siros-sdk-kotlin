// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore.mdoc

import com.upokecenter.cbor.CBORObject
import com.upokecenter.cbor.CBORType
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ProximitySessionTranscriptTest {

    private fun fakeEReaderKeyBytes(): ByteArray {
        val engagement = DeviceEngagement.create()
        // Reuse DeviceEngagement's own COSE_Key encoding as a stand-in "reader" key for this test's purposes.
        val decoded = CBORObject.DecodeFromBytes(engagement.deviceEngagementBytes)
        return decoded[CBORObject.FromObject(1L)][1].EncodeToBytes()
    }

    @Test
    fun build_qrHandover_producesNullHandoverSlot() {
        val engagement = DeviceEngagement.create()
        val eReaderKeyBytes = fakeEReaderKeyBytes()

        val transcript = ProximitySessionTranscript.build(
            deviceEngagementBytes = engagement.deviceEngagementBytes,
            eReaderKeyBytes = eReaderKeyBytes,
            handoverSelectMessageBytes = null,
        )

        val decoded = CBORObject.DecodeFromBytes(transcript)
        assertEquals(CBORType.Array, decoded.type)
        assertEquals(3, decoded.size())
        assertTrue(decoded[0].HasOneTag(24))
        assertArrayEquals(engagement.deviceEngagementBytes, decoded[0].UntagOne().GetByteString())
        assertTrue(decoded[1].HasOneTag(24))
        assertTrue(decoded[2].isNull)
    }

    @Test
    fun build_nfcStaticHandover_producesTwoElementArrayWithNullSecondSlot() {
        val engagement = DeviceEngagement.create()
        val eReaderKeyBytes = fakeEReaderKeyBytes()
        val handoverSelect = NfcHandoverSelect.build(engagement)

        val transcript = ProximitySessionTranscript.build(
            deviceEngagementBytes = engagement.deviceEngagementBytes,
            eReaderKeyBytes = eReaderKeyBytes,
            handoverSelectMessageBytes = handoverSelect,
        )

        val decoded = CBORObject.DecodeFromBytes(transcript)
        val handover = decoded[2]
        assertEquals(CBORType.Array, handover.type)
        assertEquals(2, handover.size())
        assertArrayEquals(handoverSelect, handover[0].GetByteString())
        assertTrue(handover[1].isNull)
    }

    @Test
    fun build_eReaderKeyBytes_reusedVerbatim_notRebuilt() {
        val engagement = DeviceEngagement.create()
        val eReaderKeyBytes = fakeEReaderKeyBytes()

        val transcript = ProximitySessionTranscript.build(
            deviceEngagementBytes = engagement.deviceEngagementBytes,
            eReaderKeyBytes = eReaderKeyBytes,
            handoverSelectMessageBytes = null,
        )

        val decoded = CBORObject.DecodeFromBytes(transcript)
        assertArrayEquals(eReaderKeyBytes, decoded[1].EncodeToBytes())
    }
}
