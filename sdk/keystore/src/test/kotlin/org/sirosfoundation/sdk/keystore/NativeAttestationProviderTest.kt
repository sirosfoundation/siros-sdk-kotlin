package org.sirosfoundation.sdk.keystore

import org.junit.Assert.assertEquals
import org.junit.Test

class NativeAttestationProviderTest {

    @Test
    fun nativeAttestationEvidenceDataClass() {
        val evidence = NativeAttestationEvidence(
            type = "google_play_integrity",
            token = "eyJhbGciOiJSUzI1NiJ9.test-token",
            keyId = "test-key-123",
            challenge = "random-nonce-456",
        )

        assertEquals("google_play_integrity", evidence.type)
        assertEquals("eyJhbGciOiJSUzI1NiJ9.test-token", evidence.token)
        assertEquals("test-key-123", evidence.keyId)
        assertEquals("random-nonce-456", evidence.challenge)
    }

    @Test
    fun nativeAttestationEvidenceEquality() {
        val e1 = NativeAttestationEvidence("apple_app_attest", "tok1", "k1", "c1")
        val e2 = NativeAttestationEvidence("apple_app_attest", "tok1", "k1", "c1")
        val e3 = NativeAttestationEvidence("google_play_integrity", "tok1", "k1", "c1")

        assertEquals(e1, e2)
        assertEquals(e1.hashCode(), e2.hashCode())
        assert(e1 != e3)
    }

    @Test
    fun nativeAttestationEvidenceCopy() {
        val original = NativeAttestationEvidence("apple_app_attest", "t", "k", "c")
        val modified = original.copy(type = "google_play_integrity")
        assertEquals("google_play_integrity", modified.type)
        assertEquals("t", modified.token)
    }
}
