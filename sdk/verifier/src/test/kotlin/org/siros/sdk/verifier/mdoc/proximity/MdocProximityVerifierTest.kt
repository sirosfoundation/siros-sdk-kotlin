// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.mdoc.proximity

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import kotlin.test.assertFailsWith
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.verifier.mdoc.MdocDocumentRequest
import org.siros.sdk.verifier.mdoc.MdocReaderInbound
import org.siros.sdk.verifier.mdoc.MdocRequestedElement
import org.siros.sdk.verifier.mdoc.MdocRequestedNamespace
import org.siros.sdk.verifier.mdoc.VerifiedMdocElement
import org.siros.sdk.verifier.trust.AuthZenDeniedException
import org.siros.sdk.verifier.trust.AuthZenPdp

class MdocProximityVerifierTest {
    @Test
    fun startPreservesEngagementRoleAndRequest() = runTest {
        val core = FakeCoreReader()
        val factory = FakeFactory(core)
        val engagement = engagement()
        val verifier = MdocProximityVerifier(
            pdp = AuthZenPdp { true },
            mdocIssuerRole = "mdl-issuer",
            now = { 123 },
            readerFactory = factory,
        )
        val session = verifier.start(engagement, listOf(request()))

        assertArrayEquals(engagement.deviceEngagementBytes, factory.deviceEngagement)
        assertArrayEquals(byteArrayOf(0xf6.toByte()), factory.handover)
        assertEquals("mdl-issuer", factory.role)
        assertArrayEquals(byteArrayOf(1), session.establishmentMessage())
        assertEquals(listOf(request()), core.establishmentDocuments)
        session.close()
        assertTrue(core.closed)
    }

    @Test
    fun openResponseEvaluatesExactAuthzenBeforeMappingClaims() = runTest {
        val evaluations = mutableListOf<String>()
        val core = FakeCoreReader().apply {
            response = listOf(coreDocument("authzen-request"))
        }
        val session = session(core, AuthZenPdp { request ->
            evaluations += request
            true
        })

        val inbound = session.openResponse(byteArrayOf(9))

        assertEquals(listOf("authzen-request"), evaluations)
        assertEquals(listOf("org.iso.18013.5.1.mDL"), core.acceptedDocTypes)
        assertEquals(123L, core.now)
        val verified = inbound as MdocReaderInbound.Verified
        assertEquals("org.iso.18013.5.1.mDL", verified.documents.single().docType)
        assertEquals("given_name", verified.documents.single().elements.single().identifier)
    }

    @Test
    fun explicitDenialReturnsNoClaims() = runTest {
        val core = FakeCoreReader().apply {
            response = listOf(coreDocument("deny-this"))
        }
        val session = session(core, AuthZenPdp { throw AuthZenDeniedException() })

        assertFailsWith<AuthZenDeniedException> {
            session.openResponse(byteArrayOf(9))
        }
    }

    @Test
    fun laterDenialDoesNotReturnPartiallyAcceptedDocuments() = runTest {
        val core = FakeCoreReader().apply {
            response = listOf(coreDocument("permit"), coreDocument("deny"))
        }
        val evaluations = mutableListOf<String>()
        val session = session(core, AuthZenPdp { request ->
            evaluations += request
            if (request == "deny") throw AuthZenDeniedException()
            true
        })

        assertFailsWith<AuthZenDeniedException> {
            session.openResponse(byteArrayOf(9))
        }
        assertEquals(listOf("permit", "deny"), evaluations)
    }

    @Test
    fun peerTerminationIsDataNotACryptographicFailure() = runTest {
        val core = FakeCoreReader().apply { sessionOverStatus = 20u }
        val session = session(core)

        assertEquals(
            MdocReaderInbound.SessionOver(20u),
            session.openResponse(byteArrayOf(9)),
        )
    }

    @Test
    fun coreRejectionKeepsItsStableCode() = runTest {
        val core = FakeCoreReader().apply { rejection = CoreRejectedException("integrity", "bad mac") }
        val session = session(core)

        val error = assertFailsWith<MdocVerifierException> {
            session.openResponse(byteArrayOf(9))
        }
        assertEquals("integrity", error.code)
        assertEquals("bad mac", error.detail)
    }

    @Test
    fun closeIsIdempotent() {
        val core = FakeCoreReader()
        val session = session(core)

        session.close()
        session.close()

        assertTrue(core.closed)
        assertEquals(1, core.closeCalls)
    }

    private fun session(
        core: FakeCoreReader,
        pdp: AuthZenPdp = AuthZenPdp { true },
    ): MdocReaderSession = MdocReaderSession(core, pdp, { 123 }, listOf(request()))

    private class FakeFactory(private val reader: CoreReader) : CoreReaderFactory {
        var deviceEngagement: ByteArray? = null
        var handover: ByteArray? = null
        var role: String? = null

        override fun start(deviceEngagement: ByteArray, handover: ByteArray, mdocIssuerRole: String): CoreReader {
            this.deviceEngagement = deviceEngagement
            this.handover = handover
            role = mdocIssuerRole
            return reader
        }
    }

    private class FakeCoreReader : CoreReader {
        var establishmentDocuments: List<MdocDocumentRequest>? = null
        var acceptedDocTypes: List<String>? = null
        var now: Long? = null
        var response = listOf(coreDocument("authzen"))
        var rejection: CoreRejectedException? = null
        var sessionOverStatus: ULong? = null
        var closed = false
        var closeCalls = 0

        override fun establishmentMessage(documents: List<MdocDocumentRequest>): ByteArray {
            establishmentDocuments = documents
            return byteArrayOf(1)
        }

        override fun dataMessage(documents: List<MdocDocumentRequest>): ByteArray = byteArrayOf(2)

        override fun openResponse(
            sessionData: ByteArray,
            now: Long,
            acceptedDocTypes: List<String>,
        ): List<CoreVerifiedDocument> {
            this.now = now
            this.acceptedDocTypes = acceptedDocTypes
            rejection?.let { throw it }
            sessionOverStatus?.let { throw CoreSessionOverException(it) }
            return response
        }

        override fun terminationMessage(): ByteArray = byteArrayOf(3)

        override fun close() {
            closed = true
            closeCalls++
        }
    }

    companion object {
        private fun request() = MdocDocumentRequest(
            docType = "org.iso.18013.5.1.mDL",
            namespaces = listOf(
                MdocRequestedNamespace(
                    "org.iso.18013.5.1",
                    listOf(MdocRequestedElement("given_name")),
                ),
            ),
        )

        private fun engagement() = MdocQrEngagement(
            deviceEngagementBytes = byteArrayOf(4, 5),
            eDeviceKeyBytes = byteArrayOf(6),
            qrHandover = byteArrayOf(0xf6.toByte()),
            ble = null,
        )

        private fun coreDocument(authzen: String) = CoreVerifiedDocument(
            docType = "org.iso.18013.5.1.mDL",
            elements = listOf(VerifiedMdocElement("org.iso.18013.5.1", "given_name", byteArrayOf(7))),
            issuerX5c = listOf(byteArrayOf(8)),
            validUntil = 456,
            authzenRequestJson = authzen,
        )
    }
}
