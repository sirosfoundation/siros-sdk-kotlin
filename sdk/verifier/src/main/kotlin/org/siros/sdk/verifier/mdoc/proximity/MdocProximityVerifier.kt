// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.mdoc.proximity

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.siros.sdk.verifier.mdoc.MdocDocumentRequest
import org.siros.sdk.verifier.mdoc.MdocReaderInbound
import org.siros.sdk.verifier.mdoc.VerifiedMdocDocument
import org.siros.sdk.verifier.trust.AuthZenPdp

/** A standalone ISO 18013-5 proximity verifier. No wallet or account session is required. */
class MdocProximityVerifier internal constructor(
    private val pdp: AuthZenPdp,
    private val mdocIssuerRole: String,
    private val now: () -> Long,
    private val readerFactory: CoreReaderFactory,
) {
    constructor(
        pdp: AuthZenPdp,
        mdocIssuerRole: String = "pid-provider",
        now: () -> Long = { System.currentTimeMillis() / 1000 },
    ) : this(pdp, mdocIssuerRole, now, FfiCoreReaderFactory())

    /** Starts a reader session from exact QR or NFC handover bytes and a verifier-owned request. */
    suspend fun start(
        engagement: MdocEngagement,
        documents: List<MdocDocumentRequest>,
    ): MdocReaderSession = withContext(Dispatchers.IO) {
        val reader = mapErrors {
            readerFactory.start(
                engagement.deviceEngagementBytes,
                engagement.handoverCbor,
                mdocIssuerRole,
            )
        }
        MdocReaderSession(reader, pdp, now, documents)
    }
}

/** One serialized reader session. Close it after the elected transport has finished. */
class MdocReaderSession internal constructor(
    private val reader: CoreReader,
    private val pdp: AuthZenPdp,
    private val now: () -> Long,
    initialDocuments: List<MdocDocumentRequest>,
) : AutoCloseable {
    private val operation = Mutex()
    private var requestedDocuments = initialDocuments

    @Volatile
    private var closed = false

    /** Builds and encrypts the first DeviceRequest while retaining its policy in verifier-core. */
    suspend fun establishmentMessage(): ByteArray = operation.withLock {
        checkOpen()
        withContext(Dispatchers.IO) {
            mapErrors { reader.establishmentMessage(requestedDocuments) }
        }
    }

    /** Builds and encrypts a subsequent DeviceRequest and replaces the retained response policy. */
    suspend fun dataMessage(documents: List<MdocDocumentRequest>): ByteArray = operation.withLock {
        checkOpen()
        val message = withContext(Dispatchers.IO) {
            mapErrors { reader.dataMessage(documents) }
        }
        requestedDocuments = documents
        message
    }

    /**
     * Decrypts and verifies a complete SessionData message, enforces the request,
     * and obtains a go-trust permit for every document before exposing any claims.
     */
    suspend fun openResponse(sessionData: ByteArray): MdocReaderInbound = operation.withLock {
        checkOpen()
        try {
            val documents = withContext(Dispatchers.IO) {
                mapErrors {
                    reader.openResponse(
                        sessionData,
                        now(),
                        requestedDocuments.map(MdocDocumentRequest::docType).distinct(),
                    )
                }
            }
            // Do not map or expose claims until every policy decision has permitted.
            documents.forEach { document -> pdp.evaluate(document.authzenRequestJson) }
            MdocReaderInbound.Verified(
                documents.map { document ->
                    VerifiedMdocDocument(
                        docType = document.docType,
                        elements = document.elements,
                        issuerX5c = document.issuerX5c,
                        validUntil = document.validUntil,
                    )
                },
            )
        } catch (e: CoreSessionOverException) {
            MdocReaderInbound.SessionOver(e.status)
        }
    }

    suspend fun terminationMessage(): ByteArray = operation.withLock {
        checkOpen()
        withContext(Dispatchers.IO) { mapErrors(reader::terminationMessage) }
    }

    override fun close() {
        if (!closed) {
            closed = true
            reader.close()
        }
    }

    private fun checkOpen() {
        check(!closed) { "The reader session is closed" }
    }
}

/** A verifier-core rejection with its stable machine-readable class preserved. */
class MdocVerifierException internal constructor(
    val code: String,
    val detail: String,
) : Exception("$code: $detail")

private inline fun <T> mapErrors(operation: () -> T): T =
    try {
        operation()
    } catch (e: CoreRejectedException) {
        throw MdocVerifierException(e.code, e.detail)
    }
