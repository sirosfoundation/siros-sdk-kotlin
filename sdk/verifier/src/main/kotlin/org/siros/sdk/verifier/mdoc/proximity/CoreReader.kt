// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.mdoc.proximity

import org.siros.sdk.verifier.mdoc.MdocDocumentRequest
import org.siros.sdk.verifier.mdoc.MdocReaderAuthentication
import org.siros.sdk.verifier.mdoc.VerifiedMdocDocument
import org.siros.sdk.verifier.mdoc.VerifiedMdocElement
import uniffi.siros_verifier_core_ffi.FfiException
import uniffi.siros_verifier_core_ffi.Reader as FfiReader
import uniffi.siros_verifier_core_ffi.ReaderAuth
import uniffi.siros_verifier_core_ffi.ReaderAuthSigner
import uniffi.siros_verifier_core_ffi.RequestedDocument
import uniffi.siros_verifier_core_ffi.RequestedElement
import uniffi.siros_verifier_core_ffi.RequestedNamespace
import uniffi.siros_verifier_core_ffi.VerifiedDocument

internal data class CoreVerifiedDocument(
    val docType: String,
    val elements: List<VerifiedMdocElement>,
    val issuerX5c: List<ByteArray>,
    val validUntil: Long,
    val authzenRequestJson: String,
)

internal interface CoreReader {
    fun establishmentMessage(documents: List<MdocDocumentRequest>): ByteArray
    fun dataMessage(documents: List<MdocDocumentRequest>): ByteArray
    fun openResponse(sessionData: ByteArray, now: Long, acceptedDocTypes: List<String>): List<CoreVerifiedDocument>
    fun terminationMessage(): ByteArray
    fun close()
}

internal fun interface CoreReaderFactory {
    fun start(deviceEngagement: ByteArray, handover: ByteArray, mdocIssuerRole: String): CoreReader
}

internal class CoreSessionOverException(val status: ULong) : Exception()
internal class CoreRejectedException(val code: String, val detail: String) : Exception()

internal class FfiCoreReaderFactory : CoreReaderFactory {
    override fun start(deviceEngagement: ByteArray, handover: ByteArray, mdocIssuerRole: String): CoreReader =
        mapErrors { FfiCoreReader(FfiReader.startWithRole(deviceEngagement, handover, mdocIssuerRole)) }
}

private class FfiCoreReader(private val reader: FfiReader) : CoreReader {
    override fun establishmentMessage(documents: List<MdocDocumentRequest>): ByteArray =
        mapErrors { withNativeDocuments(documents, reader::establishmentMessageFromDocuments) }

    override fun dataMessage(documents: List<MdocDocumentRequest>): ByteArray =
        mapErrors { withNativeDocuments(documents, reader::dataMessageFromDocuments) }

    override fun openResponse(
        sessionData: ByteArray,
        now: Long,
        acceptedDocTypes: List<String>,
    ): List<CoreVerifiedDocument> = mapErrors {
        reader.openResponse(sessionData, now, acceptedDocTypes).map(::coreDocument)
    }

    override fun terminationMessage(): ByteArray = mapErrors(reader::terminationMessage)

    override fun close() = reader.close()
}

private fun withNativeDocuments(
    documents: List<MdocDocumentRequest>,
    operation: (List<RequestedDocument>) -> ByteArray,
): ByteArray {
    val nativeAuthentications = mutableListOf<ReaderAuth>()
    val nativeDocuments = documents.map { document ->
        val readerAuth = document.readerAuth?.let { auth ->
            toNativeAuth(auth).also(nativeAuthentications::add)
        }
        RequestedDocument(
            docType = document.docType,
            namespaces = document.namespaces.map { namespace ->
                RequestedNamespace(
                    namespace = namespace.namespace,
                    elements = namespace.elements.map { element ->
                        RequestedElement(element.identifier, element.intentToRetain)
                    },
                )
            },
            readerAuth = readerAuth,
        )
    }
    return try {
        operation(nativeDocuments)
    } finally {
        nativeAuthentications.forEach(ReaderAuth::close)
    }
}

private fun toNativeAuth(auth: MdocReaderAuthentication): ReaderAuth =
    ReaderAuth(
        auth.certificateChain,
        object : ReaderAuthSigner {
            override fun signEs256(data: ByteArray): ByteArray = auth.signer.signEs256(data)
        },
    )

private fun coreDocument(document: VerifiedDocument): CoreVerifiedDocument =
    CoreVerifiedDocument(
        docType = document.docType,
        elements = document.elements.map { element ->
            VerifiedMdocElement(element.namespace, element.identifier, element.valueCbor)
        },
        issuerX5c = document.issuerX5c,
        validUntil = document.validUntil,
        authzenRequestJson = document.authzenRequestJson,
    )

private inline fun <T> mapErrors(operation: () -> T): T =
    try {
        operation()
    } catch (e: FfiException.SessionOver) {
        throw CoreSessionOverException(e.status)
    } catch (e: FfiException.Rejected) {
        throw CoreRejectedException(e.code, e.detail)
    }
