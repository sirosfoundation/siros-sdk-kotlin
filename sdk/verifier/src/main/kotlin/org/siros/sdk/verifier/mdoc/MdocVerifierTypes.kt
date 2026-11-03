// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.mdoc

/** One requested mdoc data element. */
data class MdocRequestedElement(
    val identifier: String,
    val intentToRetain: Boolean = false,
)

/** An ordered namespace and its ordered element requests. */
data class MdocRequestedNamespace(
    val namespace: String,
    val elements: List<MdocRequestedElement>,
)

/** Signs the exact COSE input supplied by verifier-core using a dedicated P-256 reader key. */
fun interface MdocReaderAuthSigner {
    /** Returns a raw 64-byte ES256 `r || s` signature, not a DER signature or compact JWS. */
    fun signEs256(data: ByteArray): ByteArray
}

/** Reader authentication using a dedicated verifier identity certificate chain. */
data class MdocReaderAuthentication(
    /** DER certificates, leaf first. */
    val certificateChain: List<ByteArray>,
    val signer: MdocReaderAuthSigner,
)

/** One ordered mdoc document request. */
data class MdocDocumentRequest(
    val docType: String,
    val namespaces: List<MdocRequestedNamespace>,
    val readerAuth: MdocReaderAuthentication? = null,
)

/** A cryptographically verified and policy-authorized mdoc element. */
@ConsistentCopyVisibility
data class VerifiedMdocElement internal constructor(
    val namespace: String,
    val identifier: String,
    /** CBOR-encoded element value; the application decodes only the types it displays. */
    val valueCbor: ByteArray,
)

/** A document released after core verification, request-policy checks, and go-trust permit. */
@ConsistentCopyVisibility
data class VerifiedMdocDocument internal constructor(
    val docType: String,
    val elements: List<VerifiedMdocElement>,
    /** Authentic issuer DER certificates, leaf first; authorization was evaluated separately by go-trust. */
    val issuerX5c: List<ByteArray>,
    val validUntil: Long,
)

/** A reader message that either completes verification or reports peer termination. */
sealed interface MdocReaderInbound {
    /** Claims are available only after every document has an explicit go-trust permit. */
    @ConsistentCopyVisibility
    data class Verified internal constructor(
        val documents: List<VerifiedMdocDocument>,
    ) : MdocReaderInbound

    /** The wallet ended the session. Status 20 is normal termination. */
    @ConsistentCopyVisibility
    data class SessionOver internal constructor(val status: ULong) : MdocReaderInbound
}
