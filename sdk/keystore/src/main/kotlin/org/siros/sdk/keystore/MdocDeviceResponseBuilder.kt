// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import com.upokecenter.cbor.CBORObject
import org.siros.sdk.credentials.mdoc.MdocCbor
import org.siros.sdk.credentials.mdoc.NamespaceItem
import org.siros.sdk.keystore.mdoc.MdocCose
import java.security.MessageDigest

/**
 * Builds an ISO 18013-5 DeviceResponse for mDoc credential presentation
 * via OID4VP (OpenID for Verifiable Presentations).
 *
 * The credential's raw bytes are a full DeviceResponse-shaped envelope as
 * issued (`{documents: [{docType, issuerSigned}], ...}` - confirmed via
 * `sirosfoundation/wallet-frontend#191`), not a bare IssuerSigned blob; this
 * builder parses that envelope with [MdocCbor], applies real selective
 * disclosure by filtering `issuerSigned.nameSpaces` down to [disclosedClaims]
 * (preserving each kept item's original tag-24-wrapped bytes so the issuer's
 * MSO digests remain valid - disclosure selects a subset of already-digested
 * items, it never re-hashes), and signs a fresh device authentication over
 * the OpenID4VPHandover session transcript.
 *
 * Usage:
 * ```kotlin
 * val builder = MdocDeviceResponseBuilder(credentialBytes, algorithm = "ES256")
 * val response = builder.build(
 *     nonce = "verifier-nonce",
 *     audience = "verifier-client-id",
 *     responseUri = "https://verifier.example.com/response",
 *     verifierJwkThumbprint = "base64url-thumbprint",
 *     disclosedClaims = listOf("given_name", "family_name"),
 *     signer = { data -> signer.sign(keyId, data) },
 * )
 * ```
 */
class MdocDeviceResponseBuilder(
    /** Raw credential bytes: a full DeviceResponse-shaped envelope as issued. */
    private val credentialBytes: ByteArray,
    /** Algorithm for signing (ES256 or EdDSA). */
    private val algorithm: String = "ES256",
) {

    /**
     * Build the CBOR-encoded DeviceResponse.
     *
     * @param nonce Verifier nonce from the sign request.
     * @param audience Verifier client ID.
     * @param responseUri Response endpoint URI.
     * @param verifierJwkThumbprint Optional JWK thumbprint of the verifier key.
     * @param disclosedClaims Element identifiers to disclose (null = disclose all namespaces/elements).
     * @param signer Function that signs raw bytes with the device key; must return a raw (not DER) signature.
     * @return CBOR-encoded DeviceResponse bytes.
     */
    suspend fun build(
        nonce: String,
        audience: String,
        responseUri: String,
        verifierJwkThumbprint: String?,
        disclosedClaims: List<String>?,
        signer: suspend (ByteArray) -> ByteArray,
    ): ByteArray {
        val disclosedDocument = parseAndFilter(disclosedClaims)
        val sessionTranscript = buildSessionTranscript(
            clientId = audience,
            nonce = nonce,
            responseUri = responseUri,
            verifierJwkThumbprint = verifierJwkThumbprint,
        )
        val deviceAuthBytes = buildDeviceAuthentication(disclosedDocument.docType, sessionTranscript)
        val coseSign1 = MdocCose.sign1Detached(algorithm, deviceAuthBytes, signer)

        return assembleFinalResponse(disclosedDocument, coseSign1)
    }

    /**
     * Build the CBOR-encoded DeviceResponse for a W3C Digital Credentials API
     * (DC API) presentation, using the `OpenID4VPDCAPIHandover` session
     * transcript (OpenID4VP 1.0 Appendix B.2.6) instead of the redirect
     * flow's `OpenID4VPHandover` - there is no `responseUri`/`clientId` in
     * this flow (the response is returned via the browser's synchronous
     * `navigator.credentials.get()` callback, not an HTTP POST), and the
     * handover binds to the verified browser origin instead.
     *
     * @param nonce Verifier nonce from the request.
     * @param origin The verified browser/page origin that called `navigator.credentials.get()`.
     * @param encryptionPublicJwkThumbprint JWK thumbprint of the verifier's response-encryption
     *   key (present when `response_mode=dc_api.jwt`), null otherwise.
     * @param disclosedClaims Element identifiers to disclose (null = disclose all namespaces/elements).
     * @param signer Function that signs raw bytes with the device key; must return a raw (not DER) signature.
     * @return CBOR-encoded DeviceResponse bytes.
     */
    suspend fun buildForDCAPI(
        nonce: String,
        origin: String,
        encryptionPublicJwkThumbprint: String?,
        disclosedClaims: List<String>?,
        signer: suspend (ByteArray) -> ByteArray,
    ): ByteArray {
        val disclosedDocument = parseAndFilter(disclosedClaims)
        val sessionTranscript = buildDCAPISessionTranscript(
            origin = origin,
            nonce = nonce,
            encryptionPublicJwkThumbprint = encryptionPublicJwkThumbprint,
        )
        val deviceAuthBytes = buildDeviceAuthentication(disclosedDocument.docType, sessionTranscript)
        val coseSign1 = MdocCose.sign1Detached(algorithm, deviceAuthBytes, signer)

        return assembleFinalResponse(disclosedDocument, coseSign1)
    }

    private fun parseAndFilter(disclosedClaims: List<String>?): org.siros.sdk.credentials.mdoc.DocumentMdoc {
        val document = MdocCbor.parseStoredCredential(credentialBytes)
        return if (disclosedClaims == null) {
            document
        } else {
            document.copy(
                issuerSigned = document.issuerSigned.copy(
                    nameSpaces = filterNamespaces(document.issuerSigned.nameSpaces, disclosedClaims),
                )
            )
        }
    }

    /**
     * Filter each namespace's items down to those whose `elementIdentifier`
     * is in [disclosedClaims], preserving each kept item's ORIGINAL
     * tag-24-wrapped [CBORObject] (never re-encoded from the parsed model -
     * the issuer's MSO digests were computed over those exact bytes).
     * Namespaces with no disclosed elements are dropped entirely.
     */
    private fun filterNamespaces(
        nameSpaces: Map<String, List<NamespaceItem>>,
        disclosedClaims: List<String>,
    ): Map<String, List<NamespaceItem>> {
        val disclosed = disclosedClaims.toSet()
        return nameSpaces.mapValues { (_, items) ->
            items.filter { it.item.elementIdentifier in disclosed }
        }.filterValues { it.isNotEmpty() }
    }

    /**
     * Build the OpenID4VPHandover session transcript per OID4VP mdoc profile.
     *
     * SessionTranscript = [
     *   null,  // reserved
     *   null,  // reserved
     *   [
     *     "OpenID4VPHandover",
     *     SHA-256([clientId, nonce, verifierJwkThumbprint, responseUri])
     *   ]
     * ]
     */
    private fun buildSessionTranscript(
        clientId: String,
        nonce: String,
        responseUri: String,
        verifierJwkThumbprint: String?,
    ): ByteArray {
        val handoverInfo = CBORObject.NewArray()
        handoverInfo.Add(CBORObject.FromObject(clientId))
        handoverInfo.Add(CBORObject.FromObject(nonce))
        handoverInfo.Add(
            if (verifierJwkThumbprint != null) CBORObject.FromObject(verifierJwkThumbprint) else CBORObject.Null
        )
        handoverInfo.Add(CBORObject.FromObject(responseUri))
        val handoverHash = sha256(handoverInfo.EncodeToBytes())

        val handover = CBORObject.NewArray()
        handover.Add(CBORObject.FromObject("OpenID4VPHandover"))
        handover.Add(CBORObject.FromObject(handoverHash))

        val sessionTranscript = CBORObject.NewArray()
        sessionTranscript.Add(CBORObject.Null)
        sessionTranscript.Add(CBORObject.Null)
        sessionTranscript.Add(handover)
        return sessionTranscript.EncodeToBytes()
    }

    /**
     * Build the OpenID4VPDCAPIHandover session transcript per OID4VP 1.0
     * Appendix B.2.6 (Digital Credentials API).
     *
     * SessionTranscript = [
     *   null,  // reserved
     *   null,  // reserved
     *   [
     *     "OpenID4VPDCAPIHandover",
     *     SHA-256([origin, nonce, encryptionPublicJwkThumbprint])
     *   ]
     * ]
     *
     * Unlike [buildSessionTranscript] (the redirect flow's OpenID4VPHandover),
     * there is no clientId or responseUri here - the handover binds to the
     * browser-verified origin instead, since the response never travels over
     * HTTP to a responseUri.
     */
    private fun buildDCAPISessionTranscript(
        origin: String,
        nonce: String,
        encryptionPublicJwkThumbprint: String?,
    ): ByteArray {
        val handoverInfo = CBORObject.NewArray()
        handoverInfo.Add(CBORObject.FromObject(origin))
        handoverInfo.Add(CBORObject.FromObject(nonce))
        handoverInfo.Add(
            if (encryptionPublicJwkThumbprint != null) {
                CBORObject.FromObject(encryptionPublicJwkThumbprint)
            } else {
                CBORObject.Null
            }
        )
        val handoverHash = sha256(handoverInfo.EncodeToBytes())

        val handover = CBORObject.NewArray()
        handover.Add(CBORObject.FromObject("OpenID4VPDCAPIHandover"))
        handover.Add(CBORObject.FromObject(handoverHash))

        val sessionTranscript = CBORObject.NewArray()
        sessionTranscript.Add(CBORObject.Null)
        sessionTranscript.Add(CBORObject.Null)
        sessionTranscript.Add(handover)
        return sessionTranscript.EncodeToBytes()
    }

    /** DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, DocType] */
    private fun buildDeviceAuthentication(docType: String, sessionTranscript: ByteArray): ByteArray {
        // sessionTranscript is already CBOR-encoded; decode it back to embed
        // as a nested CBOR item rather than a byte string.
        val deviceAuth = CBORObject.NewArray()
        deviceAuth.Add(CBORObject.FromObject("DeviceAuthentication"))
        deviceAuth.Add(CBORObject.DecodeFromBytes(sessionTranscript))
        deviceAuth.Add(CBORObject.FromObject(docType))
        return deviceAuth.EncodeToBytes()
    }

    /**
     * Assemble the final DeviceResponse CBOR structure.
     *
     * DeviceResponse = { "version": "1.0", "documents": [Document], "status": 0 }
     * Document = { "docType", "issuerSigned" (filtered), "deviceSigned" }
     */
    private fun assembleFinalResponse(document: org.siros.sdk.credentials.mdoc.DocumentMdoc, coseSign1: CBORObject): ByteArray {
        val documentObj = MdocCbor.encodeDocument(document)

        val deviceSignatureMap = CBORObject.NewMap()
        deviceSignatureMap["deviceSignature"] = coseSign1
        val deviceSignedMap = CBORObject.NewMap()
        deviceSignedMap["nameSpaces"] = CBORObject.FromObjectAndTag(CBORObject.NewMap().EncodeToBytes(), 24)
        deviceSignedMap["deviceAuth"] = deviceSignatureMap
        documentObj["deviceSigned"] = deviceSignedMap

        val documentsArray = CBORObject.NewArray()
        documentsArray.Add(documentObj)

        val response = CBORObject.NewMap()
        response["version"] = CBORObject.FromObject("1.0")
        response["documents"] = documentsArray
        response["status"] = CBORObject.FromObject(0)
        return response.EncodeToBytes()
    }

    private fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)
}
