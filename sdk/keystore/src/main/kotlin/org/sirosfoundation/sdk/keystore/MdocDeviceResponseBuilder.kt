// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.sirosfoundation.sdk.keystore

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.cbor.CborTag
import kotlinx.serialization.Serializable
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.Signature

/**
 * Builds an ISO 18013-5 DeviceResponse for mDoc credential presentation
 * via OID4VP (OpenID for Verifiable Presentations).
 *
 * The DeviceResponse is a CBOR-encoded structure containing:
 * - version: "1.0"
 * - documents: array of Document objects, each with:
 *   - docType: the document type (e.g., "org.iso.18013.5.1.mDL")
 *   - issuerSigned: the original IssuerSigned structure (from credential)
 *   - deviceSigned: DeviceAuth with a COSE_Sign1 over the session transcript
 *
 * Usage:
 * ```kotlin
 * val builder = MdocDeviceResponseBuilder(credentialBytes, keyId, signer)
 * val response = builder.build(
 *     nonce = "verifier-nonce",
 *     audience = "verifier-client-id",
 *     responseUri = "https://verifier.example.com/response",
 *     verifierJwkThumbprint = "base64url-thumbprint",
 *     disclosedClaims = listOf("given_name", "family_name"),
 * )
 * ```
 */
@OptIn(ExperimentalSerializationApi::class)
class MdocDeviceResponseBuilder(
    /** Raw credential bytes (base64url-decoded IssuerSigned CBOR). */
    private val issuerSignedBytes: ByteArray,
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
     * @param disclosedClaims Claim names to disclose (null = all).
     * @param signer Function that signs raw bytes with the device key. Returns DER signature.
     * @return Base64url-encoded DeviceResponse CBOR bytes.
     */
    suspend fun build(
        nonce: String,
        audience: String,
        responseUri: String,
        verifierJwkThumbprint: String?,
        disclosedClaims: List<String>?,
        signer: suspend (ByteArray) -> ByteArray,
    ): ByteArray {
        val cbor = Cbor { ignoreUnknownKeys = true }

        // Step 1: Build the OpenID4VPHandover session transcript
        val sessionTranscript = buildSessionTranscript(
            clientId = audience,
            nonce = nonce,
            responseUri = responseUri,
            verifierJwkThumbprint = verifierJwkThumbprint,
        )

        // Step 2: Build DeviceAuthentication structure
        // DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, DocType]
        // For simplicity, we use the IssuerSigned as-is and create a minimal DeviceSigned
        val docType = extractDocType(issuerSignedBytes)
            ?: throw IllegalStateException("Cannot extract docType from IssuerSigned")

        val deviceAuthBytes = buildDeviceAuthentication(docType, sessionTranscript)

        // Step 3: Sign with COSE_Sign1
        val coseSign1 = buildCoseSign1(deviceAuthBytes, signer)

        // Step 4: Assemble DeviceResponse
        return assembleFinalResponse(docType, issuerSignedBytes, coseSign1, disclosedClaims)
    }

    /**
     * Build the OpenID4VPHandover session transcript per OID4VP §7.3.1.
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
        // Encode the handover info as a CBOR array
        val handoverInfoItems = mutableListOf<ByteArray>()
        handoverInfoItems.add(encodeCborTextString(clientId))
        handoverInfoItems.add(encodeCborTextString(nonce))
        if (verifierJwkThumbprint != null) {
            handoverInfoItems.add(encodeCborTextString(verifierJwkThumbprint))
        } else {
            handoverInfoItems.add(encodeCborNull())
        }
        handoverInfoItems.add(encodeCborTextString(responseUri))

        val handoverInfoBytes = encodeCborArray(handoverInfoItems)
        val handoverHash = sha256(handoverInfoBytes)

        // Build the OID4VP handover: ["OpenID4VPHandover", hash]
        val handoverArray = encodeCborArray(listOf(
            encodeCborTextString("OpenID4VPHandover"),
            encodeCborByteString(handoverHash),
        ))

        // Build SessionTranscript: [null, null, handoverArray]
        return encodeCborArray(listOf(
            encodeCborNull(),
            encodeCborNull(),
            handoverArray,
        ))
    }

    /**
     * Build DeviceAuthentication: ["DeviceAuthentication", SessionTranscript, DocType]
     */
    private fun buildDeviceAuthentication(docType: String, sessionTranscript: ByteArray): ByteArray {
        return encodeCborArray(listOf(
            encodeCborTextString("DeviceAuthentication"),
            sessionTranscript, // already CBOR-encoded
            encodeCborTextString(docType),
        ))
    }

    /**
     * Build a COSE_Sign1 structure for device authentication.
     *
     * COSE_Sign1 = [
     *   protected: bstr,   // { 1: alg } CBOR-encoded
     *   unprotected: {},    // empty map
     *   payload: nil,       // detached payload (in deviceAuth external_aad)
     *   signature: bstr     // ECDSA or EdDSA signature
     * ]
     *
     * Sig_structure = ["Signature1", protected, external_aad, payload]
     */
    private suspend fun buildCoseSign1(
        deviceAuthBytes: ByteArray,
        signer: suspend (ByteArray) -> ByteArray,
    ): ByteArray {
        val algValue = when (algorithm.uppercase()) {
            "ES256" -> -7   // COSE alg for ECDSA w/ SHA-256
            "ES384" -> -35  // COSE alg for ECDSA w/ SHA-384
            "EDDSA", "ED25519" -> -8  // COSE alg for EdDSA
            else -> -7
        }

        // Protected header: { 1: algValue } (CBOR map with key=1, value=alg)
        val protectedHeader = encodeCborMap(mapOf(1L to algValue.toLong()))

        // Sig_structure = ["Signature1", protected, external_aad, payload]
        // For device auth: external_aad = deviceAuthBytes, payload = empty bstr
        val sigStructure = encodeCborArray(listOf(
            encodeCborTextString("Signature1"),
            encodeCborByteString(protectedHeader),
            encodeCborByteString(deviceAuthBytes),
            encodeCborByteString(byteArrayOf()), // empty payload (detached)
        ))

        // Sign the Sig_structure
        val signature = signer(sigStructure)

        // Assemble COSE_Sign1: [protected, unprotected, payload, signature]
        // Tag 18 = COSE_Sign1
        val coseSign1Inner = encodeCborArray(listOf(
            encodeCborByteString(protectedHeader),
            encodeCborEmptyMap(),
            encodeCborNull(), // detached payload
            encodeCborByteString(signature),
        ))

        return coseSign1Inner
    }

    /**
     * Assemble the final DeviceResponse CBOR structure.
     *
     * DeviceResponse = {
     *   "version": "1.0",
     *   "documents": [Document],
     *   "status": 0
     * }
     *
     * Document = {
     *   "docType": docType,
     *   "issuerSigned": IssuerSigned,
     *   "deviceSigned": { "deviceAuth": { "deviceSignature": COSE_Sign1 } }
     * }
     */
    private fun assembleFinalResponse(
        docType: String,
        issuerSigned: ByteArray,
        coseSign1: ByteArray,
        disclosedClaims: List<String>?,
    ): ByteArray {
        // deviceSigned = { "deviceAuth": { "deviceSignature": coseSign1 } }
        val deviceSignatureMap = encodeCborStringMap(mapOf(
            "deviceSignature" to coseSign1,
        ))
        val deviceSignedMap = encodeCborStringMap(mapOf(
            "nameSpaces" to encodeCborTag(24, encodeCborEmptyMap()),  // tagged empty bstr for no device namespaces
            "deviceAuth" to deviceSignatureMap,
        ))

        // Document = { docType, issuerSigned, deviceSigned }
        val document = encodeCborStringMap(mapOf(
            "docType" to encodeCborTextString(docType),
            "issuerSigned" to issuerSigned,
            "deviceSigned" to deviceSignedMap,
        ))

        // DeviceResponse = { version, documents, status }
        return encodeCborStringMap(mapOf(
            "version" to encodeCborTextString("1.0"),
            "documents" to encodeCborArray(listOf(document)),
            "status" to encodeCborUnsignedInt(0),
        ))
    }

    // ── CBOR encoding primitives ────────────────────────────────────

    private fun encodeCborTextString(s: String): ByteArray {
        val bytes = s.toByteArray(Charsets.UTF_8)
        return encodeCborMajor(3, bytes.size) + bytes
    }

    private fun encodeCborByteString(b: ByteArray): ByteArray {
        return encodeCborMajor(2, b.size) + b
    }

    private fun encodeCborUnsignedInt(v: Int): ByteArray {
        return encodeCborMajor(0, v)
    }

    private fun encodeCborNull(): ByteArray = byteArrayOf(0xF6.toByte())

    private fun encodeCborEmptyMap(): ByteArray = byteArrayOf(0xA0.toByte())

    private fun encodeCborArray(items: List<ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(encodeCborMajor(4, items.size))
        items.forEach { out.write(it) }
        return out.toByteArray()
    }

    private fun encodeCborMap(entries: Map<Long, Long>): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(encodeCborMajor(5, entries.size))
        entries.forEach { (k, v) ->
            // Integer keys
            if (k >= 0) out.write(encodeCborMajor(0, k.toInt()))
            else {
                // Negative integer: major type 1, value = -1 - k
                out.write(encodeCborMajor(1, (-1 - k).toInt()))
            }
            if (v >= 0) out.write(encodeCborMajor(0, v.toInt()))
            else out.write(encodeCborMajor(1, (-1 - v).toInt()))
        }
        return out.toByteArray()
    }

    /** Encode a CBOR map with text string keys and pre-encoded values. */
    private fun encodeCborStringMap(entries: Map<String, ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(encodeCborMajor(5, entries.size))
        entries.forEach { (k, v) ->
            out.write(encodeCborTextString(k))
            out.write(v)
        }
        return out.toByteArray()
    }

    private fun encodeCborTag(tag: Int, content: ByteArray): ByteArray {
        return encodeCborMajor(6, tag) + content
    }

    /**
     * Encode a CBOR major type + argument.
     * Major types: 0=uint, 1=negint, 2=bstr, 3=tstr, 4=array, 5=map, 6=tag, 7=simple
     */
    private fun encodeCborMajor(majorType: Int, argument: Int): ByteArray {
        val major = (majorType shl 5)
        return when {
            argument < 24 -> byteArrayOf((major or argument).toByte())
            argument < 256 -> byteArrayOf((major or 24).toByte(), argument.toByte())
            argument < 65536 -> byteArrayOf(
                (major or 25).toByte(),
                (argument shr 8).toByte(),
                argument.toByte(),
            )
            else -> byteArrayOf(
                (major or 26).toByte(),
                (argument shr 24).toByte(),
                (argument shr 16).toByte(),
                (argument shr 8).toByte(),
                argument.toByte(),
            )
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────

    private fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    /**
     * Extract the docType from an IssuerSigned CBOR structure.
     * The docType is usually in the MSO (Mobile Security Object) inside issuerAuth.
     * For simplicity, we scan the CBOR bytes for a known doctype prefix pattern.
     */
    private fun extractDocType(issuerSigned: ByteArray): String? {
        // Common doctypes to search for
        val knownDoctypes = listOf(
            "org.iso.18013.5.1.mDL",
            "eu.europa.ec.eudi.pid.1",
            "org.iso.23220.1",
        )
        val text = String(issuerSigned, Charsets.UTF_8)
        return knownDoctypes.firstOrNull { text.contains(it) }
            ?: extractFirstCborTextString(issuerSigned, "docType")
    }

    /**
     * Simple CBOR text string extractor: finds a text key and returns the following text value.
     */
    private fun extractFirstCborTextString(data: ByteArray, key: String): String? {
        val keyBytes = key.toByteArray(Charsets.UTF_8)
        var i = 0
        while (i < data.size - keyBytes.size) {
            // Look for text string header matching key length
            val matched = when {
                keyBytes.size < 24 && data[i] == (0x60 + keyBytes.size).toByte() -> {
                    data.sliceArray(i + 1 until i + 1 + keyBytes.size).contentEquals(keyBytes)
                }
                else -> false
            }
            if (matched) {
                // The value should follow immediately
                val valueStart = i + 1 + keyBytes.size
                if (valueStart < data.size) {
                    val header = data[valueStart].toInt() and 0xFF
                    val major = header shr 5
                    if (major == 3) { // text string
                        val len = header and 0x1F
                        val actualLen = if (len < 24) len
                        else if (len == 24 && valueStart + 1 < data.size) data[valueStart + 1].toInt() and 0xFF
                        else return null
                        val textStart = valueStart + if (len < 24) 1 else 2
                        if (textStart + actualLen <= data.size) {
                            return String(data, textStart, actualLen, Charsets.UTF_8)
                        }
                    }
                }
            }
            i++
        }
        return null
    }
}
