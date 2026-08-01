// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials.mdoc

import com.upokecenter.cbor.CBORObject
import com.upokecenter.cbor.CBORType

/**
 * Minimal, holder-side ISO 18013-5 mdoc data model and CBOR parsing.
 *
 * Mirrors the shapes in `sirosfoundation/vc`'s `pkg/mdoc` (DeviceResponseMdoc/
 * DocumentMdoc/IssuerSignedMdoc/IssuerSignedItem) closely enough to
 * interoperate, but scoped to only what a WALLET (holder) needs: parsing a
 * stored credential's envelope for claim display and selecting a subset of
 * disclosed elements for a presentation - not MSO digest verification,
 * DeviceRequest building, or any other verifier-side concern (those live in
 * the issuer/verifier).
 *
 * Lives in `sdk/credentials` (not `sdk/keystore`) since both the credential
 * display pipeline (`CredentialUtils`, this module) and the presentation
 * builder (`MdocDeviceResponseBuilder`, `sdk/keystore`, which depends on this
 * module) need it.
 *
 * A stored mdoc credential's raw bytes can be either of two shapes,
 * depending on the issuer:
 * - A full `DeviceResponseMdoc`-shaped envelope (`{documents: [{docType,
 *   issuerSigned}], ...}`) - `sirosfoundation/vc`'s own issuer convention,
 *   confirmed via `sirosfoundation/wallet-frontend#191`.
 * - A bare `IssuerSigned` structure (`{nameSpaces, issuerAuth}`) directly,
 *   per OID4VCI's mso_mdoc credential response as issued by real-world/
 *   interop issuers (confirmed against geneva2026.mdoc.online's conformance
 *   suite) - no outer envelope, and no docType field of its own (ISO
 *   18013-5's IssuerSigned has none); docType is read from the MSO embedded
 *   in issuerAuth's COSE_Sign1 payload instead.
 *
 * [MdocCbor.parseStoredCredential] detects and handles both.
 */

/** A single decoded ISO 18013-5 data element (an unwrapped `IssuerSignedItem`). */
data class IssuerSignedItem(
    val digestId: Long,
    val random: ByteArray,
    val elementIdentifier: String,
    val elementValue: CBORObject,
)

/**
 * One namespace's disclosed items: each entry pairs the decoded
 * [IssuerSignedItem] (for filtering/reading) with the ORIGINAL tag-24-wrapped
 * [CBORObject] bytes it came from. Selective disclosure must preserve these
 * original bytes verbatim for any item that's kept - the MSO's digests were
 * computed over the exact tagged CBOR encoding, so re-encoding from the
 * parsed model would invalidate them. Disclosure only ever *selects a
 * subset* of already-digested items; it never re-hashes.
 */
data class NamespaceItem(val item: IssuerSignedItem, val original: CBORObject)

/**
 * The IssuerSigned portion of one mdoc document: namespace -> disclosed
 * items, plus the untouched `issuerAuth` (COSE_Sign1 over the MSO). The
 * wallet never parses or modifies `issuerAuth` - it's opaque, passed through
 * as-is in any built DeviceResponse.
 */
data class IssuerSignedMdoc(
    val nameSpaces: Map<String, List<NamespaceItem>>,
    val issuerAuth: CBORObject,
)

data class DocumentMdoc(
    val docType: String,
    val issuerSigned: IssuerSignedMdoc,
)

object MdocCbor {

    /**
     * Parse a stored mdoc credential's raw bytes and return its first
     * document - see the file-level doc comment for the two shapes handled.
     */
    fun parseStoredCredential(bytes: ByteArray): DocumentMdoc {
        val root = CBORObject.DecodeFromBytes(bytes)
        val documents = root["documents"]
        if (documents != null && documents.type == CBORType.Array && documents.size() > 0) {
            return parseDocument(documents[0])
        }

        val nameSpacesObj = root["nameSpaces"]
        val issuerAuthObj = root["issuerAuth"]
        require(nameSpacesObj != null && issuerAuthObj != null) {
            "mdoc credential envelope missing documents[] (and not a bare IssuerSigned structure either)"
        }
        val docType = extractDocTypeFromIssuerAuth(issuerAuthObj)
        return DocumentMdoc(docType, parseIssuerSigned(nameSpacesObj, issuerAuthObj))
    }

    private fun parseDocument(doc: CBORObject): DocumentMdoc {
        val docType = doc["docType"]?.AsString()
            ?: throw IllegalArgumentException("mdoc document missing docType")
        val issuerSignedObj = doc["issuerSigned"]
            ?: throw IllegalArgumentException("mdoc document missing issuerSigned")
        val nameSpacesObj = issuerSignedObj["nameSpaces"]
            ?: throw IllegalArgumentException("issuerSigned missing nameSpaces")
        val issuerAuth = issuerSignedObj["issuerAuth"]
            ?: throw IllegalArgumentException("issuerSigned missing issuerAuth")
        return DocumentMdoc(docType, parseIssuerSigned(nameSpacesObj, issuerAuth))
    }

    private fun parseIssuerSigned(nameSpacesObj: CBORObject, issuerAuth: CBORObject): IssuerSignedMdoc {
        val nameSpaces = linkedMapOf<String, List<NamespaceItem>>()
        for (key in nameSpacesObj.keys) {
            val ns = key.AsString()
            val itemsArray = nameSpacesObj[key]
            val items = mutableListOf<NamespaceItem>()
            for (i in 0 until itemsArray.size()) {
                val tagged = itemsArray[i]
                items.add(NamespaceItem(parseIssuerSignedItem(tagged), tagged))
            }
            nameSpaces[ns] = items
        }
        return IssuerSignedMdoc(nameSpaces, issuerAuth)
    }

    /**
     * Extract `docType` from the MSO (MobileSecurityObject) embedded in a
     * bare IssuerSigned structure's `issuerAuth` COSE_Sign1 payload (index 2
     * of the 4-element array) - the only place docType is available when
     * there's no enclosing `{docType, issuerSigned}` document wrapper.
     */
    private fun extractDocTypeFromIssuerAuth(issuerAuth: CBORObject): String {
        require(issuerAuth.type == CBORType.Array && issuerAuth.size() >= 3) {
            "issuerAuth is not a COSE_Sign1 array"
        }
        val mso = decodeMsoFromPayload(issuerAuth[2])
        return mso["docType"]?.AsString()
            ?: throw IllegalArgumentException("MSO missing docType")
    }

    /**
     * Decode the MSO from a COSE_Sign1 `issuerAuth`'s payload slot.
     *
     * Per ISO 18013-5 §9.1.2.4, this slot is itself a `bstr` (COSE_Sign1's
     * payload is always a byte string) whose CONTENT decodes to
     * `MobileSecurityObjectBytes = #6.24(bstr .cbor MobileSecurityObject)` -
     * i.e. two nested CBOR decode steps are required: one to get from the
     * payload bytes to the tag-24 wrapper, and a second to unwrap it and
     * reach the actual MSO map. A single decode step (as this previously
     * did) yields the tag-24 wrapper itself, not the MSO - confirmed via a
     * real credential from geneva2026.mdoc.online's OID4VCI conformance
     * suite, which threw "Not an array or map" trying to read `docType` off
     * that wrapper. Also tolerates issuers that skip the tag-24 wrapper
     * entirely and emit the MSO map directly.
     */
    private fun decodeMsoFromPayload(payload: CBORObject): CBORObject {
        val outerBytes = payload.GetByteString()
        val decoded = CBORObject.DecodeFromBytes(outerBytes)
        return when {
            decoded.HasOneTag(24) -> CBORObject.DecodeFromBytes(decoded.UntagOne().GetByteString())
            decoded.type == CBORType.Map -> decoded
            decoded.type == CBORType.ByteString -> CBORObject.DecodeFromBytes(decoded.GetByteString())
            else -> throw IllegalArgumentException("unexpected MSO payload encoding")
        }
    }

    /** Unwrap a tag-24 (encoded-CBOR-data-item) bstr and decode the IssuerSignedItem map inside it. */
    private fun parseIssuerSignedItem(tagged: CBORObject): IssuerSignedItem {
        val innerBytes = if (tagged.HasOneTag(24)) {
            tagged.UntagOne().GetByteString()
        } else {
            // Tolerate an already-untagged byte string, in case an issuer omits the tag.
            tagged.GetByteString()
        }
        val item = CBORObject.DecodeFromBytes(innerBytes)
        return IssuerSignedItem(
            digestId = item["digestID"].AsInt64Value(),
            random = item["random"].GetByteString(),
            elementIdentifier = item["elementIdentifier"].AsString(),
            elementValue = item["elementValue"],
        )
    }

    /**
     * Re-encode a document (with possibly-filtered `nameSpaces`) back into
     * the `{docType, issuerSigned: {nameSpaces, issuerAuth}}` shape used
     * inside a DeviceResponse's `documents[]` array. Each kept namespace
     * item is emitted using its ORIGINAL tag-24-wrapped bytes (never
     * re-encoded from the parsed model) so MSO digests remain valid.
     */
    fun encodeDocument(doc: DocumentMdoc): CBORObject {
        val nameSpacesObj = CBORObject.NewMap()
        for ((ns, items) in doc.issuerSigned.nameSpaces) {
            val arr = CBORObject.NewArray()
            for (entry in items) {
                arr.Add(entry.original)
            }
            nameSpacesObj[ns] = arr
        }
        val issuerSignedObj = CBORObject.NewMap()
        issuerSignedObj["nameSpaces"] = nameSpacesObj
        issuerSignedObj["issuerAuth"] = doc.issuerSigned.issuerAuth

        val documentObj = CBORObject.NewMap()
        documentObj["docType"] = CBORObject.FromObject(doc.docType)
        documentObj["issuerSigned"] = issuerSignedObj
        return documentObj
    }
}
