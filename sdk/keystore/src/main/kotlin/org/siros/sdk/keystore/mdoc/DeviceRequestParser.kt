// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore.mdoc

import com.upokecenter.cbor.CBORObject
import com.upokecenter.cbor.CBORType

/**
 * Parses an ISO 18013-5 §8.3.2.1.2.1/§8.3.2.1.2.2 `DeviceRequest`, decrypted
 * from an incoming proximity `SessionEstablishment`/`SessionData` message
 * (see [ProximitySessionCrypto], [ProximitySessionMessages]).
 * ```
 * DeviceRequest = { "version": tstr, "docRequests": [DocRequest] }
 * DocRequest = { "itemsRequest": ItemsRequestBytes, ? "readerAuth": ReaderAuth }
 * ItemsRequestBytes = #6.24(bstr .cbor ItemsRequest)
 * ItemsRequest = { "docType": tstr, "nameSpaces": { tstr => { tstr => bool } } }
 * ```
 * `readerAuth` (mdoc reader authentication, §9.1.4) is parsed here (the
 * bare COSE_Sign1 array - `ReaderAuth = COSE_Sign1`, confirmed untagged
 * from the base spec's own worked example's diagnostic notation) but not
 * verified in this class - see [MdocCose.verify1]/[MdocCose.extractX5Chain]
 * for the signature/x5chain half and RICAL trust evaluation (go-trust's
 * `mdocrical` registry, or a local fallback) for the trust-decision half,
 * both driven from the wallet layer that has the session transcript this
 * parser doesn't.
 */
object DeviceRequestParser {

    /** One requested document: its type, and the namespace/element-identifier pairs asked for. */
    data class DocRequest(
        val docType: String,
        /** Namespace -> requested element identifiers (the reader's per-element `IntentToRetain` bit is ignored - every listed identifier is being requested regardless of its value). */
        val requestedItems: Map<String, List<String>>,
        /** The reader's `readerAuth` COSE_Sign1 (bare 4-element array), if the reader sent one - null for readers that don't participate in reader authentication (it's optional per §9.1.4). */
        val readerAuth: CBORObject? = null,
        /** The exact tag-24-wrapped `itemsRequest` CBOR bytes as they appeared on the wire - needed verbatim (not re-encoded) to reconstruct `ReaderAuthenticationBytes` via [MdocCose.buildReaderAuthenticationBytes]. */
        val itemsRequestTaggedBytes: ByteArray = ByteArray(0),
    ) {
        /** Flattened element identifiers across all namespaces - the shape [MdocDeviceResponseBuilder]'s `disclosedClaims` expects. */
        fun disclosedClaims(): List<String> = requestedItems.values.flatten()
    }

    fun parse(deviceRequestBytes: ByteArray): List<DocRequest> {
        val request = CBORObject.DecodeFromBytes(deviceRequestBytes)
        val docRequestsArray = request[CBORObject.FromObject("docRequests")]
            ?: throw IllegalArgumentException("DeviceRequest missing docRequests")
        if (docRequestsArray.type != CBORType.Array) {
            throw IllegalArgumentException("DeviceRequest.docRequests must be an array, was ${docRequestsArray.type}")
        }

        return (0 until docRequestsArray.size()).map { i ->
            val docRequest = docRequestsArray[i]
            val itemsRequestTagged = docRequest[CBORObject.FromObject("itemsRequest")]
                ?: throw IllegalArgumentException("DocRequest missing itemsRequest")
            // §8.3.2.1.2.1: ItemsRequestBytes = #6.24(bstr .cbor ItemsRequest) -
            // a reader sending an untagged or non-byte-string value should fail
            // here with a clear message, not inside UntagOne()/GetByteString().
            if (!itemsRequestTagged.HasOneTag(24) || itemsRequestTagged.type != CBORType.ByteString) {
                throw IllegalArgumentException("DocRequest.itemsRequest must be tag-24-wrapped (#6.24 ItemsRequest)")
            }
            val itemsRequest = CBORObject.DecodeFromBytes(itemsRequestTagged.UntagOne().GetByteString())

            val docType = (itemsRequest[CBORObject.FromObject("docType")]
                ?: throw IllegalArgumentException("ItemsRequest missing docType")).AsString()
            val nameSpacesObj = itemsRequest[CBORObject.FromObject("nameSpaces")]
                ?: throw IllegalArgumentException("ItemsRequest missing nameSpaces")
            val requestedItems = linkedMapOf<String, List<String>>()
            for (nsKey in nameSpacesObj.keys) {
                val elementsObj = nameSpacesObj[nsKey]
                val elementIds = elementsObj.keys.map { it.AsString() }
                requestedItems[nsKey.AsString()] = elementIds
            }

            // readerAuth = COSE_Sign1 (bare array, confirmed untagged from
            // ISO 18013-5:2021's own worked example's diagnostic notation) -
            // optional per §9.1.4, so a reader that doesn't participate in
            // reader authentication is not an error.
            val readerAuth = docRequest[CBORObject.FromObject("readerAuth")]

            DocRequest(
                docType = docType,
                requestedItems = requestedItems,
                readerAuth = readerAuth,
                itemsRequestTaggedBytes = itemsRequestTagged.EncodeToBytes(),
            )
        }
    }
}
