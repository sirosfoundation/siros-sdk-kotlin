// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore.mdoc

import com.upokecenter.cbor.CBORObject

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
 * `readerAuth` (mdoc reader authentication, §9.1.4) is intentionally not
 * parsed or verified here - see the proximity plan's Phase 3.5, deferred
 * until after the Tier 0 BLE transport itself is validated.
 */
object DeviceRequestParser {

    /** One requested document: its type, and the namespace/element-identifier pairs asked for. */
    data class DocRequest(
        val docType: String,
        /** Namespace -> requested element identifiers (the reader's per-element `IntentToRetain` bit is ignored - every listed identifier is being requested regardless of its value). */
        val requestedItems: Map<String, List<String>>,
    ) {
        /** Flattened element identifiers across all namespaces - the shape [MdocDeviceResponseBuilder]'s `disclosedClaims` expects. */
        fun disclosedClaims(): List<String> = requestedItems.values.flatten()
    }

    fun parse(deviceRequestBytes: ByteArray): List<DocRequest> {
        val request = CBORObject.DecodeFromBytes(deviceRequestBytes)
        val docRequestsArray = request[CBORObject.FromObject("docRequests")]
            ?: throw IllegalArgumentException("DeviceRequest missing docRequests")

        return (0 until docRequestsArray.size()).map { i ->
            val docRequest = docRequestsArray[i]
            val itemsRequestTagged = docRequest[CBORObject.FromObject("itemsRequest")]
                ?: throw IllegalArgumentException("DocRequest missing itemsRequest")
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
            DocRequest(docType = docType, requestedItems = requestedItems)
        }
    }
}
