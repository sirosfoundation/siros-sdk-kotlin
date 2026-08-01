// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials.mdoc

import com.upokecenter.cbor.CBORObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.security.SecureRandom

/**
 * Tests for [MdocCbor.parseStoredCredential] against both stored-credential
 * shapes seen in practice:
 * - `sirosfoundation/vc`'s own DeviceResponse-shaped envelope (`{documents:
 *   [{docType, issuerSigned}], ...}`), confirmed via wallet-frontend#191.
 * - A bare `IssuerSigned` structure (`{nameSpaces, issuerAuth}`) with no
 *   enclosing envelope, confirmed against geneva2026.mdoc.online's OID4VCI
 *   conformance suite - docType has to come from the MSO embedded in
 *   issuerAuth instead of a `docType` field (IssuerSigned has none).
 */
class MdocCborTest {

    private fun buildItem(digestId: Long, elementIdentifier: String, elementValue: String): CBORObject {
        val random = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val item = CBORObject.NewMap()
        item[CBORObject.FromObject("digestID")] = CBORObject.FromObject(digestId)
        item[CBORObject.FromObject("random")] = CBORObject.FromObject(random)
        item[CBORObject.FromObject("elementIdentifier")] = CBORObject.FromObject(elementIdentifier)
        item[CBORObject.FromObject("elementValue")] = CBORObject.FromObject(elementValue)
        return CBORObject.FromObjectAndTag(item.EncodeToBytes(), 24)
    }

    private fun buildNameSpaces(namespace: String, docType: String): CBORObject {
        val items = CBORObject.NewArray()
        items.Add(buildItem(0, "family_name", "Doe"))
        items.Add(buildItem(1, "given_name", "Jane"))
        val nameSpaces = CBORObject.NewMap()
        nameSpaces[CBORObject.FromObject(namespace)] = items
        return nameSpaces
    }

    /**
     * Build a COSE_Sign1 array whose payload carries an MSO with `docType`,
     * matching the REAL wire encoding (ISO 18013-5 §9.1.2.4): the payload
     * slot is a `bstr` whose content decodes to a tag-24-wrapped bstr, which
     * itself decodes to the actual MSO map - two nested decode steps, not
     * one. (An earlier version of this fixture built the payload as an
     * in-memory tagged object directly instead of a real double-encoded
     * byte string, which matched a bug in the implementation instead of
     * catching it - confirmed broken against a real geneva2026.mdoc.online
     * credential.)
     */
    private fun buildIssuerAuth(docType: String): CBORObject {
        val mso = CBORObject.NewMap()
        mso[CBORObject.FromObject("docType")] = CBORObject.FromObject(docType)
        val taggedMsoBytes = CBORObject.FromObjectAndTag(mso.EncodeToBytes(), 24).EncodeToBytes()
        val payload = CBORObject.FromObject(taggedMsoBytes)

        val issuerAuth = CBORObject.NewArray()
        issuerAuth.Add(CBORObject.FromObject(ByteArray(0))) // protected headers (opaque to the wallet)
        issuerAuth.Add(CBORObject.NewMap()) // unprotected headers
        issuerAuth.Add(payload)
        issuerAuth.Add(CBORObject.FromObject(ByteArray(64))) // signature (opaque to the wallet)
        return issuerAuth
    }

    @Test
    fun parseStoredCredential_unwrapsDeviceResponseEnvelope() {
        val docType = "org.iso.18013.5.1.mDL"
        val namespace = "org.iso.18013.5.1"

        val document = CBORObject.NewMap()
        document[CBORObject.FromObject("docType")] = CBORObject.FromObject(docType)
        val issuerSigned = CBORObject.NewMap()
        issuerSigned[CBORObject.FromObject("nameSpaces")] = buildNameSpaces(namespace, docType)
        issuerSigned[CBORObject.FromObject("issuerAuth")] = buildIssuerAuth(docType)
        document[CBORObject.FromObject("issuerSigned")] = issuerSigned

        val documents = CBORObject.NewArray()
        documents.Add(document)
        val envelope = CBORObject.NewMap()
        envelope[CBORObject.FromObject("documents")] = documents
        envelope[CBORObject.FromObject("status")] = CBORObject.FromObject(0)

        val parsed = MdocCbor.parseStoredCredential(envelope.EncodeToBytes())

        assertEquals(docType, parsed.docType)
        assertEquals(1, parsed.issuerSigned.nameSpaces.size)
        val familyName = parsed.issuerSigned.nameSpaces.getValue(namespace)
            .first { it.item.elementIdentifier == "family_name" }
        assertEquals("Doe", familyName.item.elementValue.AsString())
    }

    @Test
    fun parseStoredCredential_acceptsBareIssuerSignedStructure_derivingDocTypeFromMso() {
        // No enclosing {documents: [...]} envelope - the exact shape
        // geneva2026.mdoc.online's OID4VCI credential response returns for
        // ANY docType it issues, not just mDL (docType is read from the MSO
        // dynamically, never hardcoded), confirmed via its conformance
        // report's "Send Credential Response" section.
        val docType = "eu.europa.ec.eudi.pid.1"
        val namespace = "eu.europa.ec.eudi.pid.1"

        val bareIssuerSigned = CBORObject.NewMap()
        bareIssuerSigned[CBORObject.FromObject("nameSpaces")] = buildNameSpaces(namespace, docType)
        bareIssuerSigned[CBORObject.FromObject("issuerAuth")] = buildIssuerAuth(docType)

        val parsed = MdocCbor.parseStoredCredential(bareIssuerSigned.EncodeToBytes())

        assertEquals(docType, parsed.docType)
        assertEquals(1, parsed.issuerSigned.nameSpaces.size)
        val givenName = parsed.issuerSigned.nameSpaces.getValue(namespace)
            .first { it.item.elementIdentifier == "given_name" }
        assertEquals("Jane", givenName.item.elementValue.AsString())
    }

    @Test
    fun parseStoredCredential_bareIssuerSigned_worksForAnyDocType() {
        // A second, different docType - proves docType extraction isn't
        // accidentally coupled to mDL specifically.
        val docType = "org.iso.23220.photoid.1"
        val namespace = "org.iso.23220.1"

        val bareIssuerSigned = CBORObject.NewMap()
        bareIssuerSigned[CBORObject.FromObject("nameSpaces")] = buildNameSpaces(namespace, docType)
        bareIssuerSigned[CBORObject.FromObject("issuerAuth")] = buildIssuerAuth(docType)

        val parsed = MdocCbor.parseStoredCredential(bareIssuerSigned.EncodeToBytes())

        assertEquals(docType, parsed.docType)
    }

    @Test
    fun parseStoredCredential_throwsWhenNeitherShapeMatches() {
        val garbage = CBORObject.NewMap()
        garbage[CBORObject.FromObject("something_else")] = CBORObject.FromObject("value")

        assertThrows(IllegalArgumentException::class.java) {
            MdocCbor.parseStoredCredential(garbage.EncodeToBytes())
        }
    }
}
