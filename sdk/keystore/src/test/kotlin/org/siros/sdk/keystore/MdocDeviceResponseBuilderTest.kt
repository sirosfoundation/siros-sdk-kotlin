// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import com.upokecenter.cbor.CBORObject
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

/**
 * Tests for [MdocDeviceResponseBuilder] against a hand-built, synthetic
 * DeviceResponse-shaped credential envelope - mirroring the exact stored
 * shape confirmed via `sirosfoundation/wallet-frontend#191`
 * (`{documents: [{docType, issuerSigned: {nameSpaces, issuerAuth}}], ...}`,
 * with each namespace item tag-24-wrapped) - since no real signed-mdoc test
 * vectors with matching digests are available locally.
 */
class MdocDeviceResponseBuilderTest {

    private val docType = "org.iso.18013.5.1.mDL"
    private val namespace = "org.iso.18013.5.1"

    /** Build a tag-24-wrapped IssuerSignedItem: {digestID, random, elementIdentifier, elementValue}. */
    private fun buildItem(digestId: Long, elementIdentifier: String, elementValue: String): CBORObject {
        val random = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val item = CBORObject.NewMap()
        item[CBORObject.FromObject("digestID")] = CBORObject.FromObject(digestId)
        item[CBORObject.FromObject("random")] = CBORObject.FromObject(random)
        item[CBORObject.FromObject("elementIdentifier")] = CBORObject.FromObject(elementIdentifier)
        item[CBORObject.FromObject("elementValue")] = CBORObject.FromObject(elementValue)
        return CBORObject.FromObjectAndTag(item.EncodeToBytes(), 24)
    }

    /** Build a synthetic stored-credential envelope: DeviceResponseMdoc{documents:[{docType, issuerSigned}]}. */
    private fun buildStoredCredential(): ByteArray {
        val familyNameItem = buildItem(0, "family_name", "Doe")
        val givenNameItem = buildItem(1, "given_name", "Jane")
        val issueDateItem = buildItem(2, "issue_date", "2020-01-01")

        val mdlNamespace = CBORObject.NewArray()
        mdlNamespace.Add(familyNameItem)
        mdlNamespace.Add(givenNameItem)
        mdlNamespace.Add(issueDateItem)

        val otherNamespaceItem = buildItem(0, "some_other_claim", "value")
        val otherNamespace = CBORObject.NewArray()
        otherNamespace.Add(otherNamespaceItem)

        val nameSpaces = CBORObject.NewMap()
        nameSpaces[CBORObject.FromObject(namespace)] = mdlNamespace
        nameSpaces[CBORObject.FromObject("com.example.other")] = otherNamespace

        // issuerAuth is opaque to the wallet - a placeholder 4-element array is enough.
        val issuerAuth = CBORObject.NewArray()
        issuerAuth.Add(CBORObject.FromObject(ByteArray(0)))
        issuerAuth.Add(CBORObject.NewMap())
        issuerAuth.Add(CBORObject.FromObject(ByteArray(0)))
        issuerAuth.Add(CBORObject.FromObject(ByteArray(0)))

        val issuerSigned = CBORObject.NewMap()
        issuerSigned[CBORObject.FromObject("nameSpaces")] = nameSpaces
        issuerSigned[CBORObject.FromObject("issuerAuth")] = issuerAuth

        val document = CBORObject.NewMap()
        document[CBORObject.FromObject("docType")] = CBORObject.FromObject(docType)
        document[CBORObject.FromObject("issuerSigned")] = issuerSigned

        val documents = CBORObject.NewArray()
        documents.Add(document)

        val envelope = CBORObject.NewMap()
        envelope[CBORObject.FromObject("documents")] = documents
        envelope[CBORObject.FromObject("status")] = CBORObject.FromObject(0)
        return envelope.EncodeToBytes()
    }

    @Test
    fun parseStoredCredential_unwrapsEnvelopeAndDecodesItems() {
        val bytes = buildStoredCredential()
        val document = org.siros.sdk.credentials.mdoc.MdocCbor.parseStoredCredential(bytes)

        assertEquals(docType, document.docType)
        assertEquals(2, document.issuerSigned.nameSpaces.size)

        val mdlItems = document.issuerSigned.nameSpaces.getValue(namespace)
        assertEquals(3, mdlItems.size)
        val familyName = mdlItems.first { it.item.elementIdentifier == "family_name" }
        assertEquals("Doe", familyName.item.elementValue.AsString())
        assertEquals(0L, familyName.item.digestId)
        assertEquals(16, familyName.item.random.size)
    }

    @Test
    fun build_selectiveDisclosure_filtersToDisclosedElementsOnly() = runTest {
        val credentialBytes = buildStoredCredential()
        val builder = MdocDeviceResponseBuilder(credentialBytes, algorithm = "ES256")

        var signedBytes: ByteArray? = null
        val response = builder.build(
            nonce = "test-nonce",
            audience = "https://verifier.example.com",
            responseUri = "https://verifier.example.com/response",
            verifierJwkThumbprint = "thumbprint-abc",
            disclosedClaims = listOf("family_name", "given_name"),
            signer = { data -> signedBytes = data; ByteArray(64) { it.toByte() } },
        )

        val decoded = CBORObject.DecodeFromBytes(response)
        assertEquals("1.0", decoded["version"].AsString())
        val documents = decoded["documents"]
        assertEquals(1, documents.size())
        val doc = documents[0]
        assertEquals(docType, doc["docType"].AsString())

        val nameSpaces = doc["issuerSigned"]["nameSpaces"]
        // com.example.other's only element wasn't disclosed - namespace must be dropped entirely.
        assertNull(nameSpaces[CBORObject.FromObject("com.example.other")])

        val mdlItems = nameSpaces[CBORObject.FromObject(namespace)]
        assertEquals(2, mdlItems.size())
        val disclosedIds = (0 until mdlItems.size()).map { i ->
            val tagged = mdlItems[i]
            val inner = CBORObject.DecodeFromBytes(tagged.UntagOne().GetByteString())
            inner["elementIdentifier"].AsString()
        }.toSet()
        assertEquals(setOf("family_name", "given_name"), disclosedIds)
        assertFalse("issue_date must not be disclosed", disclosedIds.contains("issue_date"))

        // issuerAuth must be passed through completely untouched.
        assertTrue(doc["issuerSigned"]["issuerAuth"].size() == 4)

        // Signer must have been invoked with a real Sig_structure, not garbage.
        assertTrue(signedBytes != null && signedBytes!!.isNotEmpty())
    }

    @Test
    fun build_nullDisclosedClaims_keepsAllNamespacesAndElements() = runTest {
        val credentialBytes = buildStoredCredential()
        val builder = MdocDeviceResponseBuilder(credentialBytes, algorithm = "ES256")

        val response = builder.build(
            nonce = "n",
            audience = "aud",
            responseUri = "https://verifier.example.com/response",
            verifierJwkThumbprint = null,
            disclosedClaims = null,
            signer = { ByteArray(64) },
        )

        val decoded = CBORObject.DecodeFromBytes(response)
        val nameSpaces = decoded["documents"][0]["issuerSigned"]["nameSpaces"]
        assertEquals(2, nameSpaces.size())
        assertEquals(3, nameSpaces[CBORObject.FromObject(namespace)].size())
    }

    @Test
    fun build_preservesOriginalTaggedBytesForDisclosedItems() = runTest {
        val credentialBytes = buildStoredCredential()
        val originalDocument = org.siros.sdk.credentials.mdoc.MdocCbor.parseStoredCredential(credentialBytes)
        val originalFamilyNameBytes = originalDocument.issuerSigned.nameSpaces.getValue(namespace)
            .first { it.item.elementIdentifier == "family_name" }.original.EncodeToBytes()

        val builder = MdocDeviceResponseBuilder(credentialBytes, algorithm = "ES256")
        val response = builder.build(
            nonce = "n",
            audience = "aud",
            responseUri = "https://verifier.example.com/response",
            verifierJwkThumbprint = null,
            disclosedClaims = listOf("family_name"),
            signer = { ByteArray(64) },
        )

        val decoded = CBORObject.DecodeFromBytes(response)
        val mdlItems = decoded["documents"][0]["issuerSigned"]["nameSpaces"][CBORObject.FromObject(namespace)]
        assertEquals(1, mdlItems.size())
        // Byte-for-byte identical to the original tag-24-wrapped item - never re-encoded.
        assertArrayEquals(originalFamilyNameBytes, mdlItems[0].EncodeToBytes())
    }

    @Test
    fun buildForDCAPI_selectiveDisclosure_filtersToDisclosedElementsOnly() = runTest {
        val credentialBytes = buildStoredCredential()
        val builder = MdocDeviceResponseBuilder(credentialBytes, algorithm = "ES256")

        var signedBytes: ByteArray? = null
        val response = builder.buildForDCAPI(
            nonce = "dc-api-nonce",
            origin = "https://relying-party.example",
            encryptionPublicJwkThumbprint = "enc-thumbprint",
            disclosedClaims = listOf("family_name", "given_name"),
            signer = { data -> signedBytes = data; ByteArray(64) { it.toByte() } },
        )

        val decoded = CBORObject.DecodeFromBytes(response)
        val doc = decoded["documents"][0]
        val nameSpaces = doc["issuerSigned"]["nameSpaces"]
        assertNull(nameSpaces[CBORObject.FromObject("com.example.other")])
        val mdlItems = nameSpaces[CBORObject.FromObject(namespace)]
        assertEquals(2, mdlItems.size())
        assertTrue(signedBytes != null && signedBytes!!.isNotEmpty())
    }

    @Test
    fun buildForDCAPI_sessionTranscriptUsesOpenID4VPDCAPIHandoverAndOrigin() = runTest {
        val credentialBytes = buildStoredCredential()
        val builder = MdocDeviceResponseBuilder(credentialBytes, algorithm = "ES256")

        // Recompute the expected handover hash independently from the raw
        // origin/nonce/thumbprint inputs, then confirm the DeviceAuthentication
        // Sig_structure fed to the signer embeds that exact SessionTranscript -
        // proves the transcript is built from {origin, nonce, thumbprint} via
        // the "OpenID4VPDCAPIHandover" name, not the redirect flow's
        // "OpenID4VPHandover"/clientId/responseUri shape.
        val origin = "https://relying-party.example"
        val nonce = "dc-api-nonce"
        // A realistic JWK.computeThumbprint().toString() value: base64url,
        // no padding, decoding to a 32-byte SHA-256 digest.
        val thumbprintBytes = ByteArray(32) { it.toByte() }
        val thumbprint = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(thumbprintBytes)

        val handoverInfo = CBORObject.NewArray()
        handoverInfo.Add(CBORObject.FromObject(origin))
        handoverInfo.Add(CBORObject.FromObject(nonce))
        // Per OpenID4VP 1.0 (#dc_api), this element MUST be a CBOR Byte
        // String of the raw thumbprint digest - not a text string of its
        // base64url form (a real bug: encoding it as text made the wallet's
        // handover hash disagree with any spec-conformant verifier's).
        handoverInfo.Add(CBORObject.FromObject(thumbprintBytes))
        val expectedHash = java.security.MessageDigest.getInstance("SHA-256")
            .digest(handoverInfo.EncodeToBytes())

        var signingInput: ByteArray? = null
        builder.buildForDCAPI(
            nonce = nonce,
            origin = origin,
            encryptionPublicJwkThumbprint = thumbprint,
            disclosedClaims = null,
            signer = { data -> signingInput = data; ByteArray(64) },
        )

        // signingInput is the COSE Sig_structure (["Signature1", protectedHeader,
        // external_aad, payload]) built by MdocCose.sign1Detached, not the raw
        // DeviceAuthentication bytes directly - payload (index 3) IS those
        // bytes (external_aad, index 2, is empty - see MdocCose.sign1Detached's
        // doc comment on why the roles aren't the other way around). payload
        // is itself tag-24-wrapped (an "encoded CBOR data item") around the
        // actual 4-element DeviceAuthentication array - see
        // buildDeviceAuthentication's doc comment.
        val sigStructure = CBORObject.DecodeFromBytes(signingInput!!)
        assertEquals(0, sigStructure[2].GetByteString().size)
        val outerTag = CBORObject.DecodeFromBytes(sigStructure[3].GetByteString())
        val deviceAuth = CBORObject.DecodeFromBytes(outerTag.UntagOne().GetByteString())
        assertEquals("DeviceAuthentication", deviceAuth[0].AsString())
        val sessionTranscript = deviceAuth[1]
        assertTrue(sessionTranscript[0].isNull)
        assertTrue(sessionTranscript[1].isNull)
        val handover = sessionTranscript[2]
        assertEquals("OpenID4VPDCAPIHandover", handover[0].AsString())
        assertArrayEquals(expectedHash, handover[1].GetByteString())
    }

    @Test
    fun buildForDCAPI_nullEncryptionThumbprint_encodesAsCborNull() = runTest {
        val credentialBytes = buildStoredCredential()
        val builder = MdocDeviceResponseBuilder(credentialBytes, algorithm = "ES256")

        var signingInput: ByteArray? = null
        builder.buildForDCAPI(
            nonce = "n",
            origin = "https://relying-party.example",
            encryptionPublicJwkThumbprint = null,
            disclosedClaims = null,
            signer = { data -> signingInput = data; ByteArray(64) },
        )

        // Unencrypted dc_api response mode has no verifier encryption key -
        // must not crash, and must encode the thumbprint slot as CBOR null.
        val sigStructure = CBORObject.DecodeFromBytes(signingInput!!)
        val outerTag = CBORObject.DecodeFromBytes(sigStructure[3].GetByteString())
        val deviceAuth = CBORObject.DecodeFromBytes(outerTag.UntagOne().GetByteString())
        val handover = deviceAuth[1][2]
        assertEquals("OpenID4VPDCAPIHandover", handover[0].AsString())
    }

    @Test
    fun build_unsupportedAlgorithm_throwsInsteadOfSilentlyDefaultingToEs256() = runTest {
        // `algorithm` here comes from a real signing key's own reported
        // algorithm (WscdKeystoreAdapter's `key.algorithm`) - silently
        // defaulting an unrecognized value to ES256 would put the wrong COSE
        // alg identifier in the protected header while the signature itself
        // was produced with a different algorithm.
        val credentialBytes = buildStoredCredential()
        val builder = MdocDeviceResponseBuilder(credentialBytes, algorithm = "RS256")

        var thrown: Throwable? = null
        try {
            builder.build(
                nonce = "n",
                audience = "https://verifier.example.com",
                responseUri = "https://verifier.example.com/response",
                verifierJwkThumbprint = null,
                disclosedClaims = null,
                signer = { ByteArray(64) },
            )
        } catch (e: Throwable) {
            thrown = e
        }
        assertTrue(thrown is IllegalArgumentException)
    }
}
