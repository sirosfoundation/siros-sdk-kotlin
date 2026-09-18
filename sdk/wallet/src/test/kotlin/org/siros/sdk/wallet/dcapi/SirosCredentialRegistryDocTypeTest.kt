// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.dcapi

import com.upokecenter.cbor.CBORObject
import java.util.Base64
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.siros.sdk.credentials.CredentialMetadata
import org.siros.sdk.credentials.StoredCredential
import timber.log.Timber

/**
 * [SirosCredentialRegistry.docTypeFor], the docType every registered entry
 * carries.
 *
 * The mdoc parse it does is only meaningful for an mdoc: an SD-JWT's raw value
 * is a compact serialization, and its `.` separators are not base64url, so an
 * unguarded parse threw `IllegalArgumentException: Illegal base64 character 2e`
 * once per SD-JWT credential per refresh - caught and harmless, but logged at
 * warn with a full stack trace on every credential change and every flow
 * (issue #204). What the guard must NOT do is silence the warning for a
 * genuine mdoc that fails to parse, so that case is asserted too.
 */
class SirosCredentialRegistryDocTypeTest {

    private val logged = mutableListOf<Pair<Int, String>>()

    private val recorder = object : Timber.Tree() {
        override fun log(priority: Int, tag: String?, message: String, t: Throwable?) {
            logged += priority to message
        }
    }

    @Before
    fun plant() {
        Timber.plant(recorder)
    }

    @After
    fun uproot() {
        Timber.uproot(recorder)
        logged.clear()
    }

    /** A compact SD-JWT serialization: dot-separated, so not base64url as a whole. */
    private val sdJwtRaw =
        "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbS9waWQifQ.c2ln~WQ~"

    private val mdocDocType = "org.iso.18013.5.1.mDL"

    /** A synthetic mdoc credential's raw (base64url) bytes: a DeviceResponse-shaped envelope. */
    private fun mdocRaw(): String {
        val item = CBORObject.NewMap()
        item[CBORObject.FromObject("digestID")] = CBORObject.FromObject(0L)
        item[CBORObject.FromObject("random")] = CBORObject.FromObject(ByteArray(16))
        item[CBORObject.FromObject("elementIdentifier")] = CBORObject.FromObject("family_name")
        item[CBORObject.FromObject("elementValue")] = CBORObject.FromObject("Doe")

        val items = CBORObject.NewArray()
        items.Add(CBORObject.FromObjectAndTag(item.EncodeToBytes(), 24))

        val nameSpaces = CBORObject.NewMap()
        nameSpaces[CBORObject.FromObject("org.iso.18013.5.1")] = items

        val issuerAuth = CBORObject.NewArray()
        repeat(4) { issuerAuth.Add(CBORObject.FromObject(ByteArray(0))) }

        val issuerSigned = CBORObject.NewMap()
        issuerSigned[CBORObject.FromObject("nameSpaces")] = nameSpaces
        issuerSigned[CBORObject.FromObject("issuerAuth")] = issuerAuth

        val document = CBORObject.NewMap()
        document[CBORObject.FromObject("docType")] = CBORObject.FromObject(mdocDocType)
        document[CBORObject.FromObject("issuerSigned")] = issuerSigned

        val documents = CBORObject.NewArray()
        documents.Add(document)

        val envelope = CBORObject.NewMap()
        envelope[CBORObject.FromObject("documents")] = documents
        envelope[CBORObject.FromObject("status")] = CBORObject.FromObject(0)

        return Base64.getUrlEncoder().withoutPadding().encodeToString(envelope.EncodeToBytes())
    }

    private fun credential(format: String, raw: String, doctype: String? = null) = StoredCredential(
        id = 1L,
        batchId = 1L,
        instanceId = 0,
        format = format,
        raw = raw,
        metadata = doctype?.let { CredentialMetadata(doctype = it) },
    )

    @Test
    fun `an SD-JWT credential is never parsed as an mdoc and logs nothing`() {
        val docType = SirosCredentialRegistry.docTypeFor(credential("dc+sd-jwt", sdJwtRaw))

        // An SD-JWT has no docType, and no metadata supplied one.
        assertNull(docType)
        assertTrue("expected no log output, got $logged", logged.isEmpty())
    }

    @Test
    fun `a legacy vc+sd-jwt credential is not parsed as an mdoc either`() {
        val docType = SirosCredentialRegistry.docTypeFor(credential("vc+sd-jwt", sdJwtRaw))

        assertNull(docType)
        assertTrue("expected no log output, got $logged", logged.isEmpty())
    }

    @Test
    fun `an mdoc still resolves its docType from its own MSO, with no metadata`() {
        val docType = SirosCredentialRegistry.docTypeFor(credential("mso_mdoc", mdocRaw()))

        assertEquals(mdocDocType, docType)
        assertTrue("expected no log output, got $logged", logged.isEmpty())
    }

    @Test
    fun `a genuine mdoc that cannot be parsed still warns, and falls back to metadata`() {
        val docType = SirosCredentialRegistry.docTypeFor(
            credential("mso_mdoc", raw = "not base64url at all!", doctype = "org.iso.18013.5.1.mDL"),
        )

        assertEquals("org.iso.18013.5.1.mDL", docType)
        assertEquals(1, logged.size)
        assertEquals(android.util.Log.WARN, logged[0].first)
        assertTrue(logged[0].second.startsWith("Failed to parse mdoc credential"))
    }
}
