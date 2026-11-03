// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.mdoc.proximity

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.siros_verifier_core_ffi.FfiException
import uniffi.siros_verifier_core_ffi.Reader
import uniffi.siros_verifier_core_ffi.ReaderAuth
import uniffi.siros_verifier_core_ffi.ReaderAuthSigner
import uniffi.siros_verifier_core_ffi.RequestedDocument
import uniffi.siros_verifier_core_ffi.RequestedElement
import uniffi.siros_verifier_core_ffi.RequestedNamespace
import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64

/** Executes the production AAR on a real Android ABI; no vector-tests feature is used. */
@RunWith(AndroidJUnit4::class)
class ReaderAndroidTest {
    @Test
    fun productionReaderAndHostReaderAuthSignerRunOnAndroid() {
        val vector = JSONObject(asset("iso18013_annex_d5.json"))
        val certificate = CertificateFactory.getInstance("X.509").generateCertificate(
            ByteArrayInputStream(pem(asset("reader-test.crt"))),
        ) as X509Certificate
        val privateKey = KeyFactory.getInstance("EC").generatePrivate(
            PKCS8EncodedKeySpec(pem(asset("reader-test.key"))),
        )
        val signer = JcaReaderAuthSigner(privateKey)
        val auth = ReaderAuth(listOf(certificate.encoded), signer)
        val reader = Reader.startWithRole(
            hex(vector.getString("device_engagement")),
            hex(vector.getString("handover")),
            "test-mdoc-issuer",
        )
        try {
            val document = RequestedDocument(
                docType = "org.iso.18013.5.1.mDL",
                namespaces = listOf(
                    RequestedNamespace(
                        namespace = "org.iso.18013.5.1",
                        elements = listOf(RequestedElement("given_name", false)),
                    ),
                ),
                readerAuth = auth,
            )
            val message = reader.establishmentMessageFromDocuments(listOf(document))

            assertTrue(message.isNotEmpty())
            assertTrue(signer.signingInput.isNotEmpty())
        } finally {
            auth.close()
            reader.close()
        }
    }

    @Test
    fun invalidIssuerRoleIsRejectedOnAndroid() {
        val vector = JSONObject(asset("iso18013_annex_d5.json"))
        assertThrows(FfiException.Rejected::class.java) {
            Reader.startWithRole(
                hex(vector.getString("device_engagement")),
                hex(vector.getString("handover")),
                "  ",
            )
        }
    }

    private class JcaReaderAuthSigner(private val key: PrivateKey) : ReaderAuthSigner {
        var signingInput = byteArrayOf()
            private set

        override fun signEs256(data: ByteArray): ByteArray {
            signingInput = data
            val signature = Signature.getInstance("SHA256withECDSA").run {
                initSign(key)
                update(data)
                sign()
            }
            return derToRaw(signature)
        }
    }

    private fun asset(name: String): String =
        InstrumentationRegistry.getInstrumentation().context.assets.open(name).bufferedReader().use { it.readText() }

    private fun pem(value: String): ByteArray =
        Base64.getDecoder().decode(value.lineSequence().filterNot { it.startsWith("-----") }.joinToString(""))

    private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private companion object {
        private fun derToRaw(signature: ByteArray): ByteArray {
        var offset = 0
        fun byte(): Int = signature[offset++].toInt() and 0xff
        fun length(): Int {
            val first = byte()
            if (first and 0x80 == 0) return first
            var result = 0
            repeat(first and 0x7f) { result = (result shl 8) or byte() }
            return result
        }
        fun integer(): ByteArray {
            check(byte() == 0x02) { "Expected a DER INTEGER" }
            val size = length()
            val value = signature.copyOfRange(offset, offset + size).dropWhile { it == 0.toByte() }.toByteArray()
            offset += size
            return ByteArray(32).also { value.copyInto(it, destinationOffset = 32 - value.size) }
        }
        check(byte() == 0x30) { "Expected a DER SEQUENCE" }
        length()
        return integer() + integer()
        }
    }
}
