// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * The registry's job is to route a request to a system that can actually
 * serve it. These cover the two ways that can go wrong silently.
 */
class ZkProofSystemRegistryTest {

    private class FakeSystem(
        override val systemId: String,
        override val supportedCredentialTypes: Set<CredentialTypeRef>,
        private val specId: String,
        private val attributeCount: Int,
    ) : ZkProofSystem {
        override fun matchingSpec(requestedSpecs: List<ZkSystemSpec>, numAttributes: Int): ZkSystemSpec? =
            requestedSpecs.firstOrNull {
                it.system == specId && numAttributes == attributeCount
            }

        override suspend fun generateProof(
            spec: ZkSystemSpec,
            document: CredentialDocument,
            sessionTranscript: ByteArray,
            requestedClaims: List<String>,
            verifierIdentity: VerifierIdentity?,
            signer: ZkWitnessSigner,
            priorState: ByteArray?,
        ): ZkProofResult = ZkProofResult(proofBytes = byteArrayOf(1))
    }

    private val mdl = CredentialTypeRef(CredentialFormat.MSO_MDOC, "org.iso.18013.5.1.mDL")
    private val spec = ZkSystemSpec(id = "s1", system = "longfellow")

    private fun registry() = ZkProofSystemRegistry(
        listOf(FakeSystem("mdoc-only", setOf(mdl), "longfellow", attributeCount = 2)),
    )

    @Test
    fun `resolves a matching credential type`() {
        val resolved = registry().resolve(mdl, listOf(spec), numAttributes = 2)
        assertNotNull(resolved)
        assertEquals("mdoc-only", resolved!!.first.systemId)
    }

    /**
     * The reason this interface carries a format at all. An SD-JWT VC and
     * an mdoc can share a type identifier, and before the format was part
     * of the key such a request matched an mdoc-only system and failed
     * somewhere inside a native prover that had been handed bytes it could
     * not parse.
     */
    @Test
    fun `does not route a same-named credential of another format to an mdoc system`() {
        val sdJwtSameTypeId = CredentialTypeRef(CredentialFormat.DC_SD_JWT, "org.iso.18013.5.1.mDL")
        assertNull(registry().resolve(sdJwtSameTypeId, listOf(spec), numAttributes = 2))
    }

    /**
     * A circuit is compiled for a fixed attribute count, so a spec that
     * matches by name but not by count must not resolve - proving against
     * the wrong-shaped circuit still "succeeds" locally and is rejected by
     * a real verifier during deserialization.
     */
    @Test
    fun `does not resolve a spec compiled for a different attribute count`() {
        assertNull(registry().resolve(mdl, listOf(spec), numAttributes = 3))
    }

    @Test
    fun `reports no match when nothing is registered`() {
        assertNull(ZkProofSystemRegistry(emptyList()).resolve(mdl, listOf(spec), numAttributes = 2))
    }

    /**
     * The signer carries an algorithm precisely so a wallet whose keystore
     * cannot produce it fails loudly here rather than returning a
     * signature over the wrong curve, which only surfaces as a proof that
     * will not verify.
     */
    @Test
    fun `a signer may refuse an algorithm it cannot produce`() = runTest {
        val es256Only = ZkWitnessSigner { algorithm, data ->
            require(algorithm == COSE_ALG_ES256) { "unsupported COSE alg $algorithm" }
            data
        }
        assertEquals(1, es256Only.sign(COSE_ALG_ES256, byteArrayOf(1)).size)
        // A BBS key binding key (COSE -65609) lives on a different curve
        // and most keystores cannot produce one at all.
        assertThrows(IllegalArgumentException::class.java) {
            kotlinx.coroutines.runBlocking { es256Only.sign(-65609L, byteArrayOf(1)) }
        }
    }
}
